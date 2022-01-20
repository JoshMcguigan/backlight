use std::{
    ffi::c_void, fs::read, io, mem, os::unix::prelude::CommandExt, path::Path, process::Command,
};

use clap::Parser;
use goblin::elf::Elf;
use nix::{
    errno::Errno,
    sys::{
        ptrace,
        wait::{waitpid, WaitStatus},
    },
    unistd::Pid,
};
use procfs::process::{FDTarget, MMapPath, Process};

mod args;
use args::Args;

const SYSCALL_ENTRY_MARKER: u64 = -(Errno::ENOSYS as i32) as u64;
const SYS_CALL_MMAP: u64 = 9;

macro_rules! wait {
    ($pid:ident) => {
        if matches!(waitpid($pid, None)?, WaitStatus::Exited(_, _)) {
            println!("Child process exited");
            return Ok(());
        }
    };
}

#[derive(Debug)]
struct LibraryFunction {
    name: String,
    /// The virtual address where this function was loaded.
    virtual_addr: u64,
    original_instruction: i64,
}

impl LibraryFunction {
    /// Returns the original instruction with the first byte replaced by int3
    /// to trigger a trap.
    fn modified_instruction(&self) -> i64 {
        let original_instruction =
            unsafe { mem::transmute::<i64, [u8; 8]>(self.original_instruction) };
        // We want to be explicit here that we are taking a copy of the original
        // instruction, rather than aliasing and then modifying the original.
        #[allow(clippy::clone_on_copy)]
        let mut m = original_instruction.clone();
        m[0] = 0xcc;

        unsafe { mem::transmute::<[u8; 8], i64>(m) }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let (binary_to_trace, mut library_functions_to_be_resolved) = match args.command {
        args::Command::Trace {
            binary_to_trace,
            library_functions_to_trace,
            ..
        } => (binary_to_trace, library_functions_to_trace),
    };

    if library_functions_to_be_resolved.is_empty() {
        library_functions_to_be_resolved = find_undefined_symbols(&binary_to_trace)?;
    }

    let pid = spawn_tracee(&binary_to_trace)?;

    // The child reports being stopped by a SIGTRAP here.
    wait!(pid);

    let procfs_process = Process::new(pid.as_raw())?;

    let mut library_functions_to_trace = vec![];

    // At this point the shared libraries are not loaded. Watch for mmap
    // calls, indicating loading shared libraries.
    loop {
        // Allow the tracee to advance to the next system call entrance or exit.
        ptrace::syscall(pid, None)?;
        wait!(pid);

        let registers = ptrace::getregs(pid)?;
        if registers.rax == SYSCALL_ENTRY_MARKER && registers.orig_rax == SYS_CALL_MMAP {
            // TODO if not executable section continue loop
            let file_descriptor = registers.r8;
            // We could watch for openat syscalls to get this mapping for ourselves
            // rather than looking at procfs, but for now this is easier.
            let file_path = if let Some(FDTarget::Path(file_path)) = procfs_process
                .fd()?
                .into_iter()
                .find(|fd_info| fd_info.fd as u64 == file_descriptor)
                .map(|fd_info| fd_info.target)
            {
                file_path
            } else {
                continue;
            };

            // Allow the tracee to advance to the system call exit.
            //
            // We know it is the exit at this point because our last
            // wait was the entrance.
            //
            // TODO are there bugs here if there are other signals while this
            // is happening?
            ptrace::syscall(pid, None)?;
            wait!(pid);

            library_functions_to_be_resolved = library_functions_to_be_resolved
                .drain(..)
                .filter(|library_function_to_trace| {
                    // If this file doesn't have our symbol we want to skip it.
                    let library_function_virtual_addr_offset =
                        match find_library_function_address_offset(
                            &file_path,
                            library_function_to_trace,
                        ) {
                            Ok(Some(a)) => a,
                            _ => return true,
                        };

                    let file_path = MMapPath::Path(file_path.clone());
                    // Check memory map for the new section.
                    //
                    // TODO get this info from the mmap call so we
                    // don't have to wait for syscall exit.
                    if let Some(mapped_address_space) = procfs_process
                        .maps()
                        .expect("failed to read memory map")
                        .into_iter()
                        .find(|mapped_address_space| {
                            mapped_address_space.pathname
                        == file_path
                        // How would we handle cases where multiple segments
                        // are mapped with executable permissions?
                        //
                        // TODO remove this by checking mmap call args
                        && mapped_address_space.perms.contains('x')
                        })
                    {
                        let virtual_addr =
                            library_function_virtual_addr_offset + mapped_address_space.address.0;
                        let library_function = LibraryFunction {
                            name: library_function_to_trace.into(),
                            virtual_addr,
                            original_instruction: ptrace::read(pid, virtual_addr as *mut c_void)
                                .unwrap(),
                        };
                        unsafe {
                            ptrace::write(
                                pid,
                                library_function.virtual_addr as *mut c_void,
                                library_function.modified_instruction() as *mut c_void,
                            )
                            .unwrap();
                        }
                        library_functions_to_trace.push(library_function);
                        false
                    } else {
                        true
                    }
                })
                .collect();
        } else {
            // Rebind as mut, because the if-block above does not mutate the registers
            // but this block does.
            let mut registers = registers;
            if let Some(traced_function) = library_functions_to_trace
                .iter()
                // When we stop, the instruction pointer will be on the instruction
                // after our int3, so we subtrace one from the instruction pointer
                // before doing the comparison.
                .find(|f| f.virtual_addr == registers.rip - 1)
            {
                println!("called {}", &traced_function.name);
                unsafe {
                    ptrace::write(
                        pid,
                        traced_function.virtual_addr as *mut c_void,
                        traced_function.original_instruction as *mut c_void,
                    )?;
                }
                // need to move pc back by 1 here
                registers.rip -= 1;
                ptrace::setregs(pid, registers)?;
                ptrace::step(pid, None)?;
                wait!(pid);
                unsafe {
                    ptrace::write(
                        pid,
                        traced_function.virtual_addr as *mut c_void,
                        traced_function.modified_instruction() as *mut c_void,
                    )?;
                }
            }
        }
    }
}

fn spawn_tracee(binary_to_trace: &Path) -> Result<Pid, Box<dyn std::error::Error>> {
    let mut c = Command::new(&binary_to_trace);
    unsafe {
        c.pre_exec(|| ptrace::traceme().map_err(|err| io::Error::from_raw_os_error(err as i32)));
    }
    Ok(Pid::from_raw(c.spawn()?.id() as i32))
}

fn find_library_function_address_offset(
    path_to_library: &Path,
    library_function_to_trace: &str,
) -> Result<Option<u64>, Box<dyn std::error::Error>> {
    let library_bytes = read(path_to_library)?;
    let elf = Elf::parse(&library_bytes)?;

    let mut text_section_info = None;
    for (index, section_header) in elf.section_headers.into_iter().enumerate() {
        let name = elf
            .shdr_strtab
            .get_at(section_header.sh_name)
            .ok_or("failed to map section name")?;
        if name == ".text" {
            text_section_info = Some(index);
        }
    }
    let text_section_index = text_section_info.ok_or("failed to find base addr")?;

    let mut library_function_virtual_addr_offset = None;
    for symbol in elf.dynsyms.into_iter().filter(|s| {
        s.is_function()
                // For now we only handle functions in the text section.
                && s.st_shndx == text_section_index
    }) {
        let name = elf
            .dynstrtab
            .get_at(symbol.st_name)
            .ok_or("failed to map symbol name")?;

        if name == library_function_to_trace {
            let base_offset = elf
                .program_headers
                .iter()
                .find(|program_header| {
                    program_header.p_offset < symbol.st_value
                        && symbol.st_value < program_header.p_offset + program_header.p_memsz
                })
                .map(|program_header| program_header.p_offset)
                .ok_or("didn't find mem mapped place")?;
            // This is the offset between the start of the executable section
            // where this library is mapped into memory and where this function
            // is located.
            let virtual_addr_offset = symbol.st_value - base_offset;
            library_function_virtual_addr_offset = Some(virtual_addr_offset);
        }
    }

    Ok(library_function_virtual_addr_offset)
}

/// This function returns all undefined symbols, representing functions, in the
/// given elf. Undefined symbols in a binary will be dynamically linked.
fn find_undefined_symbols(path_to_bin: &Path) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let library_bytes = read(path_to_bin)?;
    let elf = Elf::parse(&library_bytes)?;
    let mut out = vec![];
    for symbol in elf
        .dynsyms
        .into_iter()
        // The first entry is reserved and holds a default unitialized entry.
        .skip(1)
        .filter(|s| s.is_import())
        .filter(|s| s.is_function())
    {
        let name = elf
            .dynstrtab
            .get_at(symbol.st_name)
            .ok_or("failed to map symbol name")?;
        out.push(name.into());
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use std::{path::PathBuf, process::Command};

    use expect_test::{expect, Expect};

    use crate::find_undefined_symbols;

    fn test_trace(bin_name: &str, trace_args: &[&str], expected: Expect) {
        cargo_build(bin_name);

        let output = Command::new("cargo")
            .args(&["run", "--quiet", "--bin", "backlight", "--", "trace"])
            .arg(&format!("../target/debug/{}", bin_name))
            .args(trace_args)
            .output()
            .unwrap();

        let result = format!(
            "status code: {}\n\nstd out:\n{}\nstd err:\n{}\n",
            match output.status.code() {
                Some(c) => format!("{}", c),
                None => "None".into(),
            },
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
        expected.assert_eq(&result);
    }

    fn cargo_build(bin_name: &str) {
        let status = Command::new("cargo")
            // cargo test sets the current working directory to the package
            // root. We need to go up to the workspace root because this
            // bin could be in a different package.
            .current_dir("..")
            .args(&["build", "--bin", bin_name])
            .status()
            .unwrap();

        assert!(status.success());
    }

    #[test]
    fn traces_single_library_call() {
        test_trace(
            "test_support_abs",
            &["-l", "abs"],
            expect![[r#"
                status code: 0

                std out:
                called abs
                called abs
                called abs
                Child process exited

                std err:

            "#]],
        );
    }

    #[test]
    fn traces_multiple_library_calls() {
        test_trace(
            "test_support_abs",
            &["-l", "abs", "-l", "labs"],
            expect![[r#"
                status code: 0

                std out:
                called abs
                called labs
                called abs
                called labs
                called abs
                Child process exited

                std err:

            "#]],
        );
    }

    #[test]
    fn traces_all_library_calls() {
        test_trace(
            "test_support_abs",
            &[],
            expect![[r#"
                status code: 0

                std out:
                called __libc_start_main
                called poll
                called signal
                called sigaction
                called sigaction
                called sigaction
                called sigaction
                called sigaction
                called sigaltstack
                called sysconf
                called mmap
                called sysconf
                called mprotect
                called sysconf
                called sigaltstack
                called sysconf
                called pthread_self
                called pthread_getattr_np
                called malloc
                called malloc
                called malloc
                called fstat64
                called malloc
                called realloc
                called realloc
                called free
                called free
                called free
                called realloc
                called malloc
                called calloc
                called realloc
                called malloc
                called free
                called pthread_attr_getstack
                called pthread_attr_destroy
                called free
                called free
                called malloc
                called pthread_mutex_lock
                called pthread_mutex_unlock
                called malloc
                called __cxa_thread_atexit_impl
                called calloc
                called abs
                called labs
                called abs
                called labs
                called abs
                called sigaltstack
                called sysconf
                called sysconf
                called munmap
                called free
                called free
                called free
                called __cxa_finalize
                called __cxa_finalize
                called __cxa_finalize
                called __cxa_finalize
                called __cxa_finalize
                Child process exited

                std err:

            "#]],
        );
    }

    #[test]
    fn finds_undefined_symbols() {
        cargo_build("test_support_abs");
        expect![[r#"
            mprotect
            pthread_getspecific
            _Unwind_GetRegionStart
            memset
            _Unwind_SetGR
            posix_memalign
            close
            _Unwind_GetDataRelBase
            abort
            pthread_setspecific
            memchr
            malloc
            __libc_start_main
            pthread_getattr_np
            _Unwind_DeleteException
            sysconf
            pthread_attr_destroy
            _Unwind_GetLanguageSpecificData
            free
            strlen
            stat64
            __cxa_thread_atexit_impl
            _Unwind_RaiseException
            __cxa_finalize
            realpath
            pthread_key_delete
            __tls_get_addr
            syscall
            _Unwind_GetIP
            _Unwind_Backtrace
            pthread_attr_getstack
            pthread_self
            poll
            pthread_mutex_trylock
            open64
            sigaction
            abs
            fstat64
            bcmp
            readlink
            signal
            memmove
            getenv
            _Unwind_GetIPInfo
            dl_iterate_phdr
            __errno_location
            getcwd
            labs
            pthread_rwlock_rdlock
            calloc
            munmap
            __xpg_strerror_r
            writev
            dlsym
            _Unwind_GetTextRelBase
            pthread_rwlock_unlock
            pthread_mutex_lock
            realloc
            pthread_key_create
            pthread_mutex_destroy
            write
            _Unwind_Resume
            sigaltstack
            pthread_mutex_unlock
            memcpy
            open
            mmap
            _Unwind_SetIP
        "#]]
        .assert_eq(
            &(find_undefined_symbols(&PathBuf::from("../target/debug/test_support_abs"))
                .unwrap()
                .join("\n")
                + "\n"),
        );
    }
}
