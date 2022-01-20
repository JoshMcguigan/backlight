use std::{
    ffi::c_void,
    fs::read,
    io,
    os::unix::prelude::CommandExt,
    path::{Path, PathBuf},
    process::Command,
};

use clap::Parser;
use goblin::elf::Elf;
use nix::{
    errno::Errno,
    sys::{
        mman::ProtFlags,
        ptrace,
        wait::{waitpid, WaitStatus},
    },
    unistd::Pid,
};
use procfs::process::{FDTarget, Process};

mod args;
use args::Args;

mod resolved_function;
use resolved_function::ResolvedFunction;

const SYSCALL_ENTRY_MARKER: u64 = -(Errno::ENOSYS as i32) as u64;
const SYS_CALL_MMAP: u64 = 9;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

macro_rules! wait {
    ($pid:ident) => {
        if matches!(waitpid($pid, None)?, WaitStatus::Exited(_, _)) {
            println!("--- Child process exited ---");
            return Ok(());
        }
    };
}

fn main() -> Result<()> {
    let args = Args::parse();
    let (binary_to_trace, mut unresolved_functions) = match args.command {
        args::Command::Trace {
            binary_to_trace,
            library_functions_to_trace,
            ..
        } => (binary_to_trace, library_functions_to_trace),
    };

    // If the user doesn't specify which functions they want to trace we
    // trace everything.
    if unresolved_functions.is_empty() {
        unresolved_functions = find_undefined_symbols(&binary_to_trace)?;
    }

    let pid = spawn_tracee(&binary_to_trace)?;

    // The child reports being stopped by a SIGTRAP here.
    wait!(pid);

    let procfs_process = Process::new(pid.as_raw())?;

    let mut resolved_functions = vec![];

    // At this point the shared libraries are not loaded. Watch for mmap
    // calls, indicating loading shared libraries.
    loop {
        // Allow the tracee to advance to the next system call entrance or exit.
        //
        // This will also stop for our INT3, or other signals.
        ptrace::syscall(pid, None)?;
        wait!(pid);

        let registers = ptrace::getregs(pid)?;
        if registers.rax == SYSCALL_ENTRY_MARKER
            && registers.orig_rax == SYS_CALL_MMAP
            && ProtFlags::from_bits_truncate(registers.rdx as i32).contains(ProtFlags::PROT_EXEC)
        {
            let file_descriptor = registers.r8;
            // We could watch for openat syscalls to get this mapping for ourselves
            // rather than looking at procfs, but for now this is easier.
            let file_path =
                if let Some(file_path) = get_file_path_from_fd(&procfs_process, file_descriptor)? {
                    file_path
                } else {
                    continue;
                };

            let mmap_offset = registers.r9;

            // Allow the tracee to advance to the system call exit.
            //
            // We know it is the exit at this point because our last
            // wait was the entrance.
            //
            // TODO are there bugs here if there are other signals while this
            // is happening?
            ptrace::syscall(pid, None)?;
            wait!(pid);

            let registers = ptrace::getregs(pid)?;
            let mapped_virtual_address_base = registers.rax;

            unresolved_functions = unresolved_functions
                .drain(..)
                .filter(|library_function_to_trace| {
                    // If this file doesn't have our symbol we want to skip it.
                    let (library_function_base_file_offset, library_function_virtual_addr_offset) =
                        match find_library_function_addr_info(&file_path, library_function_to_trace)
                        {
                            Ok(Some((a, b))) => (a, b),
                            _ => return true,
                        };

                    if library_function_base_file_offset == mmap_offset {
                        let virtual_addr =
                            library_function_virtual_addr_offset + mapped_virtual_address_base;
                        let library_function = ResolvedFunction {
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
                        resolved_functions.push(library_function);
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
            if let Some(traced_function) = resolved_functions
                .iter()
                // When we stop, the instruction pointer will be on the instruction
                // after our int3, so we subtract one from the instruction pointer
                // before doing the comparison.
                .find(|f| f.virtual_addr == registers.rip - 1)
            {
                println!("{}", &traced_function.name);
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

fn spawn_tracee(binary_to_trace: &Path) -> Result<Pid> {
    let mut c = Command::new(&binary_to_trace);
    unsafe {
        c.pre_exec(|| ptrace::traceme().map_err(|err| io::Error::from_raw_os_error(err as i32)));
    }
    Ok(Pid::from_raw(c.spawn()?.id() as i32))
}

/// If the library function is found in this library, this function returns a tuple of
///   * base address in the file of the segment containing this function
///   * virtual address offset - the number of bytes from the base virtual address
///     where that segment is mapped to this function
fn find_library_function_addr_info(
    path_to_library: &Path,
    library_function_to_trace: &str,
) -> Result<Option<(u64, u64)>> {
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

    let mut library_function_addr_info = None;
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
            library_function_addr_info = Some((base_offset, virtual_addr_offset));
        }
    }

    Ok(library_function_addr_info)
}

/// This function returns all undefined symbols, representing functions, in the
/// given elf. Undefined symbols in a binary will be dynamically linked.
fn find_undefined_symbols(path_to_bin: &Path) -> Result<Vec<String>> {
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

fn get_file_path_from_fd(
    procfs_process: &Process,
    file_descriptor: u64,
) -> Result<Option<PathBuf>> {
    if let Some(FDTarget::Path(file_path)) = procfs_process
        .fd()?
        .into_iter()
        .find(|fd_info| fd_info.fd as u64 == file_descriptor)
        .map(|fd_info| fd_info.target)
    {
        Ok(Some(file_path))
    } else {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use std::{path::PathBuf, process::Command};

    use expect_test::{expect, Expect};

    use crate::find_undefined_symbols;

    fn test_trace(bin_name: &str, trace_args: &[&str], expected: Expect) {
        cargo_build("backlight");
        cargo_build(bin_name);

        let output = Command::new("../target/debug/backlight")
            .arg("trace")
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
                abs
                abs
                abs
                --- Child process exited ---

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
                abs
                labs
                abs
                labs
                abs
                --- Child process exited ---

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
                __libc_start_main
                poll
                signal
                sigaction
                sigaction
                sigaction
                sigaction
                sigaction
                sigaltstack
                sysconf
                mmap
                sysconf
                mprotect
                sysconf
                sigaltstack
                sysconf
                pthread_self
                pthread_getattr_np
                malloc
                malloc
                malloc
                fstat64
                malloc
                realloc
                realloc
                free
                free
                free
                realloc
                malloc
                calloc
                realloc
                malloc
                free
                pthread_attr_getstack
                pthread_attr_destroy
                free
                free
                malloc
                pthread_mutex_lock
                pthread_mutex_unlock
                malloc
                __cxa_thread_atexit_impl
                calloc
                abs
                labs
                abs
                labs
                abs
                sigaltstack
                sysconf
                sysconf
                munmap
                free
                free
                free
                __cxa_finalize
                __cxa_finalize
                __cxa_finalize
                __cxa_finalize
                __cxa_finalize
                --- Child process exited ---

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
