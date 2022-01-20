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
    libc::user_regs_struct,
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
    ($pid:expr) => {
        if matches!(waitpid($pid, None)?, WaitStatus::Exited(_, _)) {
            return Ok(TraceeState::Exited);
        }
    };
}

struct Tracee {
    pid: Pid,
    procfs: procfs::process::Process,
    unresolved_functions: Vec<String>,
    resolved_functions: Vec<ResolvedFunction>,
    /// If we've seen the entry to a mmap syscall but not the exit
    /// we store the args here. Upon exit we resolve functions
    /// and set this back to None.
    mmap_in_progress: Option<MmapArgs>,
}

struct MmapArgs {
    /// Path to the file being mmap'd.
    file_path: PathBuf,
    /// Offset into the file where the mapping starts.
    offset: u64,
}

#[allow(clippy::large_enum_variant)]
enum TraceeState {
    Alive(Tracee),
    Exited,
}

impl Tracee {
    fn init(
        binary_to_trace: &Path,
        library_functions_to_trace: Vec<String>,
    ) -> Result<TraceeState> {
        let pid = spawn_tracee(binary_to_trace)?;

        ptrace::setoptions(pid, ptrace::Options::PTRACE_O_TRACESYSGOOD)?;

        // The tracee should signal a SIGTRAP here.
        if matches!(waitpid(pid, None)?, WaitStatus::Exited(_, _)) {
            Ok(TraceeState::Exited)
        } else {
            Ok(TraceeState::Alive(Self {
                pid,
                procfs: Process::new(pid.as_raw())?,
                unresolved_functions: library_functions_to_trace,
                resolved_functions: vec![],
                mmap_in_progress: None,
            }))
        }
    }
    fn step(mut self) -> Result<TraceeState> {
        ptrace::syscall(self.pid, None)?;
        match waitpid(self.pid, None)? {
            WaitStatus::Exited(_, _) => Ok(TraceeState::Exited),
            WaitStatus::PtraceSyscall(_pid) => {
                let registers = ptrace::getregs(self.pid)?;
                if registers.rax == SYSCALL_ENTRY_MARKER
                    && registers.orig_rax == SYS_CALL_MMAP
                    && ProtFlags::from_bits_truncate(registers.rdx as i32)
                        .contains(ProtFlags::PROT_EXEC)
                {
                    self.handle_mmap_entrance(registers)?;
                } else {
                    // If we are stopped on a syscall and we have a mmap
                    // in progress, we know we are exiting that mmap.
                    if let Some(mmap_args) = self.mmap_in_progress.take() {
                        self.handle_mmap_exit(mmap_args)?;
                    } else {
                        // handle any other sys call enter/exit
                    }
                }
                Ok(TraceeState::Alive(self))
            }
            _ => {
                let registers = ptrace::getregs(self.pid)?;
                self.handle_trap(registers)
            }
        }
    }
    fn handle_mmap_entrance(&mut self, registers: user_regs_struct) -> Result<()> {
        let file_descriptor = registers.r8;
        let file_path =
            if let Some(file_path) = get_file_path_from_fd(&self.procfs, file_descriptor)? {
                file_path
            } else {
                return Ok(());
            };

        let offset = registers.r9;

        self.mmap_in_progress = Some(MmapArgs { file_path, offset });

        Ok(())
    }
    fn handle_mmap_exit(&mut self, mmap_args: MmapArgs) -> Result<()> {
        let registers = ptrace::getregs(self.pid)?;
        let mapped_virtual_address_base = registers.rax;

        self.unresolved_functions = self
            .unresolved_functions
            .drain(..)
            .filter(|library_function_to_trace| {
                // If this file doesn't have our symbol we want to skip it.
                let (library_function_base_file_offset, library_function_virtual_addr_offset) =
                    match find_library_function_addr_info(
                        &mmap_args.file_path,
                        library_function_to_trace,
                    ) {
                        Ok(Some((a, b))) => (a, b),
                        _ => return true,
                    };

                if library_function_base_file_offset == mmap_args.offset {
                    let virtual_addr =
                        library_function_virtual_addr_offset + mapped_virtual_address_base;
                    let library_function = ResolvedFunction {
                        name: library_function_to_trace.into(),
                        virtual_addr,
                        original_instruction: ptrace::read(self.pid, virtual_addr as *mut c_void)
                            .unwrap(),
                    };
                    unsafe {
                        ptrace::write(
                            self.pid,
                            library_function.virtual_addr as *mut c_void,
                            library_function.modified_instruction() as *mut c_void,
                        )
                        .unwrap();
                    }
                    self.resolved_functions.push(library_function);
                    false
                } else {
                    true
                }
            })
            .collect();

        Ok(())
    }
    fn handle_trap(self, mut registers: user_regs_struct) -> Result<TraceeState> {
        if let Some(traced_function) = self
            .resolved_functions
            .iter()
            // When we stop, the instruction pointer will be on the instruction
            // after our int3, so we subtract one from the instruction pointer
            // before doing the comparison.
            .find(|f| f.virtual_addr == registers.rip - 1)
        {
            println!("{}", &traced_function.name);
            unsafe {
                ptrace::write(
                    self.pid,
                    traced_function.virtual_addr as *mut c_void,
                    traced_function.original_instruction as *mut c_void,
                )?;
            }
            // need to move pc back by 1 here
            registers.rip -= 1;
            ptrace::setregs(self.pid, registers)?;
            ptrace::step(self.pid, None)?;
            wait!(self.pid);
            unsafe {
                ptrace::write(
                    self.pid,
                    traced_function.virtual_addr as *mut c_void,
                    traced_function.modified_instruction() as *mut c_void,
                )?;
            }
        }

        Ok(TraceeState::Alive(self))
    }
}

fn main() -> Result<()> {
    let args = Args::parse();
    let (binary_to_trace, mut library_functions_to_trace) = match args.command {
        args::Command::Trace {
            binary_to_trace,
            library_functions_to_trace,
            ..
        } => (binary_to_trace, library_functions_to_trace),
    };

    // If the user doesn't specify which functions they want to trace we
    // trace everything.
    if library_functions_to_trace.is_empty() {
        library_functions_to_trace = find_undefined_symbols(&binary_to_trace)?;
    }

    let mut tracee = match Tracee::init(&binary_to_trace, library_functions_to_trace)? {
        TraceeState::Alive(t) => t,
        TraceeState::Exited => {
            println!("--- Child process exited ---");
            return Ok(());
        }
    };

    loop {
        tracee = match tracee.step()? {
            TraceeState::Alive(t) => t,
            TraceeState::Exited => {
                println!("--- Child process exited ---");
                return Ok(());
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
