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
            // We never found the shared library we were looking for and the
            // child process exited.
            println!("Child process exited");
            return Ok(());
        }
    };
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let (binary_to_trace, library_function_to_trace) = match args.command {
        args::Command::Trace {
            binary_to_trace,
            library_function_to_trace,
            ..
        } => (binary_to_trace, library_function_to_trace),
    };

    let pid = spawn_tracee(&binary_to_trace)?;

    // The child reports being stopped by a SIGTRAP here.
    wait!(pid);

    let procfs_process = Process::new(pid.as_raw())?;

    // At this point the shared libraries are not loaded. Watch for mmap
    // calls, indicating loading shared libraries.
    let (library_function_virtual_addr_offset, libc_virtual_addr_base) = loop {
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

            // If this file doesn't have our symbol we want to skip it.
            let library_function_virtual_addr_offset = match find_library_function_address_offset(
                &file_path,
                &library_function_to_trace,
            ) {
                Ok(Some(a)) => a,
                _ => continue,
            };

            let file_path = MMapPath::Path(file_path);
            // Check memory map for the new section.
            if let Some(mapped_address_space) =
                procfs_process
                    .maps()?
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
                break (
                    library_function_virtual_addr_offset,
                    mapped_address_space.address.0,
                );
            }
        }
    };

    let library_function_addr = libc_virtual_addr_base + library_function_virtual_addr_offset;

    let original_instruction = ptrace::read(pid, library_function_addr as *mut c_void)?;
    let modified_instruction = {
        let original_instruction = unsafe { mem::transmute::<i64, [u8; 8]>(original_instruction) };
        // We want to be explicit here that we are taking a copy of the original
        // instruction, rather than aliasing and then modifying the original.
        #[allow(clippy::clone_on_copy)]
        let mut m = original_instruction.clone();
        m[0] = 0xcc;

        unsafe { mem::transmute::<[u8; 8], i64>(m) }
    };

    unsafe {
        ptrace::write(
            pid,
            library_function_addr as *mut c_void,
            modified_instruction as *mut c_void,
        )?;
    }

    loop {
        ptrace::cont(pid, None)?;
        wait!(pid);
        println!("called {}", library_function_to_trace);
        unsafe {
            ptrace::write(
                pid,
                library_function_addr as *mut c_void,
                original_instruction as *mut c_void,
            )?;
        }
        // need to move pc back by 1 here
        let mut registers = ptrace::getregs(pid)?;
        registers.rip -= 1;
        ptrace::setregs(pid, registers)?;
        ptrace::step(pid, None)?;
        wait!(pid);
        unsafe {
            ptrace::write(
                pid,
                library_function_addr as *mut c_void,
                modified_instruction as *mut c_void,
            )?;
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
    let libc_bytes = read(path_to_library)?;
    let elf = Elf::parse(&libc_bytes)?;

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

#[cfg(test)]
mod tests {
    use std::process::Command;

    use expect_test::{expect, Expect};

    fn test_trace(trace_args: &[&str], expected: Expect) {
        let output = Command::new("cargo")
            .args(&["run", "--quiet", "--bin", "backlight", "--", "trace"])
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
        cargo_build("test_support_abs");
        test_trace(
            &["../target/debug/test_support_abs", "-l", "abs"],
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
}
