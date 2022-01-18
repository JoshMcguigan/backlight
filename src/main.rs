use std::{
    ffi::c_void, fs::read, io, mem, os::unix::prelude::CommandExt, path::PathBuf, process::Command,
};

use goblin::elf::Elf;
use nix::{
    sys::{
        ptrace,
        wait::{waitpid, WaitStatus},
    },
    unistd::Pid,
};
use procfs::process::{MMapPath, Process};

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
    // --- Find symbol location in library ---
    let malloc_virtual_addr_offset = find_malloc_address_offset()?;

    // --- Spawn tracee ---
    let pid = {
        // TODO take this as arg
        let mut c = Command::new("../hello/target/debug/hello");
        unsafe {
            c.pre_exec(|| {
                ptrace::traceme().map_err(|err| io::Error::from_raw_os_error(err as i32))
            });
        }
        Pid::from_raw(c.spawn()?.id() as i32)
    };

    // The child reports being stopped by a SIGTRAP here.
    wait!(pid);

    let procfs_process = Process::new(pid.as_raw())?;

    // At this point the shared libraries are not loaded. Watch for mmap
    // calls, indicating loading shared libraries.
    let libc_virtual_addr_base: u64 = loop {
        // Allow the tracee to advance to the next system call entrance or exit.
        ptrace::syscall(pid, None)?;
        // Wait for the tracee to signal.
        wait!(pid);

        // We could optimize by only doing this after a mmap, but for now
        // we check the memory map after each system call entrance/exit.
        //
        // This lookup should really happen for each mmap'ed shared library
        // rather than hardcoding and only looking for libc.
        if let Some(mapped_address_space) =
            procfs_process
                .maps()?
                .into_iter()
                .find(|mapped_address_space| {
                    mapped_address_space.pathname
                        == MMapPath::Path(PathBuf::from("/usr/lib/libc-2.33.so"))
                        // How would we handle cases where multiple segments
                        // are mapped with executable permissions?
                        && mapped_address_space.perms.contains('x')
                })
        {
            break mapped_address_space.address.0;
        }
    };

    let malloc_addr = libc_virtual_addr_base + malloc_virtual_addr_offset;

    let original_instruction = ptrace::read(pid, malloc_addr as *mut c_void)?;
    let modified_instruction = {
        let original_instruction = unsafe { mem::transmute::<i64, [u8; 8]>(original_instruction) };
        let mut m = original_instruction.clone();
        m[0] = 0xcc;

        unsafe { mem::transmute::<[u8; 8], i64>(m) }
    };

    unsafe {
        ptrace::write(
            pid,
            malloc_addr as *mut c_void,
            modified_instruction as *mut c_void,
        )?;
    }

    loop {
        ptrace::cont(pid, None)?;
        wait!(pid);
        println!("called malloc");
        unsafe {
            ptrace::write(
                pid,
                malloc_addr as *mut c_void,
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
                malloc_addr as *mut c_void,
                modified_instruction as *mut c_void,
            )?;
        }
    }
}

fn find_malloc_address_offset() -> Result<u64, Box<dyn std::error::Error>> {
    let libc_bytes = read("/usr/lib/libc-2.33.so")?;
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

    let mut malloc_virtual_addr_offset = None;
    for symbol in elf.dynsyms.into_iter().filter(|s| {
        s.is_function()
                // For now we only handle functions in the text section.
                && s.st_shndx == text_section_index
    }) {
        let name = elf
            .dynstrtab
            .get_at(symbol.st_name)
            .ok_or("failed to map symbol name")?;

        if name == "malloc" {
            let base_offset = elf
                .program_headers
                .iter()
                .find(|program_header| {
                    program_header.p_offset < symbol.st_value
                        && symbol.st_value < program_header.p_offset + program_header.p_memsz
                })
                .map(|program_header| program_header.p_offset)
                .expect("didn't find mem mapped place");
            // This is the offset between the start of the executable section
            // where this library is mapped into memory and where this function
            // is located.
            let virtual_addr_offset = symbol.st_value - base_offset;
            malloc_virtual_addr_offset = Some(virtual_addr_offset);
        }
    }
    let malloc_virtual_addr_offset = malloc_virtual_addr_offset.expect("didn't find malloc addr");

    Ok(malloc_virtual_addr_offset)
}

#[cfg(test)]
mod tests {
    use super::find_malloc_address_offset;

    #[test]
    fn finds_malloc_addr() {
        assert_eq!(0x65320, find_malloc_address_offset().unwrap());
    }
}
