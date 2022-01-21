# Backlight

Backlight is a dynamic binary tracing tool. It is similar to `ltrace` except it works by using software breakpoints rather than hijacking the procedure linkage table, so it works on binaries compiled with [full RELRO](https://www.redhat.com/en/blog/hardening-elf-binaries-using-relocation-read-only-relro) (i.e. [all binaries produced by rustc](https://doc.rust-lang.org/beta/rustc/exploit-mitigations.html#read-only-relocations-and-immediate-binding)).

## Install

```sh
$ git clone git@github.com:JoshMcguigan/backlight.git

$ cd backlight

$ cargo install-backlight
```

## Usage

```sh
# Trace all system calls, shared library function calls, etc
$ backlight trace /bin/ls
...
[lib] malloc
[sys] sys_brk
[sys] sys_brk
[lib] free
[sys] sys_openat
[sys] sys_newfstatat
[sys] sys_mmap
[sys] sys_close
[lib] malloc
...
--- Child process exited ---

# Trace specific system calls
$ backlight trace /bin/ls -s sys_openat -s sys_close

# Trace specific shared library function calls
$ backlight trace /bin/ls -l malloc -l free
```

I'm looking for feedback on the UX of backlight. Stop by [#3](https://github.com/JoshMcguigan/backlight/issues/3) and share your opinions!

## License

Licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT) at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
