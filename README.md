# Backlight

Backlight is a tool for tracing calls to shared libraries. It is similar to `ltrace` except it works by using software breakpoints rather than hijacking the procedure linkage table, so it works on binaries compiled with [full RELRO](https://www.redhat.com/en/blog/hardening-elf-binaries-using-relocation-read-only-relro) (i.e. [all binaries produced by rustc](https://doc.rust-lang.org/beta/rustc/exploit-mitigations.html#read-only-relocations-and-immediate-binding)).

## Usage

TODO provide usage examples once CLI is implemented

## License

Licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT) at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
