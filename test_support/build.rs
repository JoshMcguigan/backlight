use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=src/lib.c");
    println!("cargo:rustc-link-search=native=target");

    let out = Command::new("cc")
        .args(&["src/lib.c", "-shared", "-o", "../target/libtest_support.so"])
        .status()
        .unwrap();

    if !out.success() {
        panic!("failed to build lib");
    }
}
