//! This binary builds all the test support bin/lib files and copies
//! them to the `test_suppport/output` directory.

use std::{fs, process::Command};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let test_support_bins = vec!["test_support_abs"];

    for bin_name in test_support_bins {
        let status = Command::new("cargo")
            .args(&["build", "--bin", bin_name])
            .status()?;

        if !status.success() {
            return Err(format!("failed to build {}", bin_name).into());
        }

        fs::copy(
            format!("target/debug/{}", bin_name),
            format!("test_support/output/{}", bin_name),
        )?;
    }

    let lib_name = "test_support";
    let status = Command::new("cargo")
        .args(&["build", "-p", "test_support", "--lib"])
        .status()?;

    if !status.success() {
        return Err(format!("failed to build {}", lib_name).into());
    }

    let shared_object_name = format!("lib{}.so", lib_name);
    fs::copy(
        format!("target/debug/{}", shared_object_name),
        format!("test_support/output/{}", shared_object_name),
    )?;

    Ok(())
}
