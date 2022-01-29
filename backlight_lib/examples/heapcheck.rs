use backlight_lib::{Tracee, TraceeState};

use std::{path::PathBuf, process::Command};

// TODO add this to CI? at least make sure it builds

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path_to_example_bin = compile_example_bin();
    // TODO allow this to take &str AND &String
    let mut tracee = Tracee::init(
        &path_to_example_bin,
        &["1".into(), "foo".into()],
        vec!["malloc".into(), "strncopy".into()],
    )?;

    // TODO reconsider this API that consumes self, since it requires
    // handling every branch of match statement
    //
    // can just return exited repeatably
    loop {
        tracee = match tracee.step()? {
            TraceeState::Alive(t) => t,
            TraceeState::StoppedAtFunctionEntrace(t, _func_name) => {
                // TODO track malloc calls
                // check that strncopy calls don't overwrite buffer
                // need to be able to track function return values for this

                // how to best "unit" test this
                // if func_name == "malloc" {
                //     t.trace_function_exit(t.regs.rdi);
                // }

                t
            }
            TraceeState::Exited(code) => {
                println!("--- Child process exited with status code {} ---", code);
                return Ok(());
            }
            TraceeState::StoppedAtSystemCallEntrance(t, _) => t,
            TraceeState::StoppedAtSystemCallExit(t) => t,
        }
    }
}

fn compile_example_bin() -> PathBuf {
    let bin_path = PathBuf::from("target/heapoverflow");

    Command::new("cc")
        .args(&[
            "backlight_lib/examples/heapcheck/heapoverflow.c",
            "-o",
            bin_path.to_str().unwrap(),
        ])
        .spawn()
        .unwrap();

    bin_path
}
