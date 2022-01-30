use backlight_lib::{find_undefined_symbols, Result, Tracee, TraceeState};
use clap::Parser;

mod args;
use args::{Args, TraceRequest};

enum SyscallsToTrace {
    All,
    /// Names of the syscalls the user would like to trace.
    ///
    /// This can be empty, in which case we will not trace any syscalls.
    These(Vec<String>),
}

fn main() -> Result<()> {
    let args = Args::parse();

    let library_function_trace_request = args.library_function_trace_request();
    let syscall_trace_request = args.syscall_trace_request();

    let Args {
        binary_to_trace,
        tracee_args,
        ..
    } = args;

    let (library_functions_to_trace, syscalls_to_trace) =
        match (library_function_trace_request, syscall_trace_request) {
            (TraceRequest::All, TraceRequest::All) => (
                find_undefined_symbols(&binary_to_trace)?,
                SyscallsToTrace::All,
            ),
            (TraceRequest::All, TraceRequest::These(syscalls_to_trace)) => (
                find_undefined_symbols(&binary_to_trace)?,
                SyscallsToTrace::These(syscalls_to_trace),
            ),
            (TraceRequest::All, TraceRequest::NoSpecificRequest) => (
                find_undefined_symbols(&binary_to_trace)?,
                SyscallsToTrace::These(vec![]),
            ),
            (TraceRequest::These(functions_to_trace), TraceRequest::All) => {
                (functions_to_trace, SyscallsToTrace::All)
            }
            (TraceRequest::These(functions_to_trace), TraceRequest::These(syscalls_to_trace)) => (
                functions_to_trace,
                SyscallsToTrace::These(syscalls_to_trace),
            ),
            (TraceRequest::These(functions_to_trace), TraceRequest::NoSpecificRequest) => {
                (functions_to_trace, SyscallsToTrace::These(vec![]))
            }
            (TraceRequest::NoSpecificRequest, TraceRequest::All) => (vec![], SyscallsToTrace::All),
            (TraceRequest::NoSpecificRequest, TraceRequest::These(syscalls_to_trace)) => {
                (vec![], SyscallsToTrace::These(syscalls_to_trace))
            }
            // If the user doesn't specify what they want to trace we trace everything.
            (TraceRequest::NoSpecificRequest, TraceRequest::NoSpecificRequest) => (
                find_undefined_symbols(&binary_to_trace)?,
                SyscallsToTrace::All,
            ),
        };

    let mut tracee = Tracee::init(&binary_to_trace, &tracee_args, library_functions_to_trace)?;

    loop {
        tracee = match tracee.step()? {
            TraceeState::Alive(t) => t,
            TraceeState::StoppedAtSystemCallEntrance(t, syscall_name) => {
                // We break at all system calls, so before logging that we hit
                // one we first check if we want to trace this particular system
                // call.
                let should_trace = match syscalls_to_trace {
                    SyscallsToTrace::All => true,
                    SyscallsToTrace::These(ref syscalls_to_trace) => {
                        syscalls_to_trace.contains(&syscall_name)
                    }
                };
                if should_trace {
                    println!("[sys] {}", syscall_name);
                }

                t
            }
            TraceeState::StoppedAtSystemCallExit(t) => t,
            TraceeState::StoppedAtFunctionEntrace(t, func_name) => {
                // Unlike system calls above, we only break at functions which
                // we have explicitly asked for, so we always want to log here.
                println!("[lib] {}", func_name);

                t
            }
            TraceeState::Exited(code) => {
                println!("--- Child process exited with status code {} ---", code);
                return Ok(());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::process::Command;

    use expect_test::{expect, Expect};

    /// Used to assert on the exact output of backlight.
    fn test_trace(bin_name: &str, trace_args: &[&str], expected: Expect) {
        cargo_build("backlight");
        cargo_build(bin_name);

        let output = Command::new("../target/debug/backlight")
            // This links allows linking against our test support lib, generated
            // in test_support/build.rs.
            .env("LD_LIBRARY_PATH", "../target")
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

    /// Used to assert that the output of backlight contains some values. Useful
    /// to create tests which don't depend on the specifics of the environment
    /// they run in.
    fn assert_trace_contains(bin_name: &str, trace_args: &[&str], expected: &[&str]) {
        cargo_build("backlight");
        cargo_build(bin_name);

        let output = Command::new("../target/debug/backlight")
            // This links allows linking against our test support lib, generated
            // in test_support/build.rs.
            .env("LD_LIBRARY_PATH", "../target")
            .arg(&format!("../target/debug/{}", bin_name))
            .args(trace_args)
            .output()
            .unwrap();

        assert_eq!(0, output.status.code().unwrap());

        let stdout = String::from_utf8_lossy(&output.stdout);

        for expected_str in expected {
            assert!(stdout.contains(expected_str));
        }
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
                [lib] abs
                [lib] abs
                [lib] abs
                --- Child process exited with status code 0 ---

                std err:

            "#]],
        );
    }

    #[test]
    fn traces_nested_function_call_exit() {
        test_trace(
            "test_support_nested_function_calls",
            &["-l", "calls_foo", "-l", "foo", "--trace-function-exit"],
            expect![[r#"
                status code: 0

                std out:
                [lib] calls_foo {
                [lib]   foo {
                [lib]   }
                [lib] }

                --- Child process exited with status code 0 ---

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
                [lib] abs
                [lib] labs
                [lib] abs
                [lib] labs
                [lib] abs
                --- Child process exited with status code 0 ---

                std err:

            "#]],
        );
    }

    #[test]
    fn traces_single_syscall() {
        test_trace(
            "test_support_abs",
            &["-s", "sys_exit_group"],
            expect![[r#"
                status code: 0

                std out:
                [sys] sys_exit_group
                --- Child process exited with status code 0 ---

                std err:

            "#]],
        );
    }

    #[test]
    fn traces_multiple_syscalls() {
        assert_trace_contains(
            "test_support_abs",
            &["-s", "sys_brk", "-s", "sys_exit_group"],
            &["[sys] sys_brk", "[sys] sys_exit_group"],
        );
    }

    #[test]
    fn traces_syscall_and_library_function() {
        test_trace(
            "test_support_abs",
            &["-s", "sys_exit_group", "-l", "abs"],
            expect![[r#"
                status code: 0

                std out:
                [lib] abs
                [lib] abs
                [lib] abs
                [sys] sys_exit_group
                --- Child process exited with status code 0 ---

                std err:

            "#]],
        );
    }

    #[test]
    fn traces_syscall_and_all_library_functions() {
        assert_trace_contains(
            "test_support_abs",
            &["-s", "sys_exit_group", "--all-library-functions"],
            &["[sys] sys_exit_group", "[lib] abs"],
        );
    }

    #[test]
    fn traces_library_function_and_all_syscalls() {
        assert_trace_contains(
            "test_support_abs",
            &["-l", "abs", "--all-syscalls"],
            &["[sys] sys_exit_group", "[lib] abs"],
        );
    }

    #[test]
    fn traces_all_by_default() {
        // The expected behavior of backlight when not provided with any explicit
        // filters is to trace everything. The exact output of the trace will be
        // platform specific, so rather than asserting on the exact output
        // we just confirm we see some indication that each expected thing shows
        // up somewhere in the backlight output.
        assert_trace_contains("test_support_abs", &[], &["[sys]", "[lib]"]);
    }

    #[test]
    fn passes_along_args() {
        // This binary exits with the code given as its first arg.
        //
        // This test demonstrates that backlight will pass along args to
        // the tracee.
        for code in &["0", "47"] {
            assert_trace_contains(
                "test_support_exit",
                &["--", code],
                &[&format!("Child process exited with status code {}", code)],
            );
        }
    }
}
