//! This binary is built to act as a test tracing target for backlight.

fn main() {
    let code = std::env::args()
        .into_iter()
        .nth(1)
        .map(|arg_string| arg_string.parse().ok())
        .flatten()
        .unwrap_or(0);

    std::process::exit(code);
}
