//! This binary is built to act as a test tracing target for backlight.

#[link(name = "test_support")]
extern "C" {
    fn calls_foo();
}

fn main() {
    unsafe {
        calls_foo();
    }
}
