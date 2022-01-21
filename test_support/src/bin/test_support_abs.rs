//! This binary is built to act as a test tracing target for backlight.
//!
//! In order to minimize the behavior differences across platforms (libc versions)
//! it is built as a no_std binary. But we still link in libc in order to demonstrate
//! in our test suite that we are capable of tracing calls into libc.

#![no_std]
#![no_main]

/// This is a trick to link in libc. See the module level doc comment
/// for the justification for linking libc in a no_std binary.
#[link(name = "c")]
extern "C" {}

use libc::{abs, c_char, c_int, c_long, labs};

#[no_mangle]
pub extern "C" fn main(_: c_int, _: *const *const c_char) -> c_int {
    // This code is nonsensical, but we just want an example
    // of calling a couple different library functions with
    // different argument values.
    for i in 0..5 {
        if i % 2 == 0 {
            let _ = unsafe { abs(i as c_int) };
        } else {
            let _ = unsafe { labs(i as c_long) };
        }
    }

    0
}

/// Although there are no tests here, cargo test tries to build it and link
/// std, which causes a duplicate panic handler item error. This cfg allows
/// running cargo test without hitting that error by conditionally not
/// including our panic handler definition.
#[cfg(not(test))]
mod panic {
    use libc::exit;
    #[panic_handler]
    fn panic_handler(_: &core::panic::PanicInfo) -> ! {
        unsafe { exit(1) }
    }
}
