use std::os::raw::{c_int, c_long};

#[link(name = "c")]
extern "C" {
    fn abs(i: c_int) -> c_int;
    fn labs(i: c_long) -> c_long;
}

fn main() {
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
}
