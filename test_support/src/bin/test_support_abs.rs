use std::os::raw::c_int;

#[link(name = "c")]
extern "C" {
    fn abs(i: c_int);
}

fn main() {
    for _ in 0..5 {
        let _ = unsafe { abs(-1) };
    }
}
