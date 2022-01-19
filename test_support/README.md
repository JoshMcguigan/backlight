# Test Support

This crate contains libraries and binaries used to support testing backlight.

To avoid differences in compilers causing tests to fail, the outputs of this crate should be copied into the `test_support/output` directory, and all tests should reference that rather than looking directly at the `target` directory.
