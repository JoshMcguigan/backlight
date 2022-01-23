#[derive(Debug)]
/// Represents a function which has been mapped to a known location
/// in virtual memory.
pub struct ResolvedFunction {
    pub name: String,
    /// The virtual address where this function was loaded.
    pub virtual_addr: u64,
    /// This is the word which was originally stored at the virtual
    /// address where this function was loaded. It may contain more
    /// than a single instruction but we store the whole word because
    /// that is the granularity that the ptrace API allows us to read.
    pub original_instruction: i64,
}

impl ResolvedFunction {
    /// Returns the original instruction with the first byte replaced by int3
    /// to trigger a trap.
    pub fn modified_instruction(&self) -> i64 {
        let mut i = self.original_instruction.to_ne_bytes();
        i[0] = 0xcc;

        i64::from_ne_bytes(i)
    }
}
