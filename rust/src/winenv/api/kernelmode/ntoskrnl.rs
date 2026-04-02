// NT Kernel (NTOSKRNL) API implementations

use crate::winenv::api::ApiHandler;

pub struct NtOsKrnlHandler;

impl ApiHandler for NtOsKrnlHandler {
    fn call(&mut self, _args: &[u64]) -> u64 {
        0
    }

    fn get_name(&self) -> &str {
        "NTOSKRNL"
    }
}

// NT kernel functions
pub fn nt_create_file() -> u32 {
    0
}

pub fn nt_read_file() -> u32 {
    0
}

pub fn nt_write_file() -> u32 {
    0
}

pub fn nt_query_information_file() -> u32 {
    0
}
