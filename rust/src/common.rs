// Utility functions for Speakeasy

use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{Read, Result as IoResult};

// Emulation hook types
pub const HOOK_CODE: u32 = 1000;
pub const HOOK_MEM_INVALID: u32 = 1001;
pub const HOOK_MEM_PERM_EXEC: u32 = 1002;
pub const HOOK_MEM_READ: u32 = 1003;
pub const HOOK_MEM_WRITE: u32 = 1004;
pub const HOOK_INTERRUPT: u32 = 1005;
pub const HOOK_MEM_ACCESS: u32 = 1006;
pub const HOOK_MEM_PERM_WRITE: u32 = 1007;
pub const HOOK_API: u32 = 1008;
pub const HOOK_DYN_CODE: u32 = 1009;
pub const HOOK_INSN: u32 = 1010;
pub const HOOK_MEM_MAP: u32 = 1011;
pub const HOOK_INSN_INVALID: u32 = 1012;

// Emulation memory protection types
pub const PERM_MEM_NONE: u32 = 0;
pub const PERM_MEM_EXEC: u32 = 0x10;
pub const PERM_MEM_READ: u32 = 0x02;
pub const PERM_MEM_WRITE: u32 = 0x04;
pub const PERM_MEM_RW: u32 = PERM_MEM_READ | PERM_MEM_WRITE;
pub const PERM_MEM_RX: u32 = PERM_MEM_READ | PERM_MEM_EXEC;
pub const PERM_MEM_RWX: u32 = PERM_MEM_READ | PERM_MEM_WRITE | PERM_MEM_EXEC;

// Emulation memory access types
pub const INVALID_MEM_EXEC: u32 = 2000;
pub const INVALID_MEM_READ: u32 = 2001;
pub const INVALID_MEM_WRITE: u32 = 2002;
pub const INVAL_PERM_MEM_WRITE: u32 = 2003;
pub const INVAL_PERM_MEM_EXEC: u32 = 2004;
pub const INVAL_PERM_MEM_READ: u32 = 2005;

/// Calculate SHA256 hash of file contents
pub fn sha256_file(path: &str) -> IoResult<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0; 8192];

    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }

    Ok(hex::encode(hasher.finalize()))
}

/// Calculate SHA256 hash of bytes
pub fn sha256_bytes(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Calculate SHA1 hash of bytes
pub fn sha1_bytes(_data: &[u8]) -> String {
    // Requires sha1 crate for real implementation, using stub for now
    String::from("")
}

/// Calculate MD5 hash of bytes
pub fn md5_bytes(data: &[u8]) -> String {
    format!("{:x}", md5::compute(data))
}

/// Convert bytes to hex string
pub fn bytes_to_hex(data: &[u8]) -> String {
    hex::encode(data)
}

/// Convert hex string to bytes
pub fn hex_to_bytes(hex: &str) -> Option<Vec<u8>> {
    hex::decode(hex).ok()
}

/// Align address to next page boundary
pub fn align_to_page(addr: u64, page_size: u64) -> u64 {
    (addr + page_size - 1) & !(page_size - 1)
}

/// Check if address range overlaps
pub fn ranges_overlap(start1: u64, end1: u64, start2: u64, end2: u64) -> bool {
    start1 < end2 && start2 < end1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_bytes() {
        let data = b"hello world";
        let hash = sha256_bytes(data);
        assert_eq!(hash, "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9");
    }

    #[test]
    fn test_hex_conversion() {
        let data = b"test";
        let hex = bytes_to_hex(data);
        assert_eq!(hex, "74657374");
        
        let recovered = hex_to_bytes(&hex).unwrap();
        assert_eq!(recovered, data);
    }

    #[test]
    fn test_align_to_page() {
        assert_eq!(align_to_page(0x1000, 0x1000), 0x1000);
        assert_eq!(align_to_page(0x1001, 0x1000), 0x2000);
        assert_eq!(align_to_page(0x0fff, 0x1000), 0x1000);
    }

    #[test]
    fn test_ranges_overlap() {
        assert!(ranges_overlap(0, 10, 5, 15));
        assert!(ranges_overlap(5, 15, 0, 10));
        assert!(!ranges_overlap(0, 10, 10, 20));
        assert!(!ranges_overlap(10, 20, 0, 10));
    }
}
