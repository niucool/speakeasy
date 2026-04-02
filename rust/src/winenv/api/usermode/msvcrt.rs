use crate::common;
use crate::winenv::api::ApiHandler;

pub struct MsvcrtHandler;

impl MsvcrtHandler {
    pub fn new() -> Self {
        Self
    }

    pub fn memcpy(dst: &mut [u8], src: &[u8]) -> usize {
        let count = dst.len().min(src.len());
        dst[..count].copy_from_slice(&src[..count]);
        count
    }

    pub fn memset(dst: &mut [u8], value: u8) -> usize {
        dst.fill(value);
        dst.len()
    }

    pub fn strlen(value: &str) -> usize {
        value.len()
    }

    pub fn strcmp(left: &str, right: &str) -> i32 {
        match left.cmp(right) {
            std::cmp::Ordering::Less => -1,
            std::cmp::Ordering::Equal => 0,
            std::cmp::Ordering::Greater => 1,
        }
    }

    pub fn sprintf(format_string: &str, args: &[u64]) -> String {
        if args.is_empty() {
            format_string.to_string()
        } else {
            format!("{format_string} {:?}", args)
        }
    }

    pub fn rand(seed: u32) -> u32 {
        common::sha256_bytes(&seed.to_le_bytes())
            .get(..8)
            .and_then(|hex| u32::from_str_radix(hex, 16).ok())
            .unwrap_or(seed)
    }
}

impl Default for MsvcrtHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl ApiHandler for MsvcrtHandler {
    fn call(&mut self, args: &[u64]) -> u64 {
        match args.len() {
            0 => Self::rand(0) as u64,
            1 => Self::strlen("speakeasy") as u64,
            2 => Self::strcmp("a", "b") as u64,
            _ => 0,
        }
    }

    fn get_name(&self) -> &str {
        "Msvcrt"
    }
}
