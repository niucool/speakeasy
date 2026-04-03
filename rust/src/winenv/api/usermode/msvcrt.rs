use crate::binemu::BinaryEmulator;
use crate::common;
use crate::winenv::api::{ApiHandler, Result};

pub struct MsvcrtHandler;

impl MsvcrtHandler {
    pub fn new() -> Self {
        Self
    }

    fn strlen(&self, ptr: u64, emu: &mut dyn BinaryEmulator) -> usize {
        if let Ok(data) = emu.mem_read(ptr, 256) {
            let s = String::from_utf8_lossy(&data);
            s.trim_end_matches('\0').len()
        } else {
            0
        }
    }

    fn strcmp(&self, left: &str, right: &str) -> i32 {
        match left.cmp(right) {
            std::cmp::Ordering::Less => -1,
            std::cmp::Ordering::Equal => 0,
            std::cmp::Ordering::Greater => 1,
        }
    }
}

impl Default for MsvcrtHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl ApiHandler for MsvcrtHandler {
    fn call(&mut self, emu: &mut dyn BinaryEmulator, name: &str, args: &[u64]) -> Result<u64> {
        match name {
            "rand" => Ok(common::sha256_bytes(&[0u8; 4])
                .get(..4)
                .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
                .unwrap_or(0) as u64),
            "strlen" => Ok(self.strlen(args[0], emu) as u64),
            "strcmp" => {
                let left_ptr = args[0];
                let right_ptr = args[1];
                let left = if let Ok(data) = emu.mem_read(left_ptr, 256) {
                    String::from_utf8_lossy(&data)
                        .trim_end_matches('\0')
                        .to_string()
                } else {
                    String::new()
                };
                let right = if let Ok(data) = emu.mem_read(right_ptr, 256) {
                    String::from_utf8_lossy(&data)
                        .trim_end_matches('\0')
                        .to_string()
                } else {
                    String::new()
                };
                Ok(self.strcmp(&left, &right) as u64)
            }
            _ => Ok(0),
        }
    }

    fn get_name(&self) -> &str {
        "Msvcrt"
    }
}
