// Struct and Pointer definitions for Speakeasy

use serde::{Serialize, Deserialize};

/// Represents a pointer in emulated memory
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ptr(pub u64);

impl From<u64> for Ptr {
    fn from(val: u64) -> Self {
        Ptr(val)
    }
}

impl From<Ptr> for u64 {
    fn from(val: Ptr) -> Self {
        val.0
    }
}

/// Trait for all structures that can be emulated/mapped in memory
pub trait EmuStruct: Sized + Copy {
    fn get_bytes(&self) -> Vec<u8> {
        let size = std::mem::size_of::<Self>();
        let ptr = self as *const Self as *const u8;
        unsafe { std::slice::from_raw_parts(ptr, size).to_vec() }
    }

    fn from_bytes(data: &[u8]) -> Option<Self> {
        let size = std::mem::size_of::<Self>();
        if data.len() < size {
            return None;
        }
        let ptr = data.as_ptr() as *const Self;
        Some(unsafe { *ptr })
    }
}
