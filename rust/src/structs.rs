// Data structures for emulation mappings
use std::mem;
use std::slice;

/// Safe memory casting wrapper for C structures mapped inside the emulator space.
/// In Python, this was done dynamically via `ctypes`.
/// In Rust, implementors must use `#[repr(C)]`, `#[derive(Clone, Copy)]` on their struct.
pub trait EmuStruct: Sized + Copy {
    /// Returns the size of the underlying C struct.
    fn sizeof(&self) -> usize {
        mem::size_of::<Self>()
    }

    /// Read raw bytes corresponding to the layout of this struct.
    fn get_bytes(&self) -> Vec<u8> {
        unsafe {
            let p = self as *const Self as *const u8;
            slice::from_raw_parts(p, mem::size_of::<Self>()).to_vec()
        }
    }

    /// Construct this struct by copying over a raw byte slice.
    /// Will zero-pad if byte slice is smaller than the struct, and truncate if larger.
    fn cast(bytes: &[u8]) -> Self {
        let mut obj = unsafe { mem::zeroed::<Self>() };
        
        // Copy available bytes
        unsafe {
            let p = &mut obj as *mut Self as *mut u8;
            let size = mem::size_of::<Self>().min(bytes.len());
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), p, size);
        }
        
        obj
    }
}
