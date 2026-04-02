use std::fmt;
use std::mem;
use std::slice;

pub type Ptr = u64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PointerWidth {
    Bits32,
    Bits64,
    Native,
}

impl PointerWidth {
    pub fn bytes(self) -> usize {
        match self {
            Self::Bits32 => 4,
            Self::Bits64 => 8,
            Self::Native => mem::size_of::<usize>(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmuStructException {
    pub message: String,
}

impl EmuStructException {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for EmuStructException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for EmuStructException {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Enum {
    pub value: u64,
}

impl Enum {
    pub fn new(value: u64) -> Self {
        Self { value }
    }

    pub fn as_u32(self) -> u32 {
        self.value as u32
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FieldDescriptor {
    pub name: &'static str,
    pub offset: usize,
    pub size: usize,
}

/// Safe memory casting wrapper for C structures mapped inside the emulator space.
pub trait EmuStruct: Sized + Copy {
    fn sizeof(&self) -> usize {
        mem::size_of::<Self>()
    }

    fn get_bytes(&self) -> Vec<u8> {
        unsafe {
            let ptr = self as *const Self as *const u8;
            slice::from_raw_parts(ptr, mem::size_of::<Self>()).to_vec()
        }
    }

    fn cast(bytes: &[u8]) -> Self {
        let mut obj = unsafe { mem::zeroed::<Self>() };
        unsafe {
            let ptr = &mut obj as *mut Self as *mut u8;
            let size = mem::size_of::<Self>().min(bytes.len());
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr, size);
        }
        obj
    }

    fn cast_mut(&mut self, bytes: &[u8]) {
        let size = mem::size_of::<Self>().min(bytes.len());
        unsafe {
            let ptr = self as *mut Self as *mut u8;
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr, size);
        }
    }

    fn zeroed() -> Self {
        unsafe { mem::zeroed::<Self>() }
    }

    fn copy_to_slice(&self, out: &mut [u8]) -> usize {
        let bytes = self.get_bytes();
        let count = out.len().min(bytes.len());
        out[..count].copy_from_slice(&bytes[..count]);
        count
    }
}

pub trait EmuUnion: EmuStruct {}

impl<T: EmuStruct> EmuUnion for T {}

pub fn get_ptr_field(width: PointerWidth) -> usize {
    width.bytes()
}

pub fn get_pack(ptr_size: Option<usize>, pack: Option<usize>) -> usize {
    if let Some(pack) = pack {
        pack
    } else if let Some(ptr_size) = ptr_size {
        ptr_size * 2
    } else {
        1
    }
}

pub fn get_field_name(fields: &[FieldDescriptor], offset: usize) -> Option<&'static str> {
    fields.iter().find_map(|field| {
        if offset == field.offset || (field.offset..field.offset + field.size).contains(&offset) {
            Some(field.name)
        } else {
            None
        }
    })
}
