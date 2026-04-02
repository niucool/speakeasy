// WinDef Constants and Structures

// Types mappings
pub type DWORD = u32;
pub type WORD = u16;
pub type BYTE = u8;
pub type BOOL = i32;
pub type LONG = i32;
pub type ULONG = u32;
pub type HANDLE = u64;

// Base Struct Examples
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct POINT {
    pub x: LONG,
    pub y: LONG,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RECT {
    pub left: LONG,
    pub top: LONG,
    pub right: LONG,
    pub bottom: LONG,
}

pub const TRUE: BOOL = 1;
pub const FALSE: BOOL = 0;
