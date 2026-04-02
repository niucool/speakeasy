use crate::r#struct::{EmuStruct, Ptr};

pub const NULL: u32 = 0;
pub const ERROR_SUCCESS: u32 = 0;
pub const ERROR_FILE_NOT_FOUND: u32 = 2;
pub const ERROR_PATH_NOT_FOUND: u32 = 3;
pub const ERROR_ACCESS_DENIED: u32 = 5;
pub const ERROR_INVALID_HANDLE: u32 = 6;
pub const ERROR_NO_MORE_FILES: u32 = 18;
pub const ERROR_FILE_EXISTS: u32 = 80;
pub const ERROR_INVALID_PARAMETER: u32 = 87;
pub const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
pub const ERROR_INVALID_LEVEL: u32 = 124;
pub const ERROR_MOD_NOT_FOUND: u32 = 126;
pub const ERROR_ALREADY_EXISTS: u32 = 183;
pub const ERROR_NO_MORE_ITEMS: u32 = 259;

pub const PAGE_EXECUTE: u32 = 0x10;
pub const PAGE_EXECUTE_READ: u32 = 0x20;
pub const PAGE_EXECUTE_READWRITE: u32 = 0x40;
pub const PAGE_EXECUTE_WRITECOPY: u32 = 0x80;
pub const PAGE_NOACCESS: u32 = 0x01;
pub const PAGE_READONLY: u32 = 0x02;
pub const PAGE_READWRITE: u32 = 0x04;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct GUID {
    pub Data1: u32,
    pub Data2: u16,
    pub Data3: u16,
    pub Data4: [u8; 8],
}
impl EmuStruct for GUID {}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct KSYSTEM_TIME {
    pub LowPart: u32,
    pub High1Time: u32,
    pub High2Time: u32,
}
impl EmuStruct for KSYSTEM_TIME {}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct UNICODE_STRING {
    pub Length: u16,
    pub MaximumLength: u16,
    pub Buffer: Ptr,
}
impl EmuStruct for UNICODE_STRING {}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct LARGE_INTEGER {
    pub QuadPart: i64,
}
impl EmuStruct for LARGE_INTEGER {}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct LIST_ENTRY {
    pub Flink: Ptr,
    pub Blink: Ptr,
}
impl EmuStruct for LIST_ENTRY {}
