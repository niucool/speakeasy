use crate::r#struct::{EmuStruct, Ptr};

pub const NTE_BAD_ALGID: u32 = 0x8009_0008;
pub const SERVICE_WIN32: u32 = 0x30;
pub const SERVICE_ACTIVE: u32 = 0x1;
pub const SERVICE_INACTIVE: u32 = 0x2;
pub const SERVICE_STATE_ALL: u32 = 0x3;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct SERVICE_TABLE_ENTRY {
    pub lpServiceName: Ptr,
    pub lpServiceProc: Ptr,
}
impl EmuStruct for SERVICE_TABLE_ENTRY {}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct HCRYPTKEY {
    pub Algid: u32,
    pub keylen: u32,
    pub keyp: Ptr,
}
impl EmuStruct for HCRYPTKEY {}
