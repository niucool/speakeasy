use crate::r#struct::{EmuStruct, Ptr};

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
pub struct FWPM_DISPLAY_DATA0 {
    pub name: Ptr,
    pub description: Ptr,
}
impl EmuStruct for FWPM_DISPLAY_DATA0 {}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct FWP_VALUE0 {
    pub type_: u32,
    pub data: Ptr,
}
impl EmuStruct for FWP_VALUE0 {}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct FWP_BYTE_BLOB {
    pub size: u32,
    pub data: Ptr,
}
impl EmuStruct for FWP_BYTE_BLOB {}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct FWPM_SUBLAYER0 {
    pub subLayerKey: GUID,
    pub displayData: FWPM_DISPLAY_DATA0,
    pub flags: u32,
    pub providerKey: GUID,
    pub providerData: FWP_BYTE_BLOB,
    pub weight: u16,
}
impl EmuStruct for FWPM_SUBLAYER0 {}
