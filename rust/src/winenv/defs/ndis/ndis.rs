use crate::r#struct::{EmuStruct, Ptr};

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct NDIS_OBJECT_HEADER {
    pub Type: u8,
    pub Revision: u8,
    pub Size: u16,
}
impl EmuStruct for NDIS_OBJECT_HEADER {}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct NDIS_GENERIC_OBJECT {
    pub Header: NDIS_OBJECT_HEADER,
    pub Caller: Ptr,
    pub CallersCaller: Ptr,
    pub DriverObject: Ptr,
}
impl EmuStruct for NDIS_GENERIC_OBJECT {}
