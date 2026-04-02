use crate::r#struct::{EmuStruct, Ptr};

pub const NERR_SUCCESS: u32 = 0;
pub const NET_SETUP_UNKNOWN_STATUS: u32 = 0;
pub const NET_SETUP_UNJOINED: u32 = 1;
pub const NET_SETUP_WORKGROUP_NAME: u32 = 2;
pub const NET_SETUP_DOMAIN_NAME: u32 = 3;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct WKSTA_INFO_100 {
    pub wki_platform_id: Ptr,
    pub wki_computername: Ptr,
    pub wki_langroup: Ptr,
    pub wki_ver_major: u32,
    pub wki_ver_minor: u32,
}
impl EmuStruct for WKSTA_INFO_100 {}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct WKSTA_INFO_101 {
    pub wki_platform_id: Ptr,
    pub wki_computername: Ptr,
    pub wki_langroup: Ptr,
    pub wki_ver_major: u32,
    pub wki_ver_minor: u32,
    pub wki_lanroot: Ptr,
}
impl EmuStruct for WKSTA_INFO_101 {}
