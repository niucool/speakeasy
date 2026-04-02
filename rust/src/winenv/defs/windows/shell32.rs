use crate::r#struct::{EmuStruct, Ptr};

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct SHELLEXECUTEINFOA {
    pub cbSize: u32,
    pub fMask: u32,
    pub hwnd: Ptr,
    pub lpVerb: Ptr,
    pub lpFile: Ptr,
    pub lpParameters: Ptr,
    pub lpDirectory: Ptr,
    pub nShow: i32,
    pub hInstApp: Ptr,
    pub lpIDList: Ptr,
    pub lpClass: Ptr,
    pub hkeyClass: Ptr,
    pub dwHotKey: u32,
    pub DummyUnionName: Ptr,
    pub handle: Ptr,
}
impl EmuStruct for SHELLEXECUTEINFOA {}
