use crate::r#struct::EmuStruct;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct POINT {
    pub x: u32,
    pub y: u32,
}
impl EmuStruct for POINT {}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct RECT {
    pub left: i32,
    pub top: i32,
    pub right: i32,
    pub bottom: i32,
}
impl EmuStruct for RECT {}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct MONITORINFO {
    pub cbSize: u32,
    pub rcMonitor: RECT,
    pub rcWORK: RECT,
    pub dwFlags: u32,
}
impl EmuStruct for MONITORINFO {}
