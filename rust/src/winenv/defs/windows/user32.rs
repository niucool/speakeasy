use crate::r#struct::{EmuStruct, Ptr};

pub const WH_CALLWNDPROC: i32 = 4;
pub const WH_CALLWNDPROCRET: i32 = 12;
pub const WH_CBT: i32 = 5;
pub const WH_DEBUG: i32 = 9;
pub const WH_FOREGROUNDIDLE: i32 = 11;
pub const WH_GETMESSAGE: i32 = 3;
pub const WH_JOURNALPLAYBACK: i32 = 1;
pub const WH_JOURNALRECORD: i32 = 0;
pub const WH_KEYBOARD: i32 = 2;
pub const WH_KEYBOARD_LL: i32 = 13;
pub const WH_MOUSE: i32 = 7;
pub const WH_MOUSE_LL: i32 = 14;
pub const WH_MSGFILTER: i32 = -1;
pub const WH_SHELL: i32 = 10;
pub const WH_SYSMSGFILTER: i32 = 6;

pub const WM_KEYDOWN: u32 = 0x0100;
pub const WM_SYSKEYDOWN: u32 = 0x0104;
pub const WM_TIMER: u32 = 0x0113;
pub const WM_PAINT: u32 = 0x000F;
pub const WM_INITDIALOG: u32 = 0x0110;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct MSG {
    pub hwnd: Ptr,
    pub message: u32,
    pub wParam: Ptr,
    pub lParam: Ptr,
    pub time: u32,
    pub pt_x: Ptr,
    pub pt_y: Ptr,
    pub lPrivate: u32,
}
impl EmuStruct for MSG {}
