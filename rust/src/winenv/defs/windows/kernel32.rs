use crate::r#struct::{EmuStruct, Ptr};

pub const MAX_PATH: usize = 260;
pub const MAX_MODULE_NAME32: usize = 255;
pub const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
pub const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct PROCESSENTRY32 {
    pub dwSize: u32,
    pub cntUsage: u32,
    pub th32ProcessID: u32,
    pub th32DefaultHeapID: Ptr,
    pub th32ModuleID: u32,
    pub cntThreads: u32,
    pub th32ParentProcessID: u32,
    pub pcPriClassBase: u32,
    pub dwFlags: u32,
    pub szExeFile: [u8; MAX_PATH * 2],
}
impl EmuStruct for PROCESSENTRY32 {}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct THREADENTRY32 {
    pub dwSize: u32,
    pub cntUsage: u32,
    pub th32ThreadID: u32,
    pub th32OwnerProcessID: u32,
    pub tpBasePri: u32,
    pub tpDeltaPri: u32,
    pub dwFlags: u32,
}
impl EmuStruct for THREADENTRY32 {}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct MODULEENTRY32 {
    pub dwSize: u32,
    pub th32ModuleID: u32,
    pub th32ProcessID: u32,
    pub GlblcntUsage: u32,
    pub ProccntUsage: u32,
    pub modBaseAddr: Ptr,
    pub modBaseSize: u32,
    pub hModule: u32,
    pub szModule: [u8; (MAX_MODULE_NAME32 + 1) * 2],
    pub szExePath: [u8; MAX_PATH * 2],
}
impl EmuStruct for MODULEENTRY32 {}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct PROCESS_INFORMATION {
    pub hProcess: Ptr,
    pub hThread: Ptr,
    pub dwProcessId: u32,
    pub dwThreadId: u32,
}
impl EmuStruct for PROCESS_INFORMATION {}
