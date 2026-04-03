use crate::r#struct::{EmuStruct, Ptr};

pub const WSADESCRIPTION_LEN: usize = 256;
pub const WSASYS_STATUS_LEN: usize = 128;

pub const MAX_PATH: usize = 260;
pub const MAX_MODULE_NAME32: usize = 255;

pub const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
pub const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;

pub const TH32CS_INHERIT: u32 = 0x80000000;
pub const TH32CS_SNAPHEAPLIST: u32 = 0x00000001;
pub const TH32CS_SNAPMODULE: u32 = 0x00000008;
pub const TH32CS_SNAPMODULE32: u32 = 0x00000010;
pub const TH32CS_SNAPPROCESS: u32 = 0x00000002;
pub const TH32CS_SNAPTHREAD: u32 = 0x00000004;

pub const PROCESSOR_ARCHITECTURE_AMD64: u16 = 9;
pub const PROCESSOR_ARCHITECTURE_INTEL: u16 = 0;

pub const LOCALE_INVARIANT: u32 = 0x7F;
pub const LOCALE_USER_DEFAULT: u32 = 0x400;
pub const LOCALE_SYSTEM_DEFAULT: u32 = 0x800;
pub const LOCALE_CUSTOM_DEFAULT: u32 = 0xC00;
pub const LOCALE_CUSTOM_UNSPECIFIED: u32 = 0x1000;
pub const LOCALE_CUSTOM_UI_DEFAULT: u32 = 0x1400;

pub const LOCALE_SENGLISHLANGUAGENAME: u32 = 0x1001;
pub const LOCALE_SENGLISHCOUNTRYNAME: u32 = 0x1002;

pub const DRIVE_UNKNOWN: u32 = 0;
pub const DRIVE_NO_ROOT_DIR: u32 = 1;
pub const DRIVE_REMOVABLE: u32 = 2;
pub const DRIVE_FIXED: u32 = 3;
pub const DRIVE_REMOTE: u32 = 4;
pub const DRIVE_CDROM: u32 = 5;
pub const DRIVE_RAMDISK: u32 = 6;

pub const COMPUTER_NAME_NET_BIOS: u32 = 0;
pub const COMPUTER_NAME_DNS_HOSTNAME: u32 = 1;
pub const COMPUTER_NAME_DNS_DOMAIN: u32 = 2;
pub const COMPUTER_NAME_DNS_FULLY_QUALIFIED: u32 = 3;
pub const COMPUTER_NAME_PHYSICAL_NET_BIOS: u32 = 4;
pub const COMPUTER_NAME_PHYSICAL_DNS_HOSTNAME: u32 = 5;
pub const COMPUTER_NAME_PHYSICAL_DNS_DOMAIN: u32 = 6;
pub const COMPUTER_NAME_PHYSICAL_DNS_FULLY_QUALIFIED: u32 = 7;
pub const COMPUTER_NAME_MAX: u32 = 8;

pub const GET_FILE_EX_INFO_STANDARD: u32 = 0;

pub const EXCEPTION_CONTINUE_SEARCH: i32 = 0;
pub const EXCEPTION_EXECUTE_HANDLER: i32 = 1;

pub const THREAD_PRIORITY_NORMAL: i32 = 0;

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
    pub szExeFile: [u8; MAX_PATH * 2], // Supporting Wide by default for simplicity or use a generic
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

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct MEMORY_BASIC_INFORMATION {
    pub BaseAddress: Ptr,
    pub AllocationBase: Ptr,
    pub AllocationProtect: u32,
    pub RegionSize: Ptr,
    pub State: u32,
    pub Protect: u32,
    pub r#Type: u32,
}
impl EmuStruct for MEMORY_BASIC_INFORMATION {}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct FILETIME {
    pub dwLowDateTime: u32,
    pub dwHighDateTime: u32,
}
impl EmuStruct for FILETIME {}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct WIN32_FIND_DATA {
    pub dwFileAttributes: u32,
    pub ftCreationTime: FILETIME,
    pub ftLastAccessTime: FILETIME,
    pub ftLastWriteTime: FILETIME,
    pub nFileSizeHigh: u32,
    pub nFileSizeLow: u32,
    pub dwReserved0: u32,
    pub dwReserved1: u32,
    pub cFileName: [u8; MAX_PATH * 2],
    pub cAlternateFileName: [u8; 14 * 2],
}
impl EmuStruct for WIN32_FIND_DATA {}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct WIN32_FILE_ATTRIBUTE_DATA {
    pub dwFileAttributes: u32,
    pub ftCreationTime: FILETIME,
    pub ftLastAccessTime: FILETIME,
    pub ftLastWriteTime: FILETIME,
    pub nFileSizeHigh: u32,
    pub nFileSizeLow: u32,
}
impl EmuStruct for WIN32_FILE_ATTRIBUTE_DATA {}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct SYSTEM_INFO {
    pub wProcessorArchitecture: u16,
    pub wReserved: u16,
    pub dwPageSize: u32,
    pub lpMinimumApplicationAddress: Ptr,
    pub lpMaximumApplicationAddress: Ptr,
    pub dwActiveProcessorMask: Ptr,
    pub dwNumberOfProcessors: u32,
    pub dwProcessorType: u32,
    pub dwAllocationGranularity: u32,
    pub wProcessorLevel: u16,
    pub wProcessorRevision: u16,
}
impl EmuStruct for SYSTEM_INFO {}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct SYSTEMTIME {
    pub wYear: u16,
    pub wMonth: u16,
    pub wDayOfWeek: u16,
    pub wDay: u16,
    pub wHour: u16,
    pub wMinute: u16,
    pub wSecond: u16,
    pub wMilliseconds: u16,
}
impl EmuStruct for SYSTEMTIME {}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct STARTUPINFO {
    pub cb: u32,
    pub lpReserved: Ptr,
    pub lpDesktop: Ptr,
    pub lpTitle: Ptr,
    pub dwX: u32,
    pub dwY: u32,
    pub dwXSize: u32,
    pub dwYSize: u32,
    pub dwXCountChars: u32,
    pub dwYCountChars: u32,
    pub dwFillAttribute: u32,
    pub dwFlags: u32,
    pub wShowWindow: u16,
    pub cbReserved2: u16,
    pub lpReserved2: Ptr,
    pub hStdInput: Ptr,
    pub hStdOutput: Ptr,
    pub hStdError: Ptr,
}
impl EmuStruct for STARTUPINFO {}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct OSVERSIONINFO {
    pub dwOSVersionInfoSize: u32,
    pub dwMajorVersion: u32,
    pub dwMinorVersion: u32,
    pub dwBuildNumber: u32,
    pub dwPlatformId: u32,
    pub szCSDVersion: [u8; 128],
}
impl EmuStruct for OSVERSIONINFO {}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct OSVERSIONINFOEX {
    pub dwOSVersionInfoSize: u32,
    pub dwMajorVersion: u32,
    pub dwMinorVersion: u32,
    pub dwBuildNumber: u32,
    pub dwPlatformId: u32,
    pub szCSDVersion: [u8; 128],
    pub wServicePackMajor: u16,
    pub wServicePackMinor: u16,
    pub wSuiteMask: u16,
    pub wProductType: u8,
    pub wReserved: u8,
}
impl EmuStruct for OSVERSIONINFOEX {}
