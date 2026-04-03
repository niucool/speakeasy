use crate::r#struct::{EmuStruct, Ptr};

pub const CSIDL_DESKTOP: u32 = 0x00;
pub const CSIDL_INTERNET: u32 = 0x01;
pub const CSIDL_PROGRAMS: u32 = 0x02;
pub const CSIDL_CONTROLS: u32 = 0x03;
pub const CSIDL_PRINTERS: u32 = 0x04;
pub const CSIDL_MYDOCUMENTS: u32 = 0x05;
pub const CSIDL_FAVORITES: u32 = 0x06;
pub const CSIDL_STARTUP: u32 = 0x07;
pub const CSIDL_RECENT: u32 = 0x08;
pub const CSIDL_SENDTO: u32 = 0x09;
pub const CSIDL_BITBUCKET: u32 = 0x0A;
pub const CSIDL_STARTMENU: u32 = 0x0B;
pub const CSIDL_MYMUSIC: u32 = 0x0D;
pub const CSIDL_MYVIDEO: u32 = 0x0E;
pub const CSIDL_DESKTOPDIRECTORY: u32 = 0x10;
pub const CSIDL_DRIVES: u32 = 0x11;
pub const CSIDL_NETWORK: u32 = 0x12;
pub const CSIDL_NETHOOD: u32 = 0x13;
pub const CSIDL_FONTS: u32 = 0x14;
pub const CSIDL_TEMPLATES: u32 = 0x15;
pub const CSIDL_COMMON_STARTMENU: u32 = 0x16;
pub const CSIDL_COMMON_PROGRAMS: u32 = 0x17;
pub const CSIDL_COMMON_STARTUP: u32 = 0x18;
pub const CSIDL_COMMON_DESKTOPDIRECTORY: u32 = 0x19;
pub const CSIDL_APPDATA: u32 = 0x1A;
pub const CSIDL_PRINTHOOD: u32 = 0x1B;
pub const CSIDL_LOCAL_APPDATA: u32 = 0x1C;
pub const CSIDL_ALTSTARTUP: u32 = 0x1D;
pub const CSIDL_COMMON_ALTSTARTUP: u32 = 0x1E;
pub const CSIDL_COMMON_FAVORITES: u32 = 0x1F;
pub const CSIDL_INTERNET_CACHE: u32 = 0x20;
pub const CSIDL_COOKIES: u32 = 0x21;
pub const CSIDL_HISTORY: u32 = 0x22;
pub const CSIDL_COMMON_APPDATA: u32 = 0x23;
pub const CSIDL_WINDOWS: u32 = 0x24;
pub const CSIDL_SYSTEM: u32 = 0x25;
pub const CSIDL_PROGRAM_FILES: u32 = 0x26;
pub const CSIDL_MYPICTURES: u32 = 0x27;
pub const CSIDL_PROFILE: u32 = 0x28;
pub const CSIDL_SYSTEMX86: u32 = 0x29;
pub const CSIDL_PROGRAM_FILESX86: u32 = 0x2A;
pub const CSIDL_PROGRAM_FILES_COMMON: u32 = 0x2B;
pub const CSIDL_PROGRAM_FILES_COMMONX86: u32 = 0x2C;
pub const CSIDL_COMMON_DOCUMENTS: u32 = 0x2E;
pub const CSIDL_COMMON_TEMPLATES: u32 = 0x2D;
pub const CSIDL_COMMON_ADMINTOOLS: u32 = 0x2F;
pub const CSIDL_ADMINTOOLS: u32 = 0x30;
pub const CSIDL_CONNECTIONS: u32 = 0x31;
pub const CSIDL_COMMON_MUSIC: u32 = 0x35;
pub const CSIDL_COMMON_PICTURES: u32 = 0x36;
pub const CSIDL_COMMON_VIDEO: u32 = 0x37;
pub const CSIDL_RESOURCES: u32 = 0x38;
pub const CSIDL_RESOURCES_LOCALIZED: u32 = 0x39;
pub const CSIDL_CDBURN_AREA: u32 = 0x3B;
pub const CSIDL_COMPUTERSNEARME: u32 = 0x3D;
pub const CSIDL_PLAYLISTS: u32 = 0x3F;
pub const CSIDL_SAMPLE_MUSIC: u32 = 0x40;
pub const CSIDL_SAMPLE_PLAYLISTS: u32 = 0x41;
pub const CSIDL_SAMPLE_PICTURES: u32 = 0x42;
pub const CSIDL_SAMPLE_VIDEOS: u32 = 0x43;
pub const CSIDL_PHOTOALBUMS: u32 = 0x45;

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
