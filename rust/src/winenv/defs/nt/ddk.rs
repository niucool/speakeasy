pub const WINDOWS_CONSOLE: u32 = 3;
pub const PASSIVE_LEVEL: u32 = 0;
pub const LOW_LEVEL: u32 = 0;
pub const APC_LEVEL: u32 = 1;
pub const DISPATCH_LEVEL: u32 = 2;
pub const CMCI_LEVEL: u32 = 5;
pub const PROFILE_LEVEL: u32 = 27;
pub const CLOCK1_LEVEL: u32 = 28;
pub const CLOCK2_LEVEL: u32 = 28;
pub const IPI_LEVEL: u32 = 29;
pub const POWER_LEVEL: u32 = 30;
pub const HIGH_LEVEL: u32 = 31;

pub const STATUS_SUCCESS: u32 = 0;
pub const STATUS_BREAKPOINT: u32 = 0x8000_0003;
pub const STATUS_SINGLE_STEP: u32 = 0x8000_0004;
pub const STATUS_UNSUCCESSFUL: u32 = 0xC000_0001;
pub const STATUS_INFO_LENGTH_MISMATCH: u32 = 0xC000_0004;
pub const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
pub const STATUS_INTEGER_DIVIDE_BY_ZERO: u32 = 0xC000_0094;
pub const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
pub const STATUS_ILLEGAL_INSTRUCTION: u32 = 0xC000_001D;
pub const STATUS_PRIVILEGED_INSTRUCTION: u32 = 0xC000_0096;
pub const STATUS_INVALID_CID: u32 = 0xC000_000B;
pub const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
pub const STATUS_INVALID_DEVICE_REQUEST: u32 = 0xC000_0010;
pub const STATUS_BUFFER_TOO_SMALL: u32 = 0xC000_0023;
pub const STATUS_OBJECT_TYPE_MISMATCH: u32 = 0xC000_0024;
pub const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;
pub const STATUS_PROCEDURE_NOT_FOUND: u32 = 0xC000_007A;
pub const STATUS_RESOURCE_DATA_NOT_FOUND: u32 = 0xC000_0089;
pub const STATUS_NOT_SUPPORTED: u32 = 0xC000_00BB;
pub const STATUS_NOINTERFACE: u32 = 0xC000_02B9;
pub const STATUS_PORT_NOT_SET: u32 = 0xC000_0353;
pub const STATUS_DEBUGGER_INACTIVE: u32 = 0xC000_0354;
pub const STATUS_BAD_COMPRESSION_BUFFER: u32 = 0xC000_0242;
pub const STATUS_UNSUPPORTED_COMPRESSION: u32 = 0xC000_025F;

pub const DO_DIRECT_IO: u32 = 0x0000_0010;
pub const DO_BUFFERED_IO: u32 = 0x0000_0004;
pub const DO_EXCLUSIVE: u32 = 0x0000_0008;
pub const DO_DEVICE_INITIALIZING: u32 = 0x0000_0080;

pub const IRP_MJ_CREATE: u32 = 0x00;
pub const IRP_MJ_CREATE_NAMED_PIPE: u32 = 0x01;
pub const IRP_MJ_CLOSE: u32 = 0x02;
pub const IRP_MJ_READ: u32 = 0x03;
pub const IRP_MJ_WRITE: u32 = 0x04;
pub const IRP_MJ_QUERY_INFORMATION: u32 = 0x05;
pub const IRP_MJ_SET_INFORMATION: u32 = 0x06;
pub const IRP_MJ_QUERY_EA: u32 = 0x07;
pub const IRP_MJ_SET_EA: u32 = 0x08;
pub const IRP_MJ_FLUSH_BUFFERS: u32 = 0x09;
pub const IRP_MJ_QUERY_VOLUME_INFORMATION: u32 = 0x0A;
pub const IRP_MJ_SET_VOLUME_INFORMATION: u32 = 0x0B;
pub const IRP_MJ_DIRECTORY_CONTROL: u32 = 0x0C;
pub const IRP_MJ_FILE_SYSTEM_CONTROL: u32 = 0x0D;
pub const IRP_MJ_DEVICE_CONTROL: u32 = 0x0E;
pub const IRP_MJ_INTERNAL_DEVICE_CONTROL: u32 = 0x0F;
pub const IRP_MJ_SHUTDOWN: u32 = 0x10;
pub const IRP_MJ_LOCK_CONTROL: u32 = 0x11;
pub const IRP_MJ_CLEANUP: u32 = 0x12;
pub const IRP_MJ_CREATE_MAILSLOT: u32 = 0x13;
pub const IRP_MJ_QUERY_SECURITY: u32 = 0x14;
pub const IRP_MJ_SET_SECURITY: u32 = 0x15;
pub const IRP_MJ_POWER: u32 = 0x16;
pub const IRP_MJ_SYSTEM_CONTROL: u32 = 0x17;
pub const IRP_MJ_DEVICE_CHANGE: u32 = 0x18;
pub const IRP_MJ_QUERY_QUOTA: u32 = 0x19;
pub const IRP_MJ_SET_QUOTA: u32 = 0x1A;
pub const IRP_MJ_PNP: u32 = 0x1B;
pub const IRP_MJ_PNP_POWER: u32 = IRP_MJ_PNP;
pub const IRP_MJ_MAXIMUM_FUNCTION: u32 = 0x1B;

pub const COMPRESSION_FORMAT_LZNT1: u32 = 0x2;
pub const COMPRESSION_FORMAT_XPRESS: u32 = 0x3;

pub const DELETE: u32 = 0x0001_0000;
pub const READ_CONTROL: u32 = 0x0002_0000;
pub const WRITE_DAC: u32 = 0x0004_0000;
pub const WRITE_OWNER: u32 = 0x0008_0000;
pub const SYNCHRONIZE: u32 = 0x0010_0000;
pub const GENERIC_READ: u32 = 0x8000_0000;
pub const GENERIC_WRITE: u32 = 0x4000_0000;
pub const GENERIC_EXECUTE: u32 = 0x2000_0000;
pub const GENERIC_ALL: u32 = 0x1000_0000;

pub const FILE_SUPERSEDE: u32 = 0x0000_0000;
pub const FILE_OPEN: u32 = 0x0000_0001;
pub const FILE_CREATE: u32 = 0x0000_0002;
pub const FILE_OPEN_IF: u32 = 0x0000_0003;
pub const FILE_OVERWRITE: u32 = 0x0000_0004;
pub const FILE_OVERWRITE_IF: u32 = 0x0000_0005;

pub const FILE_READ_DATA: u32 = 0x0001;
pub const FILE_WRITE_DATA: u32 = 0x0002;
pub const FILE_APPEND_DATA: u32 = 0x0004;
pub const FILE_READ_EA: u32 = 0x0008;
pub const FILE_WRITE_EA: u32 = 0x0010;
pub const FILE_EXECUTE: u32 = 0x0020;
pub const FILE_DELETE_CHILD: u32 = 0x0040;
pub const FILE_READ_ATTRIBUTES: u32 = 0x0080;
pub const FILE_WRITE_ATTRIBUTES: u32 = 0x0100;

pub const PROCESS_BASIC_INFORMATION: u32 = 0;
pub const PROCESS_DEBUG_PORT: u32 = 7;
pub const PROCESS_WOW64_INFORMATION: u32 = 0x1A;
pub const PROCESS_IMAGE_FILE_NAME: u32 = 0x1B;
pub const PROCESS_BREAK_ON_TERMINATION: u32 = 0x1D;
pub const PROCESS_DEBUG_OBJECT_HANDLE: u32 = 0x1E;
pub const PROCESS_PROTECTION_INFORMATION: u32 = 0x3D;

pub const SYSTEM_BASIC_INFORMATION: u32 = 0x00;
pub const SYSTEM_PROCESSOR_INFORMATION: u32 = 0x01;
pub const SYSTEM_PERFORMANCE_INFORMATION: u32 = 0x02;
pub const SYSTEM_TIME_OF_DAY_INFORMATION: u32 = 0x03;
pub const SYSTEM_PATH_INFORMATION: u32 = 0x04;
pub const SYSTEM_PROCESS_INFORMATION: u32 = 0x05;
pub const SYSTEM_CALL_COUNT_INFORMATION: u32 = 0x06;
pub const SYSTEM_DEVICE_INFORMATION: u32 = 0x07;
pub const SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION: u32 = 0x08;
pub const SYSTEM_FLAGS_INFORMATION: u32 = 0x09;
pub const SYSTEM_CALL_TIME_INFORMATION: u32 = 0x0A;
pub const SYSTEM_MODULE_INFORMATION: u32 = 0x0B;
pub const SYSTEM_KERNEL_DEBUGGER_INFORMATION: u32 = 0x23;
pub const SYSTEM_CODE_INTEGRITY_INFORMATION: u32 = 0x67;

pub const FILE_DIRECTORY_INFORMATION: u32 = 1;
pub const FILE_FULL_DIRECTORY_INFORMATION: u32 = 2;
pub const FILE_BOTH_DIRECTORY_INFORMATION: u32 = 3;
pub const FILE_BASIC_INFORMATION: u32 = 4;
pub const FILE_STANDARD_INFORMATION: u32 = 5;
pub const FILE_INTERNAL_INFORMATION: u32 = 6;
pub const FILE_EA_INFORMATION: u32 = 7;
pub const FILE_ACCESS_INFORMATION: u32 = 8;
pub const FILE_NAME_INFORMATION: u32 = 9;
pub const FILE_RENAME_INFORMATION: u32 = 10;
pub const FILE_LINK_INFORMATION: u32 = 11;

pub const NONPAGED_POOL: u32 = 0;
pub const PAGED_POOL: u32 = 1;
pub const NONPAGED_POOL_MUST_SUCCEED: u32 = 2;
pub const DONT_USE_THIS_TYPE: u32 = 3;
pub const NONPAGED_POOL_CACHE_ALIGNED: u32 = 4;
pub const PAGED_POOL_CACHE_ALIGNED: u32 = 5;
pub const NONPAGED_POOL_CACHE_ALIGNED_MUST_SUCCEED: u32 = 6;
pub const MAX_POOL_TYPE: u32 = 7;
pub const NONPAGED_POOL_SESSION: u32 = 32;
pub const PAGED_POOL_SESSION: u32 = 33;
pub const NONPAGED_POOL_MUST_SUCCEED_SESSION: u32 = 34;
pub const DONT_USE_THIS_TYPE_SESSION: u32 = 35;
pub const NONPAGED_POOL_CACHE_ALIGNED_SESSION: u32 = 36;
pub const PAGED_POOL_CACHE_ALIGNED_SESSION: u32 = 37;
pub const NONPAGED_POOL_CACHE_ALIGNED_MUST_SUCCEED_SESSION: u32 = 38;
pub const NONPAGED_POOL_NX: u32 = 512;

pub const KERNEL_MODE: u32 = 0;
pub const USER_MODE: u32 = 1;
pub const MAXIMUM_MODE: u32 = 2;

pub const IMAGE_DOS_SIGNATURE: &[u8; 2] = b"MZ";
pub const PE32_BIT: u32 = 0x0100;
pub const PE32_PLUS_BIT: u32 = 0x0200;

pub fn get_flag_defines(flags: u32, prefix: &str) -> Vec<&'static str> {
    let all = [
        ("DELETE", DELETE),
        ("READ_CONTROL", READ_CONTROL),
        ("WRITE_DAC", WRITE_DAC),
        ("WRITE_OWNER", WRITE_OWNER),
        ("SYNCHRONIZE", SYNCHRONIZE),
        ("GENERIC_READ", GENERIC_READ),
        ("GENERIC_WRITE", GENERIC_WRITE),
        ("GENERIC_EXECUTE", GENERIC_EXECUTE),
        ("GENERIC_ALL", GENERIC_ALL),
        ("FILE_READ_DATA", FILE_READ_DATA),
        ("FILE_WRITE_DATA", FILE_WRITE_DATA),
        ("FILE_APPEND_DATA", FILE_APPEND_DATA),
        ("FILE_EXECUTE", FILE_EXECUTE),
        ("FILE_DELETE_CHILD", FILE_DELETE_CHILD),
    ];
    all.iter()
        .filter_map(|(name, value)| {
            if name.starts_with(prefix) && flags & *value != 0 {
                Some(*name)
            } else {
                None
            }
        })
        .collect()
}

pub fn get_const_defines(value: u32, prefix: &str) -> Vec<&'static str> {
    let all = [
        ("FILE_SUPERSEDE", FILE_SUPERSEDE),
        ("FILE_OPEN", FILE_OPEN),
        ("FILE_CREATE", FILE_CREATE),
        ("FILE_OPEN_IF", FILE_OPEN_IF),
        ("FILE_OVERWRITE", FILE_OVERWRITE),
        ("FILE_OVERWRITE_IF", FILE_OVERWRITE_IF),
        ("STATUS_SUCCESS", STATUS_SUCCESS),
        ("STATUS_INVALID_PARAMETER", STATUS_INVALID_PARAMETER),
        ("STATUS_NOT_SUPPORTED", STATUS_NOT_SUPPORTED),
    ];
    all.iter()
        .filter_map(|(name, current)| {
            if name.starts_with(prefix) && *current == value {
                Some(*name)
            } else {
                None
            }
        })
        .collect()
}

pub fn get_access_defines(flags: u32) -> Vec<&'static str> {
    get_flag_defines(flags, "")
        .into_iter()
        .filter(|name| {
            matches!(
                *name,
                "DELETE"
                    | "READ_CONTROL"
                    | "WRITE_DAC"
                    | "WRITE_OWNER"
                    | "SYNCHRONIZE"
                    | "GENERIC_READ"
                    | "GENERIC_WRITE"
                    | "GENERIC_EXECUTE"
                    | "GENERIC_ALL"
            )
        })
        .collect()
}

pub fn get_file_access_defines(flags: u32) -> Vec<&'static str> {
    get_flag_defines(flags, "FILE_")
}

pub fn get_create_disposition(disp: u32) -> Option<&'static str> {
    get_const_defines(disp, "FILE_").into_iter().next()
}
