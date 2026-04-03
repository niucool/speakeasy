use crate::r#struct::{EmuStruct, Ptr};

pub const NULL: u32 = 0;

pub const ERROR_SUCCESS: u32 = 0;
pub const ERROR_FILE_NOT_FOUND: u32 = 2;
pub const ERROR_PATH_NOT_FOUND: u32 = 3;
pub const ERROR_ACCESS_DENIED: u32 = 5;
pub const ERROR_INVALID_HANDLE: u32 = 6;
pub const ERROR_NO_MORE_FILES: u32 = 18;
pub const ERROR_FILE_EXISTS: u32 = 80;
pub const ERROR_INVALID_PARAMETER: u32 = 87;
pub const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
pub const ERROR_INVALID_LEVEL: u32 = 124;
pub const ERROR_MOD_NOT_FOUND: u32 = 126;
pub const ERROR_ALREADY_EXISTS: u32 = 183;
pub const ERROR_NO_MORE_ITEMS: u32 = 259;

pub const S_OK: u32 = 0;

pub const WAIT_OBJECT_0: u32 = 0;
pub const WAIT_TIMEOUT: u32 = 0x102;

pub const MEM_COMMIT: u32 = 0x1000;
pub const MEM_FREE: u32 = 0x10000;
pub const MEM_RESERVE: u32 = 0x2000;
pub const MEM_IMAGE: u32 = 0x1000000;
pub const MEM_MAPPED: u32 = 0x40000;
pub const MEM_PRIVATE: u32 = 0x20000;

pub const PAGE_EXECUTE: u32 = 0x10;
pub const PAGE_EXECUTE_READ: u32 = 0x20;
pub const PAGE_EXECUTE_READWRITE: u32 = 0x40;
pub const PAGE_EXECUTE_WRITECOPY: u32 = 0x80;
pub const PAGE_NOACCESS: u32 = 0x01;
pub const PAGE_READONLY: u32 = 0x02;
pub const PAGE_READWRITE: u32 = 0x04;

pub const CREATE_ALWAYS: u32 = 2;
pub const CREATE_NEW: u32 = 1;
pub const OPEN_ALWAYS: u32 = 4;
pub const OPEN_EXISTING: u32 = 3;
pub const TRUNCATE_EXISTING: u32 = 5; // Note: Python had 4 but TRUNCATE_EXISTING is usually 5

pub const INVALID_HANDLE_VALUE: u32 = 0xFFFFFFFF;

pub const EXCEPTION_CONTINUE_SEARCH: u32 = 0;
pub const EXCEPTION_EXECUTE_HANDLER: u32 = 1;
pub const EXCEPTION_CONTINUE_EXECUTION: u32 = 0xFFFFFFFF;

pub const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
pub const INVALID_FILE_ATTRIBUTES: u32 = 0xFFFFFFFF;

pub const SIGSEGV: u32 = 11;
pub const SIGILL: u32 = 4;
pub const SIGFPE: u32 = 8;

pub const CREATE_NEW_CONSOLE: u32 = 0x00000010;
pub const CREATE_NEW_PROCESS_GROUP: u32 = 0x00000200;
pub const CREATE_NO_WINDOW: u32 = 0x08000000;
pub const CREATE_SUSPENDED: u32 = 0x00000004;
pub const CREATE_UNICODE_ENVIRONMENT: u32 = 0x00000400;

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
pub struct KSYSTEM_TIME {
    pub LowPart: u32,
    pub High1Time: u32,
    pub High2Time: u32,
}
impl EmuStruct for KSYSTEM_TIME {}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct M128A {
    pub Low: u64,
    pub High: u64,
}
impl EmuStruct for M128A {}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct UNICODE_STRING {
    pub Length: u16,
    pub MaximumLength: u16,
    pub Buffer: Ptr,
}
impl EmuStruct for UNICODE_STRING {}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct LARGE_INTEGER {
    pub LowPart: u32,
    pub HighPart: u32,
}
impl EmuStruct for LARGE_INTEGER {}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct LIST_ENTRY {
    pub Flink: Ptr,
    pub Blink: Ptr,
}
impl EmuStruct for LIST_ENTRY {}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct EXCEPTION_RECORD {
    pub ExceptionCode: u32,
    pub ExceptionFlags: u32,
    pub ExceptionRecord: Ptr,
    pub ExceptionAddress: Ptr,
    pub NumberParameters: u32,
    pub ExceptionInformation: [u32; 15],
}
impl EmuStruct for EXCEPTION_RECORD {}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct FLOATING_SAVE_AREA {
    pub ControlWord: u32,
    pub StatusWord: u32,
    pub TagWord: u32,
    pub ErrorOffset: u32,
    pub ErrorSelector: u32,
    pub DataOffset: u32,
    pub DataSelector: u32,
    pub RegisterArea: [u8; 80],
    pub Spare0: u32,
}
impl EmuStruct for FLOATING_SAVE_AREA {}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct CONTEXT {
    pub ContextFlags: u32,
    pub Dr0: u32,
    pub Dr1: u32,
    pub Dr2: u32,
    pub Dr3: u32,
    pub Dr6: u32,
    pub Dr7: u32,
    pub FloatSave: FLOATING_SAVE_AREA,
    pub SegGs: u32,
    pub SegFs: u32,
    pub SegEs: u32,
    pub SegDs: u32,
    pub Edi: u32,
    pub Esi: u32,
    pub Ebx: u32,
    pub Edx: u32,
    pub Ecx: u32,
    pub Eax: u32,
    pub Ebp: u32,
    pub Eip: u32,
    pub SegCs: u32,
    pub EFlags: u32,
    pub Esp: u32,
    pub SegSs: u32,
}
impl EmuStruct for CONTEXT {}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct CONTEXT64 {
    pub P1Home: u64,
    pub P2Home: u64,
    pub P3Home: u64,
    pub P4Home: u64,
    pub P5Home: u64,
    pub P6Home: u64,
    pub ContextFlags: u32,
    pub MxCsr: u32,
    pub SegCs: u16,
    pub SegDs: u16,
    pub SegEs: u16,
    pub SegFs: u16,
    pub SegGs: u16,
    pub SegSs: u16,
    pub EFlags: u32,
    pub Dr0: u64,
    pub Dr1: u64,
    pub Dr2: u64,
    pub Dr3: u64,
    pub Dr6: u64,
    pub Dr7: u64,
    pub Rax: u64,
    pub Rcx: u64,
    pub Rdx: u64,
    pub Rbx: u64,
    pub Rsp: u64,
    pub Rbp: u64,
    pub Rsi: u64,
    pub Rdi: u64,
    pub R8: u64,
    pub R9: u64,
    pub R10: u64,
    pub R11: u64,
    pub R12: u64,
    pub R13: u64,
    pub R14: u64,
    pub R15: u64,
    pub Rip: u64,
    pub Header: [M128A; 2],
    pub Legacy: [M128A; 8],
    pub Xmm0: M128A,
    pub Xmm1: M128A,
    pub Xmm2: M128A,
    pub Xmm3: M128A,
    pub Xmm4: M128A,
    pub Xmm5: M128A,
    pub Xmm6: M128A,
    pub Xmm7: M128A,
    pub Xmm8: M128A,
    pub Xmm9: M128A,
    pub Xmm10: M128A,
    pub Xmm11: M128A,
    pub Xmm12: M128A,
    pub Xmm13: M128A,
    pub Xmm14: M128A,
    pub Xmm15: M128A,
    pub VectorRegister: [M128A; 26],
    pub VectorControl: u64,
    pub DebugControl: u64,
    pub LastBranchToRip: u64,
    pub LastBranchFromRip: u64,
    pub LastExceptionToRip: u64,
    pub LastExceptionFromRip: u64,
}
impl EmuStruct for CONTEXT64 {}
