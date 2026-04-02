use crate::r#struct::{EmuStruct, Ptr};
use crate::winenv::defs::windows::windows::{KSYSTEM_TIME, LARGE_INTEGER, LIST_ENTRY, UNICODE_STRING};

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct SSDT {
    pub pServiceTable: Ptr,
    pub pCounterTable: Ptr,
    pub NumberOfServices: u32,
    pub pArgumentTable: Ptr,
}
impl EmuStruct for SSDT {}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct STRING {
    pub Length: u16,
    pub MaximumLength: u16,
    pub Buffer: Ptr,
}
impl EmuStruct for STRING {}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct SYSTEM_MODULE {
    pub Reserved: [Ptr; 2],
    pub Base: Ptr,
    pub Size: u32,
    pub Flags: u32,
    pub Index: u16,
    pub Unknown: u16,
    pub LoadCount: u16,
    pub ModuleNameOffset: u16,
    pub ImageName: [u8; 256],
}
impl EmuStruct for SYSTEM_MODULE {}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct CLIENT_ID {
    pub UniqueProcess: u32,
    pub UniqueThread: u32,
}
impl EmuStruct for CLIENT_ID {}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct SYSTEM_THREAD_INFORMATION {
    pub Reserved1: [LARGE_INTEGER; 3],
    pub Reserved2: u32,
    pub StartAddress: Ptr,
    pub ClientId: CLIENT_ID,
    pub Priority: u32,
    pub BasePriority: u32,
    pub ContextSwitches: u32,
    pub ThreadState: u32,
    pub WaitReason: u32,
}
impl EmuStruct for SYSTEM_THREAD_INFORMATION {}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct KAPC {
    pub Type: u8,
    pub SpareByte0: u8,
    pub Size: u8,
    pub SpareByte1: u8,
    pub SpareLong0: u32,
    pub Thread: Ptr,
    pub ApcListEntry: LIST_ENTRY,
    pub KernelRoutine: Ptr,
    pub RundownRoutine: Ptr,
    pub NormalRoutine: Ptr,
    pub NormalContext: Ptr,
    pub SystemArgument1: Ptr,
    pub SystemArgument2: Ptr,
    pub ApcStateIndex: u8,
    pub ApcMode: u8,
    pub Inserted: u8,
}
impl EmuStruct for KAPC {}

pub type NtUnicodeString = UNICODE_STRING;
pub type NtKsystemTime = KSYSTEM_TIME;
