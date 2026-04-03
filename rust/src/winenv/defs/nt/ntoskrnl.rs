use crate::r#struct::{EmuStruct, Ptr};
use crate::winenv::defs::windows::windows::{
    KSYSTEM_TIME, LARGE_INTEGER, LIST_ENTRY, UNICODE_STRING,
};

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
    pub UniqueProcess: Ptr,
    pub UniqueThread: Ptr,
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
pub struct SYSTEM_PROCESS_INFORMATION {
    pub NextEntryOffset: u32,
    pub NumberOfThreads: u32,
    pub Reserved1: [u8; 48],
    pub ImageName: UNICODE_STRING,
    pub BasePriority: u32,
    pub UniqueProcessId: Ptr,
    pub InheritedFromUniqueProcessId: Ptr,
    pub HandleCount: u32,
    pub SessionId: u32,
    pub UniqueProcessKey: Ptr,
    pub PeakVirtualSize: Ptr,
    pub VirtualSize: Ptr,
    pub PageFaultCount: u32,
    pub PeakWorkingSetSize: Ptr,
    pub WorkingSetSize: Ptr,
    pub QuotaPeakPagedPoolUsage: Ptr,
    pub QuotaPagedPoolUsage: Ptr,
    pub QuotaPeakNonPagedPoolUsage: Ptr,
    pub QuotaNonPagedPoolUsage: Ptr,
    pub PagefileUsage: Ptr,
    pub PeakPagefileUsage: Ptr,
    pub PrivatePageCount: Ptr,
    pub Reserved7: [LARGE_INTEGER; 6],
}
impl EmuStruct for SYSTEM_PROCESS_INFORMATION {}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct MDL {
    pub Next: Ptr,
    pub Size: u16,
    pub MdlFlags: u16,
    pub Process: Ptr,
    pub MappedSystemVa: Ptr,
    pub StartVa: Ptr,
    pub ByteCount: u32,
    pub ByteOffset: u32,
}
impl EmuStruct for MDL {}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct KIDTENTRY {
    pub OffsetLow: u16,
    pub Selector: u16,
    pub Base: u32,
}
impl EmuStruct for KIDTENTRY {}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct KIDTENTRY64 {
    pub OffsetLow: u16,
    pub Selector: u16,
    pub Reserved0: u16,
    pub OffsetMiddle: u16,
    pub OffsetHigh: u32,
    pub Reserved1: u32,
}
impl EmuStruct for KIDTENTRY64 {}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ETHREAD {
    pub Data: [u8; 4096],
}
impl EmuStruct for ETHREAD {}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct EPROCESS {
    pub Data: [u8; 4096],
}
impl EmuStruct for EPROCESS {}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct KEVENT {
    pub Data: [u8; 4096],
}
impl EmuStruct for KEVENT {}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct MUTANT {
    pub Data: [u8; 4096],
}
impl EmuStruct for MUTANT {}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct RTL_OSVERSIONINFOW {
    pub dwOSVersionInfoSize: u32,
    pub dwMajorVersion: u32,
    pub dwMinorVersion: u32,
    pub dwBuildNumber: u32,
    pub dwPlatformId: u32,
    pub szCSDVersion: [u8; 256],
}
impl EmuStruct for RTL_OSVERSIONINFOW {}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct RTL_OSVERSIONINFOEXW {
    pub dwOSVersionInfoSize: u32,
    pub dwMajorVersion: u32,
    pub dwMinorVersion: u32,
    pub dwBuildNumber: u32,
    pub dwPlatformId: u32,
    pub szCSDVersion: [u8; 256],
    pub wServicePackMajor: u16,
    pub wServicePackMinor: u16,
    pub wSuiteMask: u16,
    pub wProductType: u8,
    pub wReserved: u8,
}
impl EmuStruct for RTL_OSVERSIONINFOEXW {}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct IDT {
    pub Limit: u16,
    pub Descriptors: Ptr,
}
impl EmuStruct for IDT {}

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

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct OBJECT_ATTRIBUTES {
    pub Length: u32,
    pub RootDirectory: Ptr,
    pub ObjectName: Ptr,
    pub Attributes: u32,
    pub SecurityDescriptor: Ptr,
    pub SecurityQualityOfService: Ptr,
}
impl EmuStruct for OBJECT_ATTRIBUTES {}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct FILE_STANDARD_INFORMATION {
    pub AllocationSize: LARGE_INTEGER,
    pub EndOfFile: LARGE_INTEGER,
    pub NumberOfLinks: u32,
    pub DeletePending: u8,
    pub Directory: u8,
}
impl EmuStruct for FILE_STANDARD_INFORMATION {}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct DRIVER_OBJECT {
    pub Type: u16,
    pub Size: u16,
    pub DeviceObject: Ptr,
    pub Flags: u32,
    pub DriverStart: Ptr,
    pub DriverSize: u32,
    pub DriverSection: Ptr,
    pub DriverExtension: Ptr,
    pub DriverName: UNICODE_STRING,
    pub HardwareDatabase: Ptr,
    pub FastIoDispatch: Ptr,
    pub DriverInit: Ptr,
    pub DriverStartIo: Ptr,
    pub DriverUnload: Ptr,
    pub MajorFunction: [Ptr; 28],
}
impl EmuStruct for DRIVER_OBJECT {}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct DEVICE_OBJECT {
    pub Type: u16,
    pub Size: u16,
    pub ReferenceCount: u32,
    pub DriverObject: Ptr,
    pub NextDevice: Ptr,
    pub AttachedDevice: Ptr,
    pub CurrentIrp: Ptr,
    pub Timer: Ptr,
    pub Flags: u32,
    pub Characteristics: u32,
    pub Vpb: Ptr,
    pub DeviceExtension: Ptr,
    pub DeviceType: u32,
    pub StackSize: u8,
    pub Queue: LIST_ENTRY,
    pub AlignmentRequirement: u32,
    // Note: Nested structures might need proper implementation if their size is fixed
    pub DeviceQueue: [u8; 32], // Placeholder for KDEVICE_QUEUE
    pub Dpc: [u8; 64],         // Placeholder for KDPC
    pub ActiveThreadCount: u32,
    pub SecurityDescriptor: Ptr,
    pub DeviceLock: KEVENT,
    pub SectorSize: u16,
    pub Spare1: u16,
    pub DeviceObjectExtension: Ptr,
    pub Reserved: Ptr,
}
impl EmuStruct for DEVICE_OBJECT {}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct FILE_OBJECT {
    pub Type: u16,
    pub Size: u16,
    pub DeviceObject: Ptr,
    pub Vpb: Ptr,
    pub FsContext: Ptr,
    pub FsContext2: Ptr,
    pub SectionObjectPointer: Ptr,
    pub PrivateCacheMap: Ptr,
    pub FinalStatus: u32,
    pub RelatedFileObject: Ptr,
    pub LockOperation: u8,
    pub DeletePending: u8,
    pub ReadAccess: u8,
    pub WriteAccess: u8,
    pub DeleteAccess: u8,
    pub SharedRead: u8,
    pub SharedWrite: u8,
    pub SharedDelete: u8,
    pub Flags: u32,
    pub FileName: UNICODE_STRING,
    pub CurrentByteOffset: LARGE_INTEGER,
    pub Waiters: u32,
    pub Busy: u32,
    pub LastLock: Ptr,
    pub Lock: KEVENT,
    pub Event: KEVENT,
    pub CompletionContext: Ptr,
    pub IrpListLock: u32,
    pub IrpList: LIST_ENTRY,
    pub FileObjectExtension: Ptr,
}
impl EmuStruct for FILE_OBJECT {}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct IO_STATUS_BLOCK {
    pub Status: Ptr,
    pub Information: Ptr,
}
impl EmuStruct for IO_STATUS_BLOCK {}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct IRP {
    pub Type: u16,
    pub Size: u16,
    pub MdlAddress: Ptr,
    pub Flags: u32,
    pub AssociatedIrp: Ptr,
    pub ThreadListEntry: LIST_ENTRY,
    pub IoStatus: IO_STATUS_BLOCK,
    pub RequestorMode: u8,
    pub PendingReturned: u8,
    pub StackCount: u8,
    pub CurrentLocation: u8,
    pub Cancel: u8,
    pub CancelIrql: u8,
    pub ApcEnvironment: u8,
    pub AllocationFlags: u8,
    pub UserIosb: Ptr,
    pub UserEvent: Ptr,
    pub Overlay: [Ptr; 2], // Placeholder for IRP_OVERLAY
    pub CancelRoutine: Ptr,
    pub UserBuffer: Ptr,
    pub Tail: [u8; 64], // Placeholder for IRP_TAIL
}
impl EmuStruct for IRP {}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct NT_TIB {
    pub ExceptionList: Ptr,
    pub StackBase: Ptr,
    pub StackLimit: Ptr,
    pub Reserved1: Ptr,
    pub Reserved2: Ptr,
    pub Reserved3: Ptr,
    pub Self_: Ptr,
}
impl EmuStruct for NT_TIB {}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct TEB {
    pub NtTib: NT_TIB,
    pub EnvironmentPointer: Ptr,
    pub ClientId: CLIENT_ID,
    pub ActiveRpcHandle: Ptr,
    pub ThreadLocalStoragePointer: Ptr,
    pub ProcessEnvironmentBlock: Ptr,
    pub LastErrorValue: u32,
    pub CountOfOwnedCriticalSections: u32,
    pub CsrClientThread: Ptr,
    pub Win32ThreadInfo: Ptr,
    pub User32Reserved: [u32; 26],
    pub UserReserved: [u32; 5],
    pub WOW32Reserved: Ptr,
    pub CurrentLocale: u32,
}
impl EmuStruct for TEB {}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct PEB {
    pub InheritedAddressSpace: u8,
    pub ReadImageFileExecOptions: u8,
    pub BeingDebugged: u8,
    pub BitField: u8,
    pub Mutant: Ptr,
    pub ImageBaseAddress: Ptr,
    pub Ldr: Ptr,
    pub ProcessParameters: Ptr,
    pub SubSystemData: Ptr,
    pub ProcessHeap: Ptr,
    pub FastPebLock: Ptr,
    pub AtlThunkSListPtr: Ptr,
    pub IFEOKey: Ptr,
    pub CrossProcessFlags: Ptr,
    pub UserSharedInfoPtr: Ptr,
    pub SystemReserved: u32,
    pub AtlThunkSListPtr32: u32,
    pub ApiSetMap: Ptr,
    pub TlsExpansionCounter: Ptr,
    pub TlsBitmap: Ptr,
    pub TlsBitmapBits: [u32; 2],
    pub ReadOnlySharedMemoryBase: Ptr,
    pub SharedData: Ptr,
    pub ReadOnlyStaticServerData: Ptr,
    pub AnsiCodePageData: Ptr,
    pub OemCodePageData: Ptr,
    pub UnicodeCaseTableData: Ptr,
    pub NumberOfProcessors: u32,
    pub NtGlobalFlag: u32,
    pub CriticalSectionTimeout: i64,
    pub HeapSegmentReserve: Ptr,
    pub HeapSegmentCommit: Ptr,
    pub HeapDeCommitTotalFreeThreshold: Ptr,
    pub HeapDeCommitFreeBlockThreshold: Ptr,
    pub NumberOfHeaps: u32,
    pub MaximumNumberOfHeaps: u32,
    pub ProcessHeaps: Ptr,
    pub GdiSharedHandleTable: Ptr,
    pub ProcessStarterHelper: Ptr,
    pub GdiDCAttributeList: Ptr,
    pub LoaderLock: Ptr,
    pub OSMajorVersion: u32,
    pub OSMinorVersion: u32,
    pub OSBuildNumber: u16,
    pub OSCSDVersion: u16,
    pub OSPlatformId: u32,
    pub ImageSubsystem: u32,
    pub ImageSubsystemMajorVersion: u32,
    pub ImageSubsystemMinorVersion: Ptr,
    pub ActiveProcessAffinityMask: Ptr,
    pub GdiHandleBuffer: [u32; 60],
    pub PostProcessInitRoutine: Ptr,
    pub TlsExpansionBitmap: Ptr,
    pub TlsExpansionBitmapBits: [u32; 32],
    pub SessionId: Ptr,
    pub AppCompatFlags: u64,
    pub AppCompatFlagsUser: u64,
    pub pShimData: Ptr,
    pub AppCompatInfo: Ptr,
    pub CSDVersion: UNICODE_STRING,
    pub ActivationContextData: Ptr,
    pub ProcessAssemblyStorageMap: Ptr,
    pub SystemDefaultActivationContextData: Ptr,
    pub SystemAssemblyStorageMap: Ptr,
    pub MinimumStackCommit: Ptr,
    pub FlsCallback: Ptr,
    pub FlsListHead: LIST_ENTRY,
    pub FlsBitmap: Ptr,
    pub FlsBitmapBits: [u32; 4],
    pub FlsHighIndex: Ptr,
    pub WerRegistrationData: Ptr,
    pub WerShipAssertPtr: Ptr,
    pub pUnused: Ptr,
    pub pImageHeaderHash: Ptr,
    pub TracingFlags: u64,
    pub CsrServerReadOnlySharedMemoryBase: u64,
    pub TppWorkerpListLock: Ptr,
    pub TppWorkerpList: LIST_ENTRY,
    pub WaitOnAddressHashTable: [Ptr; 128],
}
impl EmuStruct for PEB {}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct PEB_LDR_DATA {
    pub Length: u32,
    pub Initialized: [u8; 4],
    pub SsHandle: Ptr,
    pub InLoadOrderModuleList: LIST_ENTRY,
    pub InMemoryOrderModuleList: LIST_ENTRY,
    pub InInitializationOrderModuleList: LIST_ENTRY,
    pub EntryInProgress: Ptr,
    pub ShutdownInProgress: u8,
    pub ShutdownThreadId: Ptr,
}
impl EmuStruct for PEB_LDR_DATA {}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct LDR_DATA_TABLE_ENTRY {
    pub InLoadOrderLinks: LIST_ENTRY,
    pub InMemoryOrderLinks: LIST_ENTRY,
    pub InInitializationOrderLinks: LIST_ENTRY,
    pub DllBase: Ptr,
    pub EntryPoint: Ptr,
    pub SizeOfImage: u32,
    pub FullDllName: UNICODE_STRING,
    pub BaseDllName: UNICODE_STRING,
    pub Flags: u32,
    pub LoadCount: u16,
}
impl EmuStruct for LDR_DATA_TABLE_ENTRY {}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct CURDIR {
    pub DosPath: UNICODE_STRING,
    pub Handle: Ptr,
}
impl EmuStruct for CURDIR {}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct RTL_USER_PROCESS_PARAMETERS {
    pub MaximumLength: u32,
    pub Length: u32,
    pub Flags: u32,
    pub DebugFlags: u32,
    pub ConsoleHandle: Ptr,
    pub ConsoleFlags: u32,
    pub StandardInput: Ptr,
    pub StandardOutput: Ptr,
    pub StandardError: Ptr,
    pub CurrentDirectory: CURDIR,
    pub DllPath: UNICODE_STRING,
    pub ImagePathName: UNICODE_STRING,
    pub CommandLine: UNICODE_STRING,
    pub Environment: Ptr,
    pub StartingX: u32,
    pub StartingY: u32,
    pub CountX: u32,
    pub CountY: u32,
    pub CountCharsX: u32,
    pub CountCharsY: u32,
    pub FillAttribute: u32,
    pub WindowFlags: u32,
    pub ShowWindowFlags: u32,
    pub WindowTitle: UNICODE_STRING,
    pub DesktopInfo: UNICODE_STRING,
    pub ShellInfo: UNICODE_STRING,
    pub RuntimeData: UNICODE_STRING,
}
impl EmuStruct for RTL_USER_PROCESS_PARAMETERS {}

pub type NtUnicodeString = UNICODE_STRING;
pub type NtKsystemTime = KSYSTEM_TIME;
