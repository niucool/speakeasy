use crate::r#struct::{EmuStruct, Ptr};

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct NDIS_OBJECT_HEADER {
    pub r#Type: u8,
    pub Revision: u8,
    pub Size: u16,
}
impl EmuStruct for NDIS_OBJECT_HEADER {}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct NDIS_GENERIC_OBJECT {
    pub Header: NDIS_OBJECT_HEADER,
    pub Caller: Ptr,
    pub CallersCaller: Ptr,
    pub DriverObject: Ptr,
}
impl EmuStruct for NDIS_GENERIC_OBJECT {}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct NET_BUFFER_LIST_POOL_PARAMETERS {
    pub Header: NDIS_OBJECT_HEADER,
    pub ProtocolId: u8,
    pub fAllocateNetBuffer: u8,
    pub ContextSize: u16,
    pub PoolTag: u32,
    pub DataSize: u32,
}
impl EmuStruct for NET_BUFFER_LIST_POOL_PARAMETERS {}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct NET_BUFFER_LIST {
    pub Next: Ptr,
    pub FirstNetBuffer: Ptr,
    pub Context: Ptr,
    pub ParentNetBufferList: Ptr,
    pub NdisPoolHandle: Ptr,
    pub NdisReserved: [Ptr; 2],
    pub ProtocolReserved: [Ptr; 4],
    pub MiniportReserved: [Ptr; 2],
    pub Scratch: Ptr,
    pub SourceHandle: Ptr,
    pub NblFlags: u32,
    pub ChildRefCount: u32,
    pub Flags: u32,
    pub NetBufferListInfo: [Ptr; 11],
}
impl EmuStruct for NET_BUFFER_LIST {}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct NET_BUFFER_DATA {
    pub Next: Ptr,
    pub CurrentMdl: Ptr,
    pub CurrentMdlOffset: u32,
    pub NbDataLength: u32,
    pub MdlChain: Ptr,
    pub DataOffset: u32,
}
impl EmuStruct for NET_BUFFER_DATA {}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct NET_BUFFER_HEADER {
    pub NetBufferData: NET_BUFFER_DATA,
    pub Link: Ptr,
}
impl EmuStruct for NET_BUFFER_HEADER {}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct NET_BUFFER {
    pub Link: Ptr,
    pub NetBufferHeader: NET_BUFFER_HEADER,
    pub ChecksumBias: Ptr,
    pub Reserved: Ptr,
    pub NdisPoolHandle: Ptr,
    pub NdisReserved: [Ptr; 2],
    pub ProtocolReserved: [Ptr; 6],
    pub MiniportReserved: [Ptr; 4],
    pub DataPhysicalAddress: u64,
    pub SharedMemoryInfo: Ptr,
}
impl EmuStruct for NET_BUFFER {}
