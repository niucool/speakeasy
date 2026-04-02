use crate::r#struct::{EmuStruct, Ptr};

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct WSK_PROVIDER_BASIC_DISPATCH {
    pub WskControlSocket: Ptr,
    pub WskCloseSocket: Ptr,
}
impl EmuStruct for WSK_PROVIDER_BASIC_DISPATCH {}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct WSK_PROVIDER_DATAGRAM_DISPATCH {
    pub Basic: WSK_PROVIDER_BASIC_DISPATCH,
    pub WskBind: Ptr,
    pub WskSendTo: Ptr,
    pub WskReceiveFrom: Ptr,
    pub WskRelease: Ptr,
    pub WskGetLocalAddress: Ptr,
    pub WskSendMessages: Ptr,
}
impl EmuStruct for WSK_PROVIDER_DATAGRAM_DISPATCH {}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct WSK_CLIENT_DISPATCH {
    pub Version: u16,
    pub Reserved: u16,
    pub WskClientEvent: Ptr,
}
impl EmuStruct for WSK_CLIENT_DISPATCH {}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct WSK_CLIENT_NPI {
    pub ClientContext: Ptr,
    pub Dispatch: Ptr,
}
impl EmuStruct for WSK_CLIENT_NPI {}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct WSK_PROVIDER_DISPATCH {
    pub Version: u16,
    pub Reserved: u16,
    pub WskSocket: Ptr,
    pub WskSocketConnect: Ptr,
    pub WskControlClient: Ptr,
    pub WskGetAddressInfo: Ptr,
    pub WskFreeAddressInfo: Ptr,
    pub WskGetNameInfo: Ptr,
}
impl EmuStruct for WSK_PROVIDER_DISPATCH {}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct WSK_PROVIDER_NPI {
    pub Client: Ptr,
    pub Dispatch: Ptr,
}
impl EmuStruct for WSK_PROVIDER_NPI {}
