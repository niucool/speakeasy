use crate::r#struct::{EmuStruct, Ptr};

pub const WSADESCRIPTION_LEN: usize = 256;
pub const WSASYS_STATUS_LEN: usize = 128;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct WSAData {
    pub wVersion: u16,
    pub wHighVersion: u32,
    pub iMaxSockets: u32,
    pub iMaxUdpDg: u32,
    pub lpVendorInfo: u16,
    pub szDescription: [u8; WSADESCRIPTION_LEN + 1],
    pub szSystemStatus: [u8; WSASYS_STATUS_LEN + 1],
}
impl EmuStruct for WSAData {}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct sockaddr {
    pub sa_family: u16,
    pub sa_data: [u8; 14],
}
impl EmuStruct for sockaddr {}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct sockaddr_in {
    pub sin_family: u16,
    pub sin_port: u16,
    pub sin_addr: u32,
    pub sin_zero: [u8; 8],
}
impl EmuStruct for sockaddr_in {}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct hostent {
    pub h_name: Ptr,
    pub h_aliases: Ptr,
    pub h_addrtype: u16,
    pub h_length: u16,
    pub h_addr_list: Ptr,
}
impl EmuStruct for hostent {}
