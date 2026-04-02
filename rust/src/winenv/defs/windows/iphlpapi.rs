use crate::r#struct::{EmuStruct, Ptr};

pub const MAX_ADAPTER_NAME_LENGTH: usize = 256;
pub const MAX_ADAPTER_DESCRIPTION_LENGTH: usize = 128;
pub const MAX_ADAPTER_ADDRESS_LENGTH: usize = 8;

pub const MIB_IF_TYPE_ETHERNET: u32 = 6;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct IP_ADDR_STRING {
    pub Next: Ptr,
    pub IpAddress: [u8; 16],
    pub IpMask: [u8; 16],
    pub Context: u32,
}
impl EmuStruct for IP_ADDR_STRING {}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct IP_ADAPTER_INFO {
    pub Next: Ptr,
    pub ComboIndex: u32,
    pub AdapterName: [u8; MAX_ADAPTER_NAME_LENGTH + 4],
    pub Description: [u8; MAX_ADAPTER_DESCRIPTION_LENGTH + 4],
    pub AddressLength: u32,
    pub Address: [u8; MAX_ADAPTER_ADDRESS_LENGTH],
    pub Index: u32,
    pub Type: u32,
    pub DhcpEnabled: bool,
    pub CurrentIpAddress: Ptr,
    pub IpAddressList: IP_ADDR_STRING,
    pub GatewayList: IP_ADDR_STRING,
    pub DhcpServer: IP_ADDR_STRING,
    pub HaveWins: u32,
    pub PrimaryWinsServer: IP_ADDR_STRING,
    pub SecondaryWinsServer: IP_ADDR_STRING,
    pub LeaseObtained: Ptr,
    pub LeaseExpires: Ptr,
}
impl EmuStruct for IP_ADAPTER_INFO {}
