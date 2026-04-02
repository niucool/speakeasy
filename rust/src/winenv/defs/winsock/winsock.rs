pub const AF_UNSPEC: u32 = 0;
pub const AF_INET: u32 = 2;
pub const AF_IPX: u32 = 6;
pub const AF_APPLETALK: u32 = 16;
pub const AF_NETBIOS: u32 = 17;
pub const AF_INET6: u32 = 23;
pub const AF_IRDA: u32 = 26;
pub const AF_BTH: u32 = 32;

pub const SOCK_STREAM: u32 = 1;
pub const SOCK_DGRAM: u32 = 2;
pub const SOCK_RAW: u32 = 3;
pub const SOCK_RDM: u32 = 4;
pub const SOCK_SEQPACKET: u32 = 5;

pub const IPPROTO_ICMP: u32 = 1;
pub const IPPROTO_IGMP: u32 = 2;
pub const BTHPROTO_RFCOMM: u32 = 3;
pub const IPPROTO_TCP: u32 = 6;
pub const IPPROTO_UDP: u32 = 17;
pub const IPPROTO_ICMPV6: u32 = 58;
pub const IPPROTO_RM: u32 = 113;

pub fn get_addr_family(value: u32) -> Option<&'static str> {
    match value {
        AF_UNSPEC => Some("AF_UNSPEC"),
        AF_INET => Some("AF_INET"),
        AF_IPX => Some("AF_IPX"),
        AF_APPLETALK => Some("AF_APPLETALK"),
        AF_NETBIOS => Some("AF_NETBIOS"),
        AF_INET6 => Some("AF_INET6"),
        AF_IRDA => Some("AF_IRDA"),
        AF_BTH => Some("AF_BTH"),
        _ => None,
    }
}
