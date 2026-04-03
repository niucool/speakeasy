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

pub const WSA_FLAG_OVERLAPPED: u32 = 1;
pub const WSA_FLAG_ACCESS_SYSTEM_SECURITY: u32 = 0x40;
pub const WSA_FLAG_NO_HANDLE_INHERIT: u32 = 0x80;

pub const HOST_NOT_FOUND: u32 = 11001;
pub const WSAENOTSOCK: u32 = 10038;

pub const MSG_PEEK: u32 = 0x2;

pub const AI_NUMERICHOST: u32 = 4;

pub const SOL_SOCKET: u32 = 0xFFFF;

pub const SO_SNDBUF: u32 = 0x1001;
pub const SO_RCVBUF: u32 = 0x1002;

pub const SOCK_BUF_SIZE: usize = 0x2000;
