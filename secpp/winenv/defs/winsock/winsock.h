// winsock.h  Base Windows Sockets type definitions (constants)
//
// Maps to: speakeasy/winenv/defs/winsock/winsock.py
//
// Address families, socket types, protocol types, and common
// Winsock constants used by API handlers and network emulation.

#ifndef SPEAKEASY_DEFS_WINSOCK_H
#define SPEAKEASY_DEFS_WINSOCK_H

#include <cstdint>

namespace speakeasy { namespace defs { namespace winsock {

//  Address families 
constexpr uint32_t AF_UNSPEC    = 0;
constexpr uint32_t AF_INET      = 2;
constexpr uint32_t AF_IPX       = 6;
constexpr uint32_t AF_APPLETALK = 16;
constexpr uint32_t AF_NETBIOS   = 17;
constexpr uint32_t AF_INET6     = 23;
constexpr uint32_t AF_IRDA      = 26;
constexpr uint32_t AF_BTH       = 32;

//  Socket types 
constexpr uint32_t SOCK_STREAM    = 1;
constexpr uint32_t SOCK_DGRAM     = 2;
constexpr uint32_t SOCK_RAW       = 3;
constexpr uint32_t SOCK_RDM       = 4;
constexpr uint32_t SOCK_SEQPACKET = 5;

//  Protocol types 
constexpr uint32_t IPPROTO_ICMP   = 1;
constexpr uint32_t IPPROTO_IGMP   = 2;
constexpr uint32_t BTHPROTO_RFCOMM = 3;
constexpr uint32_t IPPROTO_TCP    = 6;
constexpr uint32_t IPPROTO_UDP    = 17;
constexpr uint32_t IPPROTO_ICMPV6 = 58;
constexpr uint32_t IPPROTO_RM     = 113;

//  WSA flags 
constexpr uint32_t WSA_FLAG_OVERLAPPED            = 0x1;
constexpr uint32_t WSA_FLAG_ACCESS_SYSTEM_SECURITY = 0x40;
constexpr uint32_t WSA_FLAG_NO_HANDLE_INHERIT      = 0x80;

//  Error / return codes 
constexpr uint32_t HOST_NOT_FOUND = 11001;
constexpr uint32_t WSAENOTSOCK    = 10038;

//  Message flags 
constexpr uint32_t MSG_PEEK = 0x2;

//  Address info flags 
constexpr uint32_t AI_NUMERICHOST = 4;

//  Socket options 
constexpr uint32_t SOL_SOCKET = 0xFFFF;
constexpr uint32_t SO_SNDBUF  = 0x1001;
constexpr uint32_t SO_RCVBUF  = 0x1002;

//  Internal buffer size 
constexpr uint32_t SOCK_BUF_SIZE = 0x2000;

// Note: SERVICE_PORTS (dict mapping service names to ports)
// from winsock.py is a Python runtime construct and is not
// translated to C++.

}}} // namespace speakeasy::defs::winsock

#endif // SPEAKEASY_DEFS_WINSOCK_H
