// winsock.h  Winsock constant definitions (new EmuStructHelper CRTP)
//
// Maps to: speakeasy/winenv/defs/winsock/winsock.py
//
// Provides constant definitions for Winsock address families, socket types,
// protocol types, and flags.

#ifndef SPEAKEASY_DEFS_NEW_WINSOCK_WINSOCK_H
#define SPEAKEASY_DEFS_NEW_WINSOCK_WINSOCK_H

#include <cstdint>
#include <string>
#include <unordered_map>

namespace speakeasy { namespace defs { namespace new_structs {

// ==========================================================================================================
// Address families
// ==========================================================================================================
constexpr int kAfUnspec    = 0;
constexpr int kAfInet      = 2;
constexpr int kAfIpx       = 6;
constexpr int kAfAppletalk = 16;
constexpr int kAfNetbios   = 17;
constexpr int kAfInet6     = 23;
constexpr int kAfIrda      = 26;
constexpr int kAfBth       = 32;

// ==========================================================================================================
// Socket types
// ==========================================================================================================
constexpr int kSockStream    = 1;
constexpr int kSockDgram     = 2;
constexpr int kSockRaw       = 3;
constexpr int kSockRdm       = 4;
constexpr int kSockSeqpacket = 5;

// ==========================================================================================================
// Protocol types
// ==========================================================================================================
constexpr int kIpprotoIcmp   = 1;
constexpr int kIpprotoIgmp   = 2;
constexpr int kBthprotoRfcomm = 3;
constexpr int kIpprotoTcp    = 6;
constexpr int kIpprotoUdp    = 17;
constexpr int kIpprotoIcmpv6 = 58;
constexpr int kIpprotoRm     = 113;

// ==========================================================================================================
// Flags & constants
// ==========================================================================================================
constexpr int kWsaFlagOverlapped             = 1;
constexpr int kWsaFlagAccessSystemSecurity   = 0x40;
constexpr int kWsaFlagNoHandleInherit        = 0x80;

constexpr int kHostNotFound   = 11001;
constexpr int kWsaenotsock    = 10038;

constexpr int kMsgPeek        = 0x2;

constexpr int kAiNumerichost  = 4;

constexpr int kSolSocket      = 0xFFFF;
constexpr int kSoSndbuf       = 0x1001;
constexpr int kSoRcvbuf       = 0x1002;
constexpr int kSockBufSize    = 0x2000;

// ==========================================================================================================
// Helper: get string name for address family
// ==========================================================================================================
inline std::string get_addr_family_name(int define) {
    switch (define) {
        case 0:  return "AF_UNSPEC";
        case 2:  return "AF_INET";
        case 6:  return "AF_IPX";
        case 16: return "AF_APPLETALK";
        case 17: return "AF_NETBIOS";
        case 23: return "AF_INET6";
        case 26: return "AF_IRDA";
        case 32: return "AF_BTH";
        default: return "";
    }
}

// ==========================================================================================================
// Helper: get string name for socket type
// ==========================================================================================================
inline std::string get_sock_type_name(int define) {
    switch (define) {
        case 1: return "SOCK_STREAM";
        case 2: return "SOCK_DGRAM";
        case 3: return "SOCK_RAW";
        case 4: return "SOCK_RDM";
        case 5: return "SOCK_SEQPACKET";
        default: return "";
    }
}

// ==========================================================================================================
// Helper: get string name for protocol type
// ==========================================================================================================
inline std::string get_proto_type_name(int define) {
    switch (define) {
        case 1:  return "IPPROTO_ICMP";
        case 2:  return "IPPROTO_IGMP";
        case 3:  return "BTHPROTO_RFCOMM";
        case 6:  return "IPPROTO_TCP";
        case 17: return "IPPROTO_UDP";
        case 58: return "IPPROTO_ICMPV6";
        case 113:return "IPPROTO_RM";
        default: return "";
    }
}

// ==========================================================================================================
// Service ports mapping
// ==========================================================================================================
inline int get_service_port(const std::string& service) {
    static const std::unordered_map<std::string, int> kServicePorts = {
        {"ftp", 21}, {"ssh", 22}, {"smtp", 25},
        {"http", 80}, {"https", 443}
    };
    auto it = kServicePorts.find(service);
    if (it != kServicePorts.end()) return it->second;
    return 0;
}

}}} // namespace speakeasy::defs::new_structs

#endif // SPEAKEASY_DEFS_NEW_WINSOCK_WINSOCK_H
