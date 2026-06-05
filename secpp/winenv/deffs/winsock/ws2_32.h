// ws2_32.h  Winsock 2 type definitions (new EmuStructHelper CRTP)
//
// Maps to: speakeasy/winenv/defs/winsock/ws2_32.py
//
// Uses the new EmuStructHelper CRTP approach for auto serialize/deserialize.
// All structs use #pragma pack(push, 1) with explicit padding fields to match
// the sizeof() that Python ctypes (natural C ABI alignment) would produce.

#ifndef SPEAKEASY_DEFS_NEW_WINSOCK_WS2_32_H
#define SPEAKEASY_DEFS_NEW_WINSOCK_WS2_32_H

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include "struct.h"

namespace speakeasy { namespace deffs { namespace winsock {

#pragma pack(push, 1)

// ==========================================================================================================
// Constants from ws2_32.py
// ==========================================================================================================
constexpr int kWSADescriptionLen = 256;
constexpr int kWSASysStatusLen   = 128;

// ==========================================================================================================
// WSAData: ptr-size polymorphic (pack(1) + explicit alignment padding)
//   Windows SDK layout (x86, natural alignment):
//   wVersion(2)+wHighVersion(2)+szDescription[257]+szSystemStatus[129]+
//   iMaxSockets(2)+iMaxUdpDg(2)+pad(2)+lpVendorInfo(Ptr=4) = 400
//   Windows SDK layout (x64, natural alignment):
//   wVersion(2)+wHighVersion(2)+szDescription[257]+szSystemStatus[129]+
//   iMaxSockets(2)+iMaxUdpDg(2)+pad(6)+lpVendorInfo(Ptr=8) = 408
// ==========================================================================================================
template <int PtrSize>
struct WSAData_POD;

template <>
struct WSAData_POD<4> {
    uint16_t wVersion;              // offset   0
    uint16_t wHighVersion;          // offset   2
    uint8_t  szDescription[257];    // offset   4
    uint8_t  szSystemStatus[129];   // offset 261
    uint16_t iMaxSockets;           // offset 390
    uint16_t iMaxUdpDg;             // offset 392
    uint16_t pad1;                  // offset 394 → align lpVendorInfo to 4
    uint32_t lpVendorInfo;          // offset 396 (Ptr=4 on x86)
    // total = 400
};

template <>
struct WSAData_POD<8> {
    uint16_t wVersion;              // offset   0
    uint16_t wHighVersion;          // offset   2
    uint8_t  szDescription[257];    // offset   4
    uint8_t  szSystemStatus[129];   // offset 261
    uint16_t iMaxSockets;           // offset 390
    uint16_t iMaxUdpDg;             // offset 392
    uint8_t  pad_alignment[6];      // offset 394 → align lpVendorInfo to 8
    uint64_t lpVendorInfo;          // offset 400 (Ptr=8 on x64)
    // total = 408
};

template <int PtrSize>
struct WSAData : public EmuStructHelper<WSAData<PtrSize>>, public WSAData_POD<PtrSize> {
    std::string get_mem_tag() const override { return "wsadata"; }
};

// ==========================================================================================================
// sockaddr: sa_family(u16) + sa_data(u8[14])
//   Natural: 2+14 = 16 → no padding needed (largest alignment is 2)
//   Packed: same = 16
// ==========================================================================================================
struct sockaddr_POD {
    uint16_t sa_family;       // offset 0
    uint8_t  sa_data[14];     // offset 2
    // total = 16
};

struct sockaddr : public EmuStructHelper<sockaddr>, public sockaddr_POD {
    std::string get_mem_tag() const override { return "sockaddr"; }
};

// ==========================================================================================================
// sockaddr_in:
//   sin_family(u16)+sin_port(u16)+sin_addr(u32)+sin_zero(u8[8])
//   Natural: 2+2+4+8 = 16 (all naturally aligned, no padding needed)
// ==========================================================================================================
struct sockaddr_in_POD {
    uint16_t sin_family;      // offset 0
    uint16_t sin_port;        // offset 2
    uint32_t sin_addr;        // offset 4
    uint8_t  sin_zero[8];     // offset 8
    // total = 16
};

struct sockaddr_in : public EmuStructHelper<sockaddr_in>, public sockaddr_in_POD {
    std::string get_mem_tag() const override { return "sockaddr_in"; }
};

// ==========================================================================================================
// hostent:
//   h_name(Ptr)+h_aliases(Ptr)+h_addrtype(u16)+h_length(u16)+h_addr_list(Ptr)
//   x86: 4+4+2+2+4 = 16
//   x64: 8+8+2+2+pad(4)+8 = 32
// ==========================================================================================================
template <int PtrSize>
struct hostent_POD;

template <>
struct hostent_POD<4> {
    uint32_t h_name;              // offset 0
    uint32_t h_aliases;           // offset 4
    uint16_t h_addrtype;          // offset 8
    uint16_t h_length;            // offset 10
    uint32_t h_addr_list;         // offset 12
    // total = 16
};

template <>
struct hostent_POD<8> {
    uint64_t h_name;              // offset 0
    uint64_t h_aliases;           // offset 8
    uint16_t h_addrtype;          // offset 16
    uint16_t h_length;            // offset 18
    uint32_t pad1;                // offset 20 → align h_addr_list to 8
    uint64_t h_addr_list;         // offset 24
    // total = 32
};

template <int PtrSize>
struct hostent : public EmuStructHelper<hostent<PtrSize>>,
                 public hostent_POD<PtrSize> {
    std::string get_mem_tag() const override { return "hostent"; }
};

// ==========================================================================================================
// addrinfo:
//   ai_flags(u32)+ai_family(u32)+ai_socktype(u32)+ai_protocol(u32)+
//   ai_addrlen(size_t/PtrSize)+ai_canonname(Ptr)+ai_addr(Ptr)+ai_next(Ptr)
//
//   x86: 4+4+4+4+4+4+4+4 = 32
//   x64: 4+4+4+4+8+8+8+8 = 48 (ai_addrlen is size_t, which is 8 on x64)
//   Wait, Python uses ct.c_uint for ai_addrlen. On Windows, uint is 4 bytes (unsigned int).
//   Let me check: ct.c_uint is typically typedef for unsigned int, which is 4 bytes even on x64 Windows.
//   Actually on Windows x64, unsigned int is still 32 bits (4 bytes) per MS ABI.
//   So: x64: 4+4+4+4+4+pad(4)+8+8+8 = 44?... Let me be careful.
//
//   Hmm, actually ctypes uses ct.c_uint which is typically unsigned int (4 bytes).
//   But in the task it says "Ptr" is used for pointer-sized fields. ai_addrlen is c_uint, which is 4 bytes.
//   On x64, after 4*u32(16), we have ai_addrlen(u32, 4)=20, then next Ptr needs 8-byte alignment.
//   20→pad(4)→24, then 3*Ptr(24)=48. Total = 48.
//   x86: 4*u32(16)+u32(4)+3*Ptr(12)=32. Total = 32.
// ==========================================================================================================
template <int PtrSize>
struct addrinfo_POD;

template <>
struct addrinfo_POD<4> {
    uint32_t ai_flags;        // offset  0
    uint32_t ai_family;       // offset  4
    uint32_t ai_socktype;     // offset  8
    uint32_t ai_protocol;     // offset 12
    uint32_t ai_addrlen;      // offset 16 (c_uint = 4 bytes)
    uint32_t ai_canonname;    // offset 20 (Ptr)
    uint32_t ai_addr;         // offset 24 (Ptr)
    uint32_t ai_next;         // offset 28 (Ptr)
    // total = 32
};

template <>
struct addrinfo_POD<8> {
    uint32_t ai_flags;        // offset  0
    uint32_t ai_family;       // offset  4
    uint32_t ai_socktype;     // offset  8
    uint32_t ai_protocol;     // offset 12
    uint32_t ai_addrlen;      // offset 16 (c_uint = 4 bytes)
    uint32_t pad1;            // offset 20 → align next Ptr to 8
    uint64_t ai_canonname;    // offset 24 (Ptr)
    uint64_t ai_addr;         // offset 32 (Ptr)
    uint64_t ai_next;         // offset 40 (Ptr)
    // total = 48
};

template <int PtrSize>
struct addrinfo : public EmuStructHelper<addrinfo<PtrSize>>,
                  public addrinfo_POD<PtrSize> {
    std::string get_mem_tag() const override { return "addrinfo"; }
};

#pragma pack(pop)

}}} // namespace speakeasy::deffs::winsock

#endif // SPEAKEASY_DEFS_NEW_WINSOCK_WS2_32_H
