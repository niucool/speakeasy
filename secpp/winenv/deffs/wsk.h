// wsk.h  Winsock Kernel type definitions (new EmuStructHelper CRTP)
//
// Maps to: speakeasy/winenv/defs/wsk.py
//
// Uses the new EmuStructHelper CRTP approach for auto serialize/deserialize.
// All structs use #pragma pack(push, 1) with explicit padding fields to match
// the sizeof() that Python ctypes (natural C ABI alignment) would produce.

#ifndef SPEAKEASY_DEFS_NEW_WSK_H
#define SPEAKEASY_DEFS_NEW_WSK_H

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include "struct.h"

namespace speakeasy { namespace deffs {

#pragma pack(push, 1)

// ==========================================================================================================
// WSK_PROVIDER_BASIC_DISPATCH: WskControlSocket(Ptr)+WskCloseSocket(Ptr)
//   x86: 4+4 = 8
//   x64: 8+8 = 16
// ==========================================================================================================
template <int PtrSize>
struct WSK_PROVIDER_BASIC_DISPATCH_POD;

template <>
struct WSK_PROVIDER_BASIC_DISPATCH_POD<4> {
    uint32_t WskControlSocket;   // offset 0
    uint32_t WskCloseSocket;     // offset 4
    // total = 8
};

template <>
struct WSK_PROVIDER_BASIC_DISPATCH_POD<8> {
    uint64_t WskControlSocket;   // offset 0
    uint64_t WskCloseSocket;     // offset 8
    // total = 16
};

template <int PtrSize>
struct WSK_PROVIDER_BASIC_DISPATCH
    : public EmuStructHelper<WSK_PROVIDER_BASIC_DISPATCH<PtrSize>>,
      public WSK_PROVIDER_BASIC_DISPATCH_POD<PtrSize> {
    std::string get_mem_tag() const override { return "wsk_provider_basic_dispatch"; }
};

// ==========================================================================================================
// WSK_PROVIDER_DATAGRAM_DISPATCH:
//   Basic(WSK_PROVIDER_BASIC_DISPATCH)+WskBind(Ptr)+WskSendTo(Ptr)+
//   WskReceiveFrom(Ptr)+WskRelease(Ptr)+WskGetLocalAddress(Ptr)+WskSendMessages(Ptr)
//   x86: 8+5*4 = 28
//   x64: 16+5*8 = 56
// ==========================================================================================================
template <int PtrSize>
struct WSK_PROVIDER_DATAGRAM_DISPATCH_POD;

template <>
struct WSK_PROVIDER_DATAGRAM_DISPATCH_POD<4> {
    WSK_PROVIDER_BASIC_DISPATCH_POD<4> Basic;         // offset  0 (8)
    uint32_t WskBind;                                  // offset  8
    uint32_t WskSendTo;                                // offset 12
    uint32_t WskReceiveFrom;                           // offset 16
    uint32_t WskRelease;                               // offset 20
    uint32_t WskGetLocalAddress;                       // offset 24
    uint32_t WskSendMessages;                          // offset 28
    // total = 32
};

template <>
struct WSK_PROVIDER_DATAGRAM_DISPATCH_POD<8> {
    WSK_PROVIDER_BASIC_DISPATCH_POD<8> Basic;         // offset  0 (16)
    uint64_t WskBind;                                  // offset 16
    uint64_t WskSendTo;                                // offset 24
    uint64_t WskReceiveFrom;                           // offset 32
    uint64_t WskRelease;                               // offset 40
    uint64_t WskGetLocalAddress;                       // offset 48
    uint64_t WskSendMessages;                          // offset 56
    // total = 64
};

template <int PtrSize>
struct WSK_PROVIDER_DATAGRAM_DISPATCH
    : public EmuStructHelper<WSK_PROVIDER_DATAGRAM_DISPATCH<PtrSize>>,
      public WSK_PROVIDER_DATAGRAM_DISPATCH_POD<PtrSize> {
    std::string get_mem_tag() const override { return "wsk_provider_datagram_dispatch"; }
};

// ==========================================================================================================
// WSK_CLIENT_DISPATCH: Version(u16)+Reserved(u16)+WskClientEvent(Ptr)
//   x86: 2+2+4 = 8
//   x64: 2+2+pad(4)+8 = 16
// ==========================================================================================================
template <int PtrSize>
struct WSK_CLIENT_DISPATCH_POD;

template <>
struct WSK_CLIENT_DISPATCH_POD<4> {
    uint16_t Version;            // offset 0
    uint16_t Reserved;           // offset 2
    uint32_t WskClientEvent;     // offset 4 (Ptr)
    // total = 8
};

template <>
struct WSK_CLIENT_DISPATCH_POD<8> {
    uint16_t Version;            // offset 0
    uint16_t Reserved;           // offset 2
    uint32_t pad;                // offset 4
    uint64_t WskClientEvent;     // offset 8
    // total = 16
};

template <int PtrSize>
struct WSK_CLIENT_DISPATCH : public EmuStructHelper<WSK_CLIENT_DISPATCH<PtrSize>>,
                             public WSK_CLIENT_DISPATCH_POD<PtrSize> {
    std::string get_mem_tag() const override { return "wsk_client_dispatch"; }
};

// ==========================================================================================================
// WSK_CLIENT_NPI: ClientContext(Ptr)+Dispatch(Ptr)
//   x86: 4+4 = 8
//   x64: 8+8 = 16
// ==========================================================================================================
template <int PtrSize>
struct WSK_CLIENT_NPI_POD;

template <>
struct WSK_CLIENT_NPI_POD<4> {
    uint32_t ClientContext;    // offset 0
    uint32_t Dispatch;         // offset 4
    // total = 8
};

template <>
struct WSK_CLIENT_NPI_POD<8> {
    uint64_t ClientContext;    // offset 0
    uint64_t Dispatch;         // offset 8
    // total = 16
};

template <int PtrSize>
struct WSK_CLIENT_NPI : public EmuStructHelper<WSK_CLIENT_NPI<PtrSize>>,
                        public WSK_CLIENT_NPI_POD<PtrSize> {
    std::string get_mem_tag() const override { return "wsk_client_npi"; }
};

// ==========================================================================================================
// WSK_PROVIDER_DISPATCH:
//   Version(u16)+Reserved(u16)+WskSocket(Ptr)+WskSocketConnect(Ptr)+
//   WskControlClient(Ptr)+WskGetAddressInfo(Ptr)+WskFreeAddressInfo(Ptr)+WskGetNameInfo(Ptr)
//   x86: 2+2+6*4 = 28
//   x64: 2+2+pad(4)+6*8 = 56... wait 2+2+4=8, then 6*8=48, total=56... hmm that's 56
//   Actually: 2+2=4, pad(4)=8, then 6*Ptr(48)=56
//   x86: 2+2+6*4=28
// ==========================================================================================================
template <int PtrSize>
struct WSK_PROVIDER_DISPATCH_POD;

template <>
struct WSK_PROVIDER_DISPATCH_POD<4> {
    uint16_t Version;              // offset  0
    uint16_t Reserved;             // offset  2
    uint32_t WskSocket;            // offset  4
    uint32_t WskSocketConnect;     // offset  8
    uint32_t WskControlClient;     // offset 12
    uint32_t WskGetAddressInfo;    // offset 16
    uint32_t WskFreeAddressInfo;   // offset 20
    uint32_t WskGetNameInfo;       // offset 24
    // total = 28
};

template <>
struct WSK_PROVIDER_DISPATCH_POD<8> {
    uint16_t Version;              // offset  0
    uint16_t Reserved;             // offset  2
    uint32_t pad;                  // offset  4
    uint64_t WskSocket;            // offset  8
    uint64_t WskSocketConnect;     // offset 16
    uint64_t WskControlClient;     // offset 24
    uint64_t WskGetAddressInfo;    // offset 32
    uint64_t WskFreeAddressInfo;   // offset 40
    uint64_t WskGetNameInfo;       // offset 48
    // total = 56
};

template <int PtrSize>
struct WSK_PROVIDER_DISPATCH : public EmuStructHelper<WSK_PROVIDER_DISPATCH<PtrSize>>,
                               public WSK_PROVIDER_DISPATCH_POD<PtrSize> {
    std::string get_mem_tag() const override { return "wsk_provider_dispatch"; }
};

// ==========================================================================================================
// WSK_PROVIDER_NPI: Client(Ptr)+Dispatch(Ptr)
//   x86: 4+4 = 8
//   x64: 8+8 = 16
// ==========================================================================================================
template <int PtrSize>
struct WSK_PROVIDER_NPI_POD;

template <>
struct WSK_PROVIDER_NPI_POD<4> {
    uint32_t Client;     // offset 0
    uint32_t Dispatch;   // offset 4
    // total = 8
};

template <>
struct WSK_PROVIDER_NPI_POD<8> {
    uint64_t Client;     // offset 0
    uint64_t Dispatch;   // offset 8
    // total = 16
};

template <int PtrSize>
struct WSK_PROVIDER_NPI : public EmuStructHelper<WSK_PROVIDER_NPI<PtrSize>>,
                          public WSK_PROVIDER_NPI_POD<PtrSize> {
    std::string get_mem_tag() const override { return "wsk_provider_npi"; }
};

#pragma pack(pop)

} // namespace deffs
} // namespace speakeasy

#endif // SPEAKEASY_DEFS_NEW_WSK_H
