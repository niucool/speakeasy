// iphlpapi.h  Windows IPHLPAPI type definitions (new EmuStructHelper CRTP)
//
// Maps to: speakeasy/winenv/defs/windows/iphlpapi.py
//
// Uses the new EmuStructHelper CRTP approach for auto serialize/deserialize.
// All structs use #pragma pack(push, 1).
//
// Namespace speakeasy::deffs::windows to avoid conflicts with existing defs.

#ifndef SPEAKEASY_DEFS_NEW_WINDOWS_IPHLPAPI_H
#define SPEAKEASY_DEFS_NEW_WINDOWS_IPHLPAPI_H

#include <cstdint>
#include <string>
#include "struct.h"

namespace speakeasy { namespace deffs { namespace windows {

#pragma pack(push, 1)

// ==========================================================================================================
// Constants
// ==========================================================================================================
constexpr int kMaxAdapterNameLength        = 256;
constexpr int kMaxAdapterDescriptionLength = 128;
constexpr int kMaxAdapterAddressLength     = 8;

constexpr int kMibIfTypeOther    = 1;
constexpr int kMibIfTypeEthernet = 6;
constexpr int kMibIfTypePpp      = 23;
constexpr int kMibIfTypeLoopback = 24;
constexpr int kMibIfTypeSlip     = 28;

constexpr int kIfTypeIso88025Tokenring = 9;
constexpr int kIfTypeIeee80211        = 71;

// ==========================================================================================================
// IP_ADDR_STRING: ptr-size polymorphic
// x86: Next(4) + IpAddress(16) + IpMask(16) + Context(4) = 40
// x64: Next(8) + IpAddress(16) + IpMask(16) + Context(4) + pad(4) = 48
// ==========================================================================================================
template <int PtrSize>
struct IP_ADDR_STRING_POD;

template <>
struct IP_ADDR_STRING_POD<4> {
    uint32_t  Next                      = 0;  // offset  0
    uint8_t   IpAddress[16]             = {}; // offset  4
    uint8_t   IpMask[16]                = {}; // offset 20
    uint32_t  Context                   = 0;  // offset 36
    // total = 40
};

template <>
struct IP_ADDR_STRING_POD<8> {
    uint64_t  Next                      = 0;  // offset  0
    uint8_t   IpAddress[16]             = {}; // offset  8
    uint8_t   IpMask[16]                = {}; // offset 24
    uint32_t  Context                   = 0;  // offset 40
    uint32_t  pad1                      = 0;  // offset 44 → round to 48
    // total = 48
};

template <int PtrSize>
struct IP_ADDR_STRING : public EmuStructHelper<IP_ADDR_STRING<PtrSize>>, public IP_ADDR_STRING_POD<PtrSize> {
    std::string get_mem_tag() const override { return "ip_addr_string"; }
};

// ==========================================================================================================
// IP_ADAPTER_INFO: ptr-size polymorphic (contains embedded IP_ADDR_STRING fields)
//
// x86 layout (640 bytes):
//    0: Next(4)
//    4: ComboIndex(4)
//    8: AdapterName[260]
//  268: Description[132]
//  400: AddressLength(4)
//  404: Address[8]
//  412: Index(4)
//  416: Type(4)
//  420: DhcpEnabled(1)
//  421: pad1[3] → align CurrentIpAddress to 4
//  424: CurrentIpAddress(4)
//  428: IpAddressList(IP_ADDR_STRING<4>) 40 bytes: Next(4)+IpAddress[16]+IpMask[16]+Context(4)
//  468: GatewayList(40)
//  508: DhcpServer(40)
//  548: HaveWins(4)
//  552: PrimaryWinsServer(40)
//  592: SecondaryWinsServer(40)
//  632: LeaseObtained(4)
//  636: LeaseExpires(4)
//  total = 640
//
// x64 layout (704 bytes):
//    0: Next(8)
//    8: ComboIndex(4)
//   12: AdapterName[260]
//  272: Description[132]
//  404: AddressLength(4)
//  408: Address[8]
//  416: Index(4)
//  420: Type(4)
//  424: DhcpEnabled(1)
//  425: pad1[7] → align CurrentIpAddress to 8
//  432: CurrentIpAddress(8)
//  440: IpAddressList(IP_ADDR_STRING<8>) 48 bytes: Next(8)+IpAddress[16]+IpMask[16]+Context(4)+pad(4)
//  488: GatewayList(48)
//  536: DhcpServer(48)
//  584: HaveWins(4)
//  588: pad2[4] → align PrimaryWinsServer.Next to 8
//  592: PrimaryWinsServer(48)
//  640: SecondaryWinsServer(48)
//  688: LeaseObtained(8)
//  696: LeaseExpires(8)
//  total = 704
// ==========================================================================================================
template <int PtrSize>
struct IP_ADAPTER_INFO_POD;

template <>
struct IP_ADAPTER_INFO_POD<4> {
    uint32_t  Next                                  = 0;  // offset   0
    uint32_t  ComboIndex                            = 0;  // offset   4
    uint8_t   AdapterName[260]                      = {}; // offset   8
    uint8_t   Description[132]                      = {}; // offset 268
    uint32_t  AddressLength                         = 0;  // offset 400
    uint8_t   Address[8]                            = {}; // offset 404
    uint32_t  Index                                 = 0;  // offset 412
    uint32_t  Type                                  = 0;  // offset 416
    uint8_t   DhcpEnabled                           = 0;  // offset 420
    uint8_t   pad1[3]                               = {}; // offset 421 → align CurrentIpAddress
    uint32_t  CurrentIpAddress                      = 0;  // offset 424
    // IpAddressList (IP_ADDR_STRING<4> = 40 bytes) — flattened
    IP_ADDR_STRING_POD<4> IpAddressList;               // offset 428 (nested, size=40)
    IP_ADDR_STRING_POD<4> GatewayList;                 // offset 468 (nested, size=40)
    IP_ADDR_STRING_POD<4> DhcpServer;                  // offset 508 (nested, size=40)
    uint32_t  HaveWins                              = 0;  // offset 548
    IP_ADDR_STRING_POD<4> PrimaryWinsServer;            // offset 552 (nested, size=40)
    IP_ADDR_STRING_POD<4> SecondaryWinsServer;          // offset 592 (nested, size=40)
    uint32_t  LeaseObtained                         = 0;  // offset 632
    uint32_t  LeaseExpires                          = 0;  // offset 636
    // total = 640
};

template <>
struct IP_ADAPTER_INFO_POD<8> {
    uint64_t  Next                                  = 0;  // offset   0
    uint32_t  ComboIndex                            = 0;  // offset   8
    uint8_t   AdapterName[260]                      = {}; // offset  12
    uint8_t   Description[132]                      = {}; // offset 272
    uint32_t  AddressLength                         = 0;  // offset 404
    uint8_t   Address[8]                            = {}; // offset 408
    uint32_t  Index                                 = 0;  // offset 416
    uint32_t  Type                                  = 0;  // offset 420
    uint8_t   DhcpEnabled                           = 0;  // offset 424
    uint8_t   pad1[7]                               = {}; // offset 425 → align CurrentIpAddress to 432
    uint64_t  CurrentIpAddress                      = 0;  // offset 432
    // IpAddressList (IP_ADDR_STRING<8> = 48 bytes) — flattened
    IP_ADDR_STRING_POD<8> IpAddressList;    uint32_t  IpAddressList_pad                     = 0;  // offset 484
    // GatewayList (48 bytes)
    uint64_t  GatewayList_Next                      = 0;  // offset 488
    uint8_t   GatewayList_IpAddress[16]             = {}; // offset 496
    uint8_t   GatewayList_IpMask[16]                = {}; // offset 512
    uint32_t  GatewayList_Context                   = 0;  // offset 528
    uint32_t  GatewayList_pad                       = 0;  // offset 532
    // DhcpServer (48 bytes)
    uint64_t  DhcpServer_Next                       = 0;  // offset 536
    uint8_t   DhcpServer_IpAddress[16]              = {}; // offset 544
    uint8_t   DhcpServer_IpMask[16]                 = {}; // offset 560
    uint32_t  DhcpServer_Context                    = 0;  // offset 576
    uint32_t  DhcpServer_pad                        = 0;  // offset 580
    uint32_t  HaveWins                              = 0;  // offset 584
    uint32_t  pad2                                  = 0;  // offset 588 → align PrimaryWinsServer.Next
    // PrimaryWinsServer (48 bytes)
    uint64_t  PrimaryWinsServer_Next                = 0;  // offset 592
    uint8_t   PrimaryWinsServer_IpAddress[16]       = {}; // offset 600
    uint8_t   PrimaryWinsServer_IpMask[16]          = {}; // offset 616
    uint32_t  PrimaryWinsServer_Context             = 0;  // offset 632
    uint32_t  PrimaryWinsServer_pad                 = 0;  // offset 636
    // SecondaryWinsServer (48 bytes)
    uint64_t  SecondaryWinsServer_Next              = 0;  // offset 640
    uint8_t   SecondaryWinsServer_IpAddress[16]     = {}; // offset 648
    uint8_t   SecondaryWinsServer_IpMask[16]        = {}; // offset 664
    uint32_t  SecondaryWinsServer_Context           = 0;  // offset 680
    uint32_t  SecondaryWinsServer_pad               = 0;  // offset 684
    uint64_t  LeaseObtained                         = 0;  // offset 688
    uint64_t  LeaseExpires                          = 0;  // offset 696
    // total = 704
};

template <int PtrSize>
struct IP_ADAPTER_INFO : public EmuStructHelper<IP_ADAPTER_INFO<PtrSize>>, public IP_ADAPTER_INFO_POD<PtrSize> {
    std::string get_mem_tag() const override { return "ip_adapter_info"; }
};

#pragma pack(pop)

}}} // namespace speakeasy::deffs::windows

#endif // SPEAKEASY_DEFS_NEW_WINDOWS_IPHLPAPI_H
