// iphlpapi.h — IP Helper API type definitions
//
// Maps to: speakeasy/winenv/defs/windows/iphlpapi.py
//
// Network adapter and IP address structures used by iphlpapi API handlers.

#ifndef SPEAKEASY_DEFS_WINDOWS_IPHLPAPI_H
#define SPEAKEASY_DEFS_WINDOWS_IPHLPAPI_H

#include <cstdint>
#include <cstring>
#include <vector>
#include "windef.h"
#include "../../../struct.h"

namespace speakeasy { namespace defs { namespace windows {

// ── Constants ──────────────────────────────────────────────────

constexpr uint32_t MAX_ADAPTER_NAME_LENGTH        = 256;
constexpr uint32_t MAX_ADAPTER_DESCRIPTION_LENGTH = 128;
constexpr uint32_t MAX_ADAPTER_ADDRESS_LENGTH     = 8;

// MIB interface types
constexpr uint32_t MIB_IF_TYPE_OTHER     = 1;
constexpr uint32_t MIB_IF_TYPE_ETHERNET  = 6;
constexpr uint32_t MIB_IF_TYPE_PPP       = 23;
constexpr uint32_t MIB_IF_TYPE_LOOPBACK  = 24;
constexpr uint32_t MIB_IF_TYPE_SLIP      = 28;

// Extended interface types
constexpr uint32_t IF_TYPE_ISO88025_TOKENRING = 9;
constexpr uint32_t IF_TYPE_IEEE80211          = 71;

// ── IP_ADDR_STRING ─────────────────────────────────────────────

struct IP_ADDR_STRING : speakeasy::EmuStruct {
    uint64_t Next       = 0;  // struct _IP_ADDR_STRING*
    uint8_t  IpAddress[16] = {};  // char[16] (dotted-decimal string, e.g. "192.168.1.1")
    uint8_t  IpMask[16]    = {};  // char[16] (subnet mask)
    uint32_t Context    = 0;

    size_t sizeof_obj() const override {
        return (sizeof(uint64_t) == 8) ? 44 : 40;
    }
    std::vector<uint8_t> get_bytes() const override {
        size_t sz = sizeof_obj();
        std::vector<uint8_t> b(sz, 0);
        if (sz == 44) {
            speakeasy::write_le(b, 0,  Next, 8);
            for (size_t i = 0; i < 16; ++i)
                b[8 + i] = IpAddress[i];
            for (size_t i = 0; i < 16; ++i)
                b[24 + i] = IpMask[i];
            speakeasy::write_le(b, 40, Context, 4);
        } else {
            speakeasy::write_le(b, 0,  Next, 4);
            for (size_t i = 0; i < 16; ++i)
                b[4 + i] = IpAddress[i];
            for (size_t i = 0; i < 16; ++i)
                b[20 + i] = IpMask[i];
            speakeasy::write_le(b, 36, Context, 4);
        }
        return b;
    }
};

// ── IP_ADAPTER_INFO ────────────────────────────────────────────

struct IP_ADAPTER_INFO : speakeasy::EmuStruct {
    uint64_t Next                      = 0;  // struct _IP_ADAPTER_INFO*
    uint32_t ComboIndex                = 0;
    uint8_t  AdapterName[260]          = {};  // char[MAX_ADAPTER_NAME_LENGTH + 4]
    uint8_t  Description[132]          = {};  // char[MAX_ADAPTER_DESCRIPTION_LENGTH + 4]
    uint32_t AddressLength             = 0;
    uint8_t  Address[8]                = {};  // BYTE[MAX_ADAPTER_ADDRESS_LENGTH]
    uint32_t Index                     = 0;
    uint32_t Type                      = 0;
    uint32_t DhcpEnabled               = 0;  // BOOL (uint32_t for alignment)
    uint64_t CurrentIpAddress          = 0;  // IP_ADDR_STRING*
    IP_ADDR_STRING IpAddressList;
    IP_ADDR_STRING GatewayList;
    IP_ADDR_STRING DhcpServer;
    uint32_t HaveWins                  = 0;
    IP_ADDR_STRING PrimaryWinsServer;
    IP_ADDR_STRING SecondaryWinsServer;
    int64_t  LeaseObtained             = 0;  // time_t
    int64_t  LeaseExpires              = 0;  // time_t

    size_t sizeof_obj() const override {
        // Size calculation (x64): 8 + 4 + 260 + 132 + 4 + 8 + 4 + 4 + 4 + 4(pad) + 8
        //   + 44*5 + 4 + 8 + 8 = 640
        // x86: 4 + 4 + 260 + 132 + 4 + 8 + 4 + 4 + 4 + 4 + 40*5 + 4 + 4 + 4 = 636
        return (sizeof(uint64_t) == 8) ? 648 : 636;
    }
    std::vector<uint8_t> get_bytes() const override {
        size_t sz = sizeof_obj();
        std::vector<uint8_t> b(sz, 0);
        size_t p = (sizeof(uint64_t) == 8) ? 8 : 4;
        size_t off = 0;

        speakeasy::write_le(b, off, Next, p); off += p;
        speakeasy::write_le(b, off, ComboIndex, 4); off += 4;
        for (size_t i = 0; i < 260; ++i) b[off + i] = AdapterName[i]; off += 260;
        for (size_t i = 0; i < 132; ++i) b[off + i] = Description[i]; off += 132;
        speakeasy::write_le(b, off, AddressLength, 4); off += 4;
        for (size_t i = 0; i < 8; ++i) b[off + i] = Address[i]; off += 8;
        speakeasy::write_le(b, off, Index, 4); off += 4;
        speakeasy::write_le(b, off, Type, 4); off += 4;
        speakeasy::write_le(b, off, DhcpEnabled, 4); off += 4;
        if (p == 8) off += 4;  // padding
        speakeasy::write_le(b, off, CurrentIpAddress, p); off += p;

        auto ipl = IpAddressList.get_bytes();
        std::copy(ipl.begin(), ipl.end(), b.begin() + off); off += ipl.size();
        auto gl = GatewayList.get_bytes();
        std::copy(gl.begin(), gl.end(), b.begin() + off); off += gl.size();
        auto ds = DhcpServer.get_bytes();
        std::copy(ds.begin(), ds.end(), b.begin() + off); off += ds.size();

        speakeasy::write_le(b, off, HaveWins, 4); off += 4;

        auto pws = PrimaryWinsServer.get_bytes();
        std::copy(pws.begin(), pws.end(), b.begin() + off); off += pws.size();
        auto sws = SecondaryWinsServer.get_bytes();
        std::copy(sws.begin(), sws.end(), b.begin() + off); off += sws.size();

        speakeasy::write_le(b, off, static_cast<uint64_t>(LeaseObtained), p); off += p;
        speakeasy::write_le(b, off, static_cast<uint64_t>(LeaseExpires), p); off += p;

        return b;
    }
};

}}} // namespaces

#endif // SPEAKEASY_DEFS_WINDOWS_IPHLPAPI_H
