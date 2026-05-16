// spea_ws2_32.h — Windows Sockets 2 (ws2_32) type definitions
//
// Maps to: speakeasy/winenv/defs/winsock/ws2_32.py
//
// Winsock structures used by API handlers and network emulation:
// WSAData, sockaddr, sockaddr_in, hostent, addrinfo

#ifndef SPEAKEASY_DEFS_WINSOCK_SPEA_WS2_32_H
#define SPEAKEASY_DEFS_WINSOCK_SPEA_WS2_32_H

#include <cstdint>
#include <vector>
#include "../../../struct.h"

namespace speakeasy { namespace defs { namespace winsock {

// ── Constants ─────────────────────────────────────────────────

constexpr size_t WSADESCRIPTION_LEN = 256;
constexpr size_t WSASYS_STATUS_LEN  = 128;

// ── WSAData ──────────────────────────────────────────────────

struct WSAData : speakeasy::EmuStruct {
    uint16_t wVersion         = 0;
    uint32_t wHighVersion     = 0;
    uint32_t iMaxSockets      = 0;
    uint32_t iMaxUdpDg        = 0;
    uint16_t lpVendorInfo     = 0;
    uint8_t  szDescription[WSADESCRIPTION_LEN + 1]{};
    uint8_t  szSystemStatus[WSASYS_STATUS_LEN + 1]{};

    size_t sizeof_obj() const override { return 404; }
    std::vector<uint8_t> get_bytes() const override {
        std::vector<uint8_t> b(404);
        speakeasy::write_le(b, 0,  wVersion,     2);
        speakeasy::write_le(b, 4,  wHighVersion, 4);
        speakeasy::write_le(b, 8,  iMaxSockets,  4);
        speakeasy::write_le(b, 12, iMaxUdpDg,    4);
        speakeasy::write_le(b, 16, lpVendorInfo, 2);
        for (size_t i = 0; i < WSADESCRIPTION_LEN + 1; ++i)
            speakeasy::write_le(b, 18 + i, szDescription[i], 1);
        for (size_t i = 0; i < WSASYS_STATUS_LEN + 1; ++i)
            speakeasy::write_le(b, 275 + i, szSystemStatus[i], 1);
        return b;
    }
};

// ── sockaddr ─────────────────────────────────────────────────

struct sockaddr : speakeasy::EmuStruct {
    uint16_t sa_family = 0;
    uint8_t  sa_data[14]{};

    size_t sizeof_obj() const override { return 16; }
    std::vector<uint8_t> get_bytes() const override {
        std::vector<uint8_t> b(16);
        speakeasy::write_le(b, 0, sa_family, 2);
        for (size_t i = 0; i < 14; ++i)
            speakeasy::write_le(b, 2 + i, sa_data[i], 1);
        return b;
    }
};

// ── sockaddr_in ─────────────────────────────────────────────

struct sockaddr_in : speakeasy::EmuStruct {
    uint16_t sin_family = 0;
    uint16_t sin_port   = 0;
    uint32_t sin_addr   = 0;
    uint8_t  sin_zero[8]{};

    size_t sizeof_obj() const override { return 16; }
    std::vector<uint8_t> get_bytes() const override {
        std::vector<uint8_t> b(16);
        speakeasy::write_le(b, 0, sin_family, 2);
        speakeasy::write_le(b, 2, sin_port,   2);
        speakeasy::write_le(b, 4, sin_addr,   4);
        for (size_t i = 0; i < 8; ++i)
            speakeasy::write_le(b, 8 + i, sin_zero[i], 1);
        return b;
    }
};

// ── hostent ─────────────────────────────────────────────────

struct hostent : speakeasy::EmuStruct {
    uint64_t h_name      = 0;  // Ptr
    uint64_t h_aliases   = 0;  // Ptr
    uint16_t h_addrtype  = 0;
    uint16_t h_length    = 0;
    uint64_t h_addr_list = 0;  // Ptr

    size_t sizeof_obj() const override { return 32; }
    std::vector<uint8_t> get_bytes() const override {
        std::vector<uint8_t> b(32);
        speakeasy::write_le(b, 0,  h_name,      8);
        speakeasy::write_le(b, 8,  h_aliases,   8);
        speakeasy::write_le(b, 16, h_addrtype,  2);
        speakeasy::write_le(b, 18, h_length,    2);
        speakeasy::write_le(b, 24, h_addr_list, 8);
        return b;
    }
};

// ── addrinfo ────────────────────────────────────────────────

struct addrinfo : speakeasy::EmuStruct {
    uint32_t ai_flags     = 0;
    uint32_t ai_family    = 0;
    uint32_t ai_socktype  = 0;
    uint32_t ai_protocol  = 0;
    uint64_t ai_addrlen   = 0;  // size_t: 8 bytes on 64-bit, 4 bytes on 32-bit
    uint64_t ai_canonname = 0;  // Ptr
    uint64_t ai_addr      = 0;  // Ptr
    uint64_t ai_next      = 0;  // Ptr

    size_t sizeof_obj() const override { return 48; }
    std::vector<uint8_t> get_bytes() const override {
        size_t sz = sizeof_obj();
        std::vector<uint8_t> b(sz, 0);
        speakeasy::write_le(b, 0,  ai_flags,     4);
        speakeasy::write_le(b, 4,  ai_family,    4);
        speakeasy::write_le(b, 8,  ai_socktype,  4);
        speakeasy::write_le(b, 12, ai_protocol,  4);
        if (sz == 48) {
            // 64-bit layout
            speakeasy::write_le(b, 16, ai_addrlen,   8);
            speakeasy::write_le(b, 24, ai_canonname, 8);
            speakeasy::write_le(b, 32, ai_addr,      8);
            speakeasy::write_le(b, 40, ai_next,      8);
        } else {
            // 32-bit layout
            speakeasy::write_le(b, 16, ai_addrlen,   4);
            speakeasy::write_le(b, 20, ai_canonname, 4);
            speakeasy::write_le(b, 24, ai_addr,      4);
            speakeasy::write_le(b, 28, ai_next,      4);
        }
        return b;
    }
};

} // namespace winsock
} // namespace defs
} // namespace speakeasy

#endif // SPEAKEASY_DEFS_WINSOCK_SPEA_WS2_32_H
