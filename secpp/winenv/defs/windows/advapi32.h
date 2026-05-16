// advapi32.h — Windows Advanced Services (AdvAPI32) type definitions
//
// Maps to: speakeasy/winenv/defs/windows/advapi32.py
//
// Structures and constants for the Windows Advanced Services API,
// including registry, event logging, security, and service management.

#ifndef SPEAKEASY_DEFS_WINDOWS_ADVAPI32_H
#define SPEAKEASY_DEFS_WINDOWS_ADVAPI32_H

#include <cstdint>
#include <vector>
#include "../../../struct.h"

namespace speakeasy { namespace defs { namespace windows {

// ── Constants ─────────────────────────────────────────────────

constexpr uint32_t NTE_BAD_ALGID    = 0x80090008;

constexpr uint32_t SERVICE_WIN32     = 0x30;

constexpr uint32_t SERVICE_ACTIVE    = 0x1;
constexpr uint32_t SERVICE_INACTIVE  = 0x2;
constexpr uint32_t SERVICE_STATE_ALL = 0x3;

// ── Structures ────────────────────────────────────────────────

struct SERVICE_TABLE_ENTRY : speakeasy::EmuStruct {
    uint64_t lpServiceName = 0;
    uint64_t lpServiceProc = 0;

    size_t sizeof_obj() const override { return 16; }
    std::vector<uint8_t> get_bytes() const override {
        std::vector<uint8_t> b(16);
        speakeasy::write_le(b, 0, lpServiceName, 8);
        speakeasy::write_le(b, 8, lpServiceProc, 8);
        return b;
    }
};

struct HCRYPTKEY : speakeasy::EmuStruct {
    uint32_t Algid  = 0;
    uint32_t keylen = 0;
    uint64_t keyp   = 0;

    size_t sizeof_obj() const override { return 16; }
    std::vector<uint8_t> get_bytes() const override {
        std::vector<uint8_t> b(16);
        speakeasy::write_le(b, 0, Algid,  4);
        speakeasy::write_le(b, 4, keylen, 4);
        speakeasy::write_le(b, 8, keyp,   8);
        return b;
    }
};

}}} // namespace speakeasy::defs::windows

#endif // SPEAKEASY_DEFS_WINDOWS_ADVAPI32_H
