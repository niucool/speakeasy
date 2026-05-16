// netapi32.h — Network Management API type definitions
//
// Maps to: speakeasy/winenv/defs/windows/netapi32.py
//
// NetAPI workstation and server information structures used by
// netapi32 API handlers.

#ifndef SPEAKEASY_DEFS_WINDOWS_NETAPI32_H
#define SPEAKEASY_DEFS_WINDOWS_NETAPI32_H

#include <cstdint>
#include <vector>
#include "windef.h"
#include "../../../struct.h"

namespace speakeasy { namespace defs { namespace windows {

// ── Constants ──────────────────────────────────────────────────

constexpr uint32_t NERR_Success = 0;

// NetSetup join status
constexpr uint32_t NetSetupUnknownStatus    = 0;
constexpr uint32_t NetSetupUnjoined         = 1;
constexpr uint32_t NetSetupWorkgroupName   = 2;
constexpr uint32_t NetSetupDomainName      = 3;

// ── WKSTA_INFO_100 ─────────────────────────────────────────────

struct WKSTA_INFO_100 : speakeasy::EmuStruct {
    uint64_t wki_platform_id  = 0;  // wchar_t*
    uint64_t wki_computername = 0;  // wchar_t*
    uint64_t wki_langroup     = 0;  // wchar_t*
    uint32_t wki_ver_major    = 0;
    uint32_t wki_ver_minor    = 0;

    size_t sizeof_obj() const override {
        return (sizeof(uint64_t) == 8) ? 32 : 20;
    }
    std::vector<uint8_t> get_bytes() const override {
        size_t sz = sizeof_obj();
        std::vector<uint8_t> b(sz, 0);
        size_t p = (sizeof(uint64_t) == 8) ? 8 : 4;
        speakeasy::write_le(b, 0,  wki_platform_id, p);
        speakeasy::write_le(b, p,  wki_computername, p);
        speakeasy::write_le(b, p*2, wki_langroup, p);
        if (sz == 32 && p == 8) {
            // x64: no padding needed, pointers fill 24 bytes, then 4+4 = 32
        }
        speakeasy::write_le(b, p*3, wki_ver_major, 4);
        speakeasy::write_le(b, p*3 + 4, wki_ver_minor, 4);
        return b;
    }
};

// ── WKSTA_INFO_101 ─────────────────────────────────────────────

struct WKSTA_INFO_101 : speakeasy::EmuStruct {
    uint64_t wki_platform_id  = 0;  // wchar_t*
    uint64_t wki_computername = 0;  // wchar_t*
    uint64_t wki_langroup     = 0;  // wchar_t*
    uint32_t wki_ver_major    = 0;
    uint32_t wki_ver_minor    = 0;
    uint64_t wki_lanroot      = 0;  // wchar_t*

    size_t sizeof_obj() const override {
        return (sizeof(uint64_t) == 8) ? 40 : 24;
    }
    std::vector<uint8_t> get_bytes() const override {
        size_t sz = sizeof_obj();
        std::vector<uint8_t> b(sz, 0);
        size_t p = (sizeof(uint64_t) == 8) ? 8 : 4;
        speakeasy::write_le(b, 0,   wki_platform_id, p);
        speakeasy::write_le(b, p,   wki_computername, p);
        speakeasy::write_le(b, p*2, wki_langroup, p);
        if (sz == 40 && p == 8) {
            speakeasy::write_le(b, 24, wki_ver_major, 4);
            speakeasy::write_le(b, 28, wki_ver_minor, 4);
        } else {
            speakeasy::write_le(b, p*3, wki_ver_major, 4);
            speakeasy::write_le(b, p*3 + 4, wki_ver_minor, 4);
        }
        speakeasy::write_le(b, p == 8 ? 32 : 20, wki_lanroot, p);
        return b;
    }
};

// ── WKSTA_INFO_102 ─────────────────────────────────────────────

struct WKSTA_INFO_102 : speakeasy::EmuStruct {
    uint64_t wki_platform_id     = 0;  // wchar_t*
    uint64_t wki_computername    = 0;  // wchar_t*
    uint64_t wki_langroup        = 0;  // wchar_t*
    uint32_t wki_ver_major       = 0;
    uint32_t wki_ver_minor       = 0;
    uint64_t wki_lanroot         = 0;  // wchar_t*
    uint64_t wki_logged_on_users = 0;  // wchar_t*

    size_t sizeof_obj() const override {
        return (sizeof(uint64_t) == 8) ? 48 : 28;
    }
    std::vector<uint8_t> get_bytes() const override {
        size_t sz = sizeof_obj();
        std::vector<uint8_t> b(sz, 0);
        size_t p = (sizeof(uint64_t) == 8) ? 8 : 4;
        speakeasy::write_le(b, 0,   wki_platform_id, p);
        speakeasy::write_le(b, p,   wki_computername, p);
        speakeasy::write_le(b, p*2, wki_langroup, p);
        if (sz == 48 && p == 8) {
            speakeasy::write_le(b, 24, wki_ver_major, 4);
            speakeasy::write_le(b, 28, wki_ver_minor, 4);
            speakeasy::write_le(b, 32, wki_lanroot, 8);
            speakeasy::write_le(b, 40, wki_logged_on_users, 8);
        } else {
            speakeasy::write_le(b, p*3, wki_ver_major, 4);
            speakeasy::write_le(b, p*3 + 4, wki_ver_minor, 4);
            speakeasy::write_le(b, p*4, wki_lanroot, 4);
            speakeasy::write_le(b, p*5, wki_logged_on_users, 4);
        }
        return b;
    }
};

// ── SERVER_INFO_101 (common) ──────────────────────────────────

struct SERVER_INFO_101 : speakeasy::EmuStruct {
    uint32_t sv101_platform_id   = 0;
    uint64_t sv101_name          = 0;  // wchar_t*
    uint32_t sv101_version_major = 0;
    uint32_t sv101_version_minor = 0;
    uint32_t sv101_type          = 0;
    uint64_t sv101_comment       = 0;  // wchar_t*

    size_t sizeof_obj() const override {
        return (sizeof(uint64_t) == 8) ? 32 : 24;
    }
    std::vector<uint8_t> get_bytes() const override {
        size_t sz = sizeof_obj();
        std::vector<uint8_t> b(sz, 0);
        speakeasy::write_le(b, 0, sv101_platform_id, 4);
        if (sz == 32) {
            speakeasy::write_le(b, 4,  0, 4);  // padding
            speakeasy::write_le(b, 8,  sv101_name, 8);
            speakeasy::write_le(b, 16, sv101_version_major, 4);
            speakeasy::write_le(b, 20, sv101_version_minor, 4);
            speakeasy::write_le(b, 24, sv101_type, 4);
            // no padding needed before sv101_comment at 32
        } else {
            speakeasy::write_le(b, 4, sv101_name, 4);
            speakeasy::write_le(b, 8, sv101_version_major, 4);
            speakeasy::write_le(b, 12, sv101_version_minor, 4);
            speakeasy::write_le(b, 16, sv101_type, 4);
            speakeasy::write_le(b, 20, sv101_comment, 4);
            return b;
        }
        // x64: comment after the 4+4(pad)+8+4+4+4 = 28, so offset 28 no pad
        speakeasy::write_le(b, 28, 0, 4);  // padding before comment ptr
        speakeasy::write_le(b, 32, sv101_comment, 8);
        return b;
    }
};

}}} // namespaces

#endif // SPEAKEASY_DEFS_WINDOWS_NETAPI32_H
