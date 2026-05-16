// mpr.h — Windows Multi-Protocol Router (WNet) type definitions
//
// Maps to: speakeasy/winenv/defs/windows/mpr.py
//
// WNet (Windows Networking) constants and structures used by
// mpr API handlers for network resource enumeration.

#ifndef SPEAKEASY_DEFS_WINDOWS_MPR_H
#define SPEAKEASY_DEFS_WINDOWS_MPR_H

#include <cstdint>
#include <vector>
#include "windef.h"
#include "../../../struct.h"

namespace speakeasy { namespace defs { namespace windows {

// ── Resource scope ─────────────────────────────────────────────

constexpr uint32_t RESOURCE_CONNECTED    = 1;
constexpr uint32_t RESOURCE_GLOBALNET   = 2;
constexpr uint32_t RESOURCE_REMEMBERED   = 3;
constexpr uint32_t RESOURCE_CONTEXT      = 5;

// ── Resource type ──────────────────────────────────────────────

constexpr uint32_t RESOURCETYPE_ANY    = 0;
constexpr uint32_t RESOURCETYPE_DISK   = 1;
constexpr uint32_t RESOURCETYPE_PRINT  = 2;

// ── Resource usage ─────────────────────────────────────────────

constexpr uint32_t RESOURCEUSAGE_CONNECTABLE = 1;
constexpr uint32_t RESOURCEUSAGE_CONTAINER   = 2;
constexpr uint32_t RESOURCEUSAGE_ATTACHED    = 0x10;
constexpr uint32_t RESOURCEUSAGE_ALL         = 0x13;

// ── Error codes ────────────────────────────────────────────────

constexpr uint32_t ERROR_NO_NETWORK = 0x4C6;

// ── NETRESOURCE structure ──────────────────────────────────────

struct NETRESOURCE : speakeasy::EmuStruct {
    uint32_t dwScope       = 0;
    uint32_t dwType        = 0;
    uint32_t dwDisplayType = 0;
    uint32_t dwUsage       = 0;
    uint64_t lpLocalName   = 0;  // LPWSTR
    uint64_t lpRemoteName  = 0;  // LPWSTR
    uint64_t lpComment     = 0;  // LPWSTR
    uint64_t lpProvider    = 0;  // LPWSTR

    size_t sizeof_obj() const override {
        return (sizeof(uint64_t) == 8) ? 48 : 32;
    }
    std::vector<uint8_t> get_bytes() const override {
        size_t sz = sizeof_obj();
        std::vector<uint8_t> b(sz, 0);
        speakeasy::write_le(b, 0, dwScope, 4);
        speakeasy::write_le(b, 4, dwType, 4);
        speakeasy::write_le(b, 8, dwDisplayType, 4);
        speakeasy::write_le(b, 12, dwUsage, 4);
        if (sz == 48) {
            speakeasy::write_le(b, 16, lpLocalName, 8);
            speakeasy::write_le(b, 24, lpRemoteName, 8);
            speakeasy::write_le(b, 32, lpComment, 8);
            speakeasy::write_le(b, 40, lpProvider, 8);
        } else {
            speakeasy::write_le(b, 16, lpLocalName, 4);
            speakeasy::write_le(b, 20, lpRemoteName, 4);
            speakeasy::write_le(b, 24, lpComment, 4);
            speakeasy::write_le(b, 28, lpProvider, 4);
        }
        return b;
    }
};

}}} // namespaces

#endif // SPEAKEASY_DEFS_WINDOWS_MPR_H
