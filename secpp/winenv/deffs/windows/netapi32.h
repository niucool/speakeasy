// netapi32.h  Windows NETAPI32 type definitions (new EmuStructHelper CRTP)
//
// Maps to: speakeasy/winenv/defs/windows/netapi32.py
//
// Uses the new EmuStructHelper CRTP approach for auto serialize/deserialize.
// All structs use #pragma pack(push, 1).
//
// Namespace speakeasy::defs::new_structs to avoid conflicts with existing defs.

#ifndef SPEAKEASY_DEFS_NEW_WINDOWS_NETAPI32_H
#define SPEAKEASY_DEFS_NEW_WINDOWS_NETAPI32_H

#include <cstdint>
#include <string>
#include "struct.h"

namespace speakeasy { namespace defs { namespace new_structs {

// ==========================================================================================================
// Constants
// ==========================================================================================================

constexpr uint32_t kNerrSuccess               = 0;
constexpr uint32_t kNetSetupUnknownStatus      = 0;
constexpr uint32_t kNetSetupUnjoined           = 1;
constexpr uint32_t kNetSetupWorkgroupName     = 2;
constexpr uint32_t kNetSetupDomainName        = 3;

// Old-name aliases for migration compatibility
constexpr uint32_t NERR_Success           = 0;
constexpr auto     NetSetupDomainName     = kNetSetupDomainName;

#pragma pack(push, 1)

// ==========================================================================================================
// WKSTA_INFO_100: ptr-size polymorphic
// x86: wki_platform_id(4) + wki_computername(4) + wki_langroup(4) + wki_ver_major(4) + wki_ver_minor(4) = 20
// x64: wki_platform_id(8) + wki_computername(8) + wki_langroup(8) + wki_ver_major(4) + wki_ver_minor(4) = 32
//      + pad(4) → but no, wki_ver_major is a u32 so no padding needed after 3 consecutive ptrs? Under pack(1) there's no implicit padding.
//      Actually, wki_platform_id is Ptr, wki_computername is Ptr, wki_langroup is Ptr
//      then wki_ver_major is u32, wki_ver_minor is u32.
//      x64: 8+8+8+4+4 = 32 (all 8-alignments satisfied ✓ since 8+8+8 = 24, then u32 at 24 is 4-aligned ✓)
// ==========================================================================================================
template <int PtrSize>
struct WKSTA_INFO_100_POD;

template <>
struct WKSTA_INFO_100_POD<4> {
    uint32_t wki_platform_id  = 0;  // offset  0
    uint32_t wki_computername = 0;  // offset  4
    uint32_t wki_langroup     = 0;  // offset  8
    uint32_t wki_ver_major    = 0;  // offset 12
    uint32_t wki_ver_minor    = 0;  // offset 16
    // total = 20
};

template <>
struct WKSTA_INFO_100_POD<8> {
    uint64_t wki_platform_id  = 0;  // offset  0
    uint64_t wki_computername = 0;  // offset  8
    uint64_t wki_langroup     = 0;  // offset 16
    uint32_t wki_ver_major    = 0;  // offset 24
    uint32_t wki_ver_minor    = 0;  // offset 28
    // total = 32
};

template <int PtrSize>
struct WKSTA_INFO_100 : public EmuStructHelper<WKSTA_INFO_100<PtrSize>>, public WKSTA_INFO_100_POD<PtrSize> {
    std::string get_mem_tag() const override { return "wksta_info_100"; }
};

// ==========================================================================================================
// WKSTA_INFO_101: ptr-size polymorphic (WKSTA_INFO_100 + wki_lanroot)
// x86: 3*Ptr(12) + 2*u32(8) + Ptr(4) = 24
// x64: u32(4)+pad(4)+2*Ptr(16)+2*u32(8)+Ptr(8) = 40
// ==========================================================================================================
template <int PtrSize>
struct WKSTA_INFO_101_POD;

template <>
struct WKSTA_INFO_101_POD<4> {
    uint32_t wki_platform_id  = 0;  // offset  0
    uint32_t wki_computername = 0;  // offset  4
    uint32_t wki_langroup     = 0;  // offset  8
    uint32_t wki_ver_major    = 0;  // offset 12
    uint32_t wki_ver_minor    = 0;  // offset 16
    uint32_t wki_lanroot      = 0;  // offset 20
    // total = 24
};

template <>
struct WKSTA_INFO_101_POD<8> {
    uint32_t wki_platform_id  = 0;  // offset  0
    uint32_t pad0                = 0;  // offset  4 → align next Ptr
    uint64_t wki_computername = 0;  // offset  8
    uint64_t wki_langroup     = 0;  // offset 16
    uint32_t wki_ver_major    = 0;  // offset 24
    uint32_t wki_ver_minor    = 0;  // offset 28
    uint64_t wki_lanroot      = 0;  // offset 32
    // total = 40
};

template <int PtrSize>
struct WKSTA_INFO_101 : public EmuStructHelper<WKSTA_INFO_101<PtrSize>>, public WKSTA_INFO_101_POD<PtrSize> {
    std::string get_mem_tag() const override { return "wksta_info_101"; }
};

// ==========================================================================================================
// WKSTA_INFO_102: ptr-size polymorphic (WKSTA_INFO_101 + wki_logged_on_users)
// x86: 3*Ptr(12) + 2*u32(8) + Ptr(4) + Ptr(4) = 28
// x64: u32(4)+pad(4)+2*Ptr(16)+2*u32(8)+2*Ptr(16) = 48
// ==========================================================================================================
template <int PtrSize>
struct WKSTA_INFO_102_POD;

template <>
struct WKSTA_INFO_102_POD<4> {
    uint32_t wki_platform_id      = 0;  // offset  0
    uint32_t wki_computername     = 0;  // offset  4
    uint32_t wki_langroup         = 0;  // offset  8
    uint32_t wki_ver_major        = 0;  // offset 12
    uint32_t wki_ver_minor        = 0;  // offset 16
    uint32_t wki_lanroot          = 0;  // offset 20
    uint32_t wki_logged_on_users  = 0;  // offset 24
    // total = 28
};

template <>
struct WKSTA_INFO_102_POD<8> {
    uint32_t wki_platform_id      = 0;  // offset  0
    uint32_t pad0                    = 0;  // offset  4 → align next Ptr
    uint64_t wki_computername     = 0;  // offset  8
    uint64_t wki_langroup         = 0;  // offset 16
    uint32_t wki_ver_major        = 0;  // offset 24
    uint32_t wki_ver_minor        = 0;  // offset 28
    uint64_t wki_lanroot          = 0;  // offset 32
    uint64_t wki_logged_on_users  = 0;  // offset 40
    // total = 48
};

template <int PtrSize>
struct WKSTA_INFO_102 : public EmuStructHelper<WKSTA_INFO_102<PtrSize>>, public WKSTA_INFO_102_POD<PtrSize> {
    std::string get_mem_tag() const override { return "wksta_info_102"; }
};

// ==========================================================================================================
// SERVER_INFO_101: ptr-size polymorphic
// x86: platform_id(4) + name(4) + version_major(4) + version_minor(4) + type(4) + comment(4) = 24
// x64: platform_id(4) + pad(4) + name(8) + version_major(4) + version_minor(4) + type(4) + pad(4) + comment(8) = 40
// ==========================================================================================================
template <int PtrSize>
struct SERVER_INFO_101_POD;

template <>
struct SERVER_INFO_101_POD<4> {
    uint32_t sv101_platform_id   = 0;  // offset  0
    uint32_t sv101_name          = 0;  // offset  4
    uint32_t sv101_version_major = 0;  // offset  8
    uint32_t sv101_version_minor = 0;  // offset 12
    uint32_t sv101_type          = 0;  // offset 16
    uint32_t sv101_comment       = 0;  // offset 20
    // total = 24
};

template <>
struct SERVER_INFO_101_POD<8> {
    uint32_t sv101_platform_id   = 0;  // offset  0
    uint32_t pad0                = 0;  // offset  4
    uint64_t sv101_name          = 0;  // offset  8
    uint32_t sv101_version_major = 0;  // offset 16
    uint32_t sv101_version_minor = 0;  // offset 20
    uint32_t sv101_type          = 0;  // offset 24
    uint32_t pad1                = 0;  // offset 28
    uint64_t sv101_comment       = 0;  // offset 32
    // total = 40
};

template <int PtrSize>
struct SERVER_INFO_101 : public EmuStructHelper<SERVER_INFO_101<PtrSize>>, public SERVER_INFO_101_POD<PtrSize> {
    std::string get_mem_tag() const override { return "server_info_101"; }
};

#pragma pack(pop)

}}} // namespace speakeasy::defs::new_structs

#endif // SPEAKEASY_DEFS_NEW_WINDOWS_NETAPI32_H
