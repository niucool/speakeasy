// advapi32.h  Windows ADVAPI32 type definitions (new EmuStructHelper CRTP)
//
// Maps to: speakeasy/winenv/defs/windows/advapi32.py
//
// Uses the new EmuStructHelper CRTP approach for auto serialize/deserialize.
// All structs use #pragma pack(push, 1).
//
// Namespace speakeasy::deffs::windows to avoid conflicts with existing defs.

#ifndef SPEAKEASY_DEFS_NEW_WINDOWS_ADVAPI32_H
#define SPEAKEASY_DEFS_NEW_WINDOWS_ADVAPI32_H

#include <cstdint>
#include <string>
#include "struct.h"

namespace speakeasy { namespace deffs { namespace windows {

#pragma pack(push, 1)

// ==========================================================================================================
// SERVICE_TABLE_ENTRY: ptr-size polymorphic
// x86: lpServiceName(Ptr=4) + lpServiceProc(Ptr=4) = 8
// x64: lpServiceName(Ptr=8) + lpServiceProc(Ptr=8) = 16
// ==========================================================================================================
template <int PtrSize>
struct SERVICE_TABLE_ENTRY_POD;

template <>
struct SERVICE_TABLE_ENTRY_POD<4> {
    uint32_t lpServiceName = 0; // offset 0
    uint32_t lpServiceProc = 0; // offset 4
    // total = 8
};

template <>
struct SERVICE_TABLE_ENTRY_POD<8> {
    uint64_t lpServiceName = 0; // offset 0
    uint64_t lpServiceProc = 0; // offset 8
    // total = 16
};

template <int PtrSize>
struct SERVICE_TABLE_ENTRY : public EmuStructHelper<SERVICE_TABLE_ENTRY<PtrSize>>, public SERVICE_TABLE_ENTRY_POD<PtrSize> {
    std::string get_mem_tag() const override { return "service_table_entry"; }
};

// ==========================================================================================================
// HCRYPTKEY: ptr-size polymorphic
// x86: Algid(4)+keylen(4)+keyp(4) = 12
// x64: Algid(4)+keylen(4)+pad(4)+keyp(8) = 20
// ==========================================================================================================
template <int PtrSize>
struct HCRYPTKEY_POD;

template <>
struct HCRYPTKEY_POD<4> {
    uint32_t Algid  = 0; // offset 0
    uint32_t keylen = 0; // offset 4
    uint32_t keyp   = 0; // offset 8
    // total = 12
};

template <>
struct HCRYPTKEY_POD<8> {
    uint32_t Algid  = 0; // offset 0
    uint32_t keylen = 0; // offset 4
    uint32_t pad1   = 0; // offset 8 → align keyp
    uint64_t keyp   = 0; // offset 12
    // total = 20
};

template <int PtrSize>
struct HCRYPTKEY : public EmuStructHelper<HCRYPTKEY<PtrSize>>, public HCRYPTKEY_POD<PtrSize> {
    std::string get_mem_tag() const override { return "hcryptkey"; }
};

#pragma pack(pop)

}}} // namespace speakeasy::deffs::windows

#endif // SPEAKEASY_DEFS_NEW_WINDOWS_ADVAPI32_H
