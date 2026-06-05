// shell32.h  Windows SHELL32 type definitions (new EmuStructHelper CRTP)
//
// Maps to: speakeasy/winenv/defs/windows/shell32.py
//
// Uses the new EmuStructHelper CRTP approach for auto serialize/deserialize.
// All structs use #pragma pack(push, 1).
//
// Namespace speakeasy::defs::new_structs to avoid conflicts with existing defs.

#ifndef SPEAKEASY_DEFS_NEW_WINDOWS_SHELL32_H
#define SPEAKEASY_DEFS_NEW_WINDOWS_SHELL32_H

#include <cstdint>
#include <string>
#include "struct.h"

namespace speakeasy { namespace defs { namespace new_structs {

#pragma pack(push, 1)

// ==========================================================================================================
// SHELLEXECUTEINFOA: ptr-size polymorphic
// x86: cbSize(4)+fMask(4)+hwnd(4)+lpVerb(4)+lpFile(4)+lpParameters(4)+lpDirectory(4)+nShow(4)
//      +hInstApp(4)+lpIDList(4)+lpClass(4)+hkeyClass(4)+dwHotKey(4)+DummyUnionName(4)+handle(4) = 60
// x64: cbSize(4)+fMask(4)+hwnd(8)+lpVerb(8)+lpFile(8)+lpParameters(8)+lpDirectory(8)+nShow(4)
//      +pad1(4)+hInstApp(8)+lpIDList(8)+lpClass(8)+hkeyClass(8)+dwHotKey(4)+pad2(4)
//      +DummyUnionName(8)+handle(8) = 112
// ==========================================================================================================
template <int PtrSize>
struct SHELLEXECUTEINFOA_POD;

template <>
struct SHELLEXECUTEINFOA_POD<4> {
    uint32_t cbSize          = 0; // offset  0
    uint32_t fMask           = 0; // offset  4
    uint32_t hwnd            = 0; // offset  8
    uint32_t lpVerb          = 0; // offset 12
    uint32_t lpFile          = 0; // offset 16
    uint32_t lpParameters    = 0; // offset 20
    uint32_t lpDirectory     = 0; // offset 24
    int32_t  nShow           = 0; // offset 28
    uint32_t hInstApp        = 0; // offset 32
    uint32_t lpIDList        = 0; // offset 36
    uint32_t lpClass         = 0; // offset 40
    uint32_t hkeyClass       = 0; // offset 44
    uint32_t dwHotKey        = 0; // offset 48
    uint32_t DummyUnionName  = 0; // offset 52
    uint32_t handle          = 0; // offset 56
    // total = 60
};

template <>
struct SHELLEXECUTEINFOA_POD<8> {
    uint32_t cbSize          = 0; // offset  0
    uint32_t fMask           = 0; // offset  4
    uint64_t hwnd            = 0; // offset  8
    uint64_t lpVerb          = 0; // offset 16
    uint64_t lpFile          = 0; // offset 24
    uint64_t lpParameters    = 0; // offset 32
    uint64_t lpDirectory     = 0; // offset 40
    int32_t  nShow           = 0; // offset 48
    uint32_t pad1            = 0; // offset 52 → align hInstApp
    uint64_t hInstApp        = 0; // offset 56
    uint64_t lpIDList        = 0; // offset 64
    uint64_t lpClass         = 0; // offset 72
    uint64_t hkeyClass       = 0; // offset 80
    uint32_t dwHotKey        = 0; // offset 88
    uint32_t pad2            = 0; // offset 92 → align DummyUnionName
    uint64_t DummyUnionName  = 0; // offset 96
    uint64_t handle          = 0; // offset 104
    // total = 112
};

template <int PtrSize>
struct SHELLEXECUTEINFOA : public EmuStructHelper<SHELLEXECUTEINFOA<PtrSize>>, public SHELLEXECUTEINFOA_POD<PtrSize> {
    std::string get_mem_tag() const override { return "shellexecuteinfoa"; }
};

#pragma pack(pop)

}}} // namespace speakeasy::defs::new_structs

#endif // SPEAKEASY_DEFS_NEW_WINDOWS_SHELL32_H
