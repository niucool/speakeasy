// windef.h  Windows base type definitions (new EmuStructHelper CRTP)
//
// Maps to: speakeasy/winenv/defs/windows/windef.py
//
// Uses the new EmuStructHelper CRTP approach for auto serialize/deserialize.
// All structs use #pragma pack(push, 1) with explicit field ordering to match
// the sizeof() that Python ctypes (natural C ABI alignment) would produce.
//
// Namespace speakeasy::deffs::windows to avoid conflicts with existing defs.

#ifndef SPEAKEASY_DEFS_NEW_WINDOWS_WINDEF_H
#define SPEAKEASY_DEFS_NEW_WINDOWS_WINDEF_H

#include <cstdint>
#include <string>
#include "struct.h"

namespace speakeasy { namespace deffs { namespace windows {

#pragma pack(push, 1)

// ==========================================================================================================
// POINT: 8 bytes (int32 x, int32 y)
// ==========================================================================================================
struct POINT_POD {
    int32_t x = 0;
    int32_t y = 0;
};
struct POINT : public EmuStructHelper<POINT>, public POINT_POD {
    std::string get_mem_tag() const override { return "point"; }
};

// ==========================================================================================================
// RECT: 16 bytes (int32 left, top, right, bottom)
// ==========================================================================================================
struct RECT_POD {
    int32_t left   = 0;
    int32_t top    = 0;
    int32_t right  = 0;
    int32_t bottom = 0;
};
struct RECT : public EmuStructHelper<RECT>, public RECT_POD {
    std::string get_mem_tag() const override { return "rect"; }
};

// ==========================================================================================================
// MONITORINFO: 40 bytes (uint32 + RECT + RECT + uint32)
// ==========================================================================================================
struct MONITORINFO_POD {
    uint32_t    cbSize      = 0;   // offset  0
    RECT_POD    rcMonitor;         // offset  4 (16 bytes)
    RECT_POD    rcWork;            // offset 20 (16 bytes)
    uint32_t    dwFlags     = 0;   // offset 36
    // total = 40
};
struct MONITORINFO : public EmuStructHelper<MONITORINFO>, public MONITORINFO_POD {
    std::string get_mem_tag() const override { return "monitor_info"; }
};

#pragma pack(pop)

}}} // namespace speakeasy::deffs::windows

#endif // SPEAKEASY_DEFS_NEW_WINDOWS_WINDEF_H
