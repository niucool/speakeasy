// user32.h  Windows USER32 type definitions (new EmuStructHelper CRTP)
//
// Maps to: speakeasy/winenv/defs/windows/user32.py
//
// Uses the new EmuStructHelper CRTP approach for auto serialize/deserialize.
// All structs use #pragma pack(push, 1).
//
// Namespace speakeasy::deffs::windows to avoid conflicts with existing defs.

#ifndef SPEAKEASY_DEFS_NEW_WINDOWS_USER32_H
#define SPEAKEASY_DEFS_NEW_WINDOWS_USER32_H

#include <cstdint>
#include <string>
#include "struct.h"
#include "windef.h"

namespace speakeasy { namespace deffs { namespace windows {

#pragma pack(push, 1)

// ==========================================================================================================
// MSG: 48 bytes (x64) / 28 bytes (x86)
// x86: hwnd(4) + message(4) + wParam(4) + lParam(4) + time(4) + pt_x(4) + pt_y(4) + lPrivate(4) = 32
// x64: hwnd(8) + message(4) + pad(4) + wParam(8) + lParam(8) + time(4) + pad(4) + pt_x(8) + pt_y(8) + lPrivate(4) + pad(4) = 56... 
// Actually let me recalculate for what Python ctypes would give:
// Python under packed EmuStruct: hwnd(Ptr=4/8) + message(u32=4) + wParam(Ptr=4/8) + lParam(Ptr=4/8) + time(u32=4) + pt_x(Ptr=4/8) + pt_y(Ptr=4/8) + lPrivate(u32=4)
// x86: 4+4+4+4+4+4+4+4 = 32
// x64: 8+4+4(pad)+8+8+4+4(pad)+8+8+4+4(pad) = 64
// Wait, no. Under pack(1), fields are laid out consecutively without padding.
// x64: 8+4+8+8+4+8+8+4 = 52? No that doesn't work for pointer alignment either.
// Actually under pack(1) the struct is packed, so no alignment padding.
// x64: 8+4+8+8+4+8+8+4 = 52
// But the Python code runs without pack - ctypes uses natural alignment by default.
// hwnd(Ptr=8) at 0, message(u32=4) at 8, wParam(Ptr=8) at 12 (not 8-aligned!), lParam(Ptr=8) at 20...
// Actually wait, Python ctypes by default uses natural alignment for each field.
// Under natural alignment:
// x64: hwnd(Ptr=8)@0, message(u32=4)@8, wParam(Ptr=8)@12(but Ptr needs 8-alignment)→@16, lParam(Ptr=8)@24, time(u32=4)@32, pt_x(Ptr=8)@36→@40, pt_y(Ptr=8)@48, lPrivate(u32=4)@56 = 60
// But EmuStruct packs things??? Let me check... the Python EmuStruct uses ctypes with manual field layout.

// Actually, looking at the original Python more carefully: MSG uses Ptr which is pointer-sized,
// and the EmuStruct framework handles field layout. In C++ under pack(1), we lay out fields
// contiguously. I need to figure out the right sizes.

// Under pack(1) sequential layout:
// x86 (PtrSize=4): 4+4+4+4+4+4+4+4 = 32
// x64 (PtrSize=8): 8+4+8+8+4+8+8+4 = 52
// But the original Python uses the EmuStruct framework. Let me just match the Python ctypes
// sizeof behavior by adding padding where pointers need alignment.

// Actually, on second thought, looking at the existing ntoskrnl.h pattern, when PtrSize=4
// we don't need padding, and when PtrSize=8 we add padding before pointers that follow
// non-8-byte fields. Under pack(1), there's no automatic padding, but we add explicit padding
// fields to match what ctypes natural alignment would produce.

// For MSG on x64: hwnd(Ptr=8)@0, message(u32=4)@8, pad(4)@12→align wParam to 16,
// wParam(Ptr=8)@16, lParam(Ptr=8)@24, time(u32=4)@32, pad(4)@36→align pt_x to 40,
// pt_x(Ptr=8)@40, pt_y(Ptr=8)@48, lPrivate(u32=4)@56, pad(4)@60
// Total: 64 bytes

// But hmm, in Python EmuStruct, do they use natural ABI alignment or packed layout?
// Let me look at the Python EmuStruct code to understand.
// Looking at: EmuStruct -> ctypes.BigEndianStructure (or similar) with ctypes fields.
// Actually no, the Python EmuStruct stores field descriptors and serializes/deserializes
// manually. The layout matches the in-memory representation of the emulated process.

// So the question is: are these packed (no padding) or naturally aligned?
// Looking at the existing C++ pattern in ntoskrnl.h, the SSDT<8> has:
//   pServiceTable (u64)@0, pCounterTable(u64)@8, NumberOfServices(u32)@16,
//   pad(u32)@20, pArgumentTable(u64)@24
// That pad is added because pArgumentTable is a Ptr that needs 8-alignment.
// So the approach is: add padding before pointer fields when PtrSize=8 and the
// current offset is not 8-aligned.

// For MSG, let me recalculate with this approach:
// x64 (PtrSize=8):
//   hwnd(Ptr=8)         @0  (0%8=0 ✓)
//   message(u32=4)      @8
//   pad(u32=4)          @12 → align wParam to 16
//   wParam(Ptr=8)       @16
//   lParam(Ptr=8)       @24
//   time(u32=4)         @32
//   pad(u32=4)          @36 → align pt_x to 40
//   pt_x(Ptr=8)         @40
//   pt_y(Ptr=8)         @48
//   lPrivate(u32=4)     @56
//   pad(u32=4)          @60 → total = 64

// Wait, but the task says "MSG (48 bytes x64)" - 48 bytes? Let me recheck.
// Original Python MSG: hwnd(Ptr) + message(u32) + wParam(Ptr) + lParam(Ptr) + time(u32) + pt_x(Ptr) + pt_y(Ptr) + lPrivate(u32)

// With ctypes natural alignment on x64:
// hwnd(Ptr=8)@0, message(u32=4)@8, wParam(Ptr=8)@12→padded to @16, lParam(Ptr=8)@24,
// time(u32=4)@32, pt_x(Ptr=8)@36→padded to @40, pt_y(Ptr=8)@48, lPrivate(u32=4)@56
// Total = 60 (no final padding)

// The task says 48 bytes x64... but that doesn't match. Let me look at the actual Windows MSG struct.
// Windows MSG (win32):
//   HWND hwnd;      // Ptr
//   UINT message;    // 4 bytes (on Win32) 
//   WPARAM wParam;   // Ptr
//   LPARAM lParam;   // Ptr
//   DWORD time;      // 4 bytes
//   POINT pt;        // 8 bytes (x64: LONG=4 + LONG=4)
//   DWORD lPrivate;  // 4 bytes

// Windows MSG x64: 8+4+4(pad)+8+8+4+4+4+4+4 = 48? No...
// Actually in real Windows SDK, MSG on x64 is:
//   HWND hwnd;     @0 (8 bytes)
//   UINT message;  @8 (4 bytes)  
//   WPARAM wParam; @12 (8 bytes, but only 4-byte aligned?) No...
// In the Windows ABI, the struct uses natural alignment.
// Actually, WPARAM is UINT_PTR which is 8 bytes on x64, needs 8-byte alignment.
// So: hwnd@0(8), message@8(4), pad@12(4), wParam@16(8), lParam@24(8),
// time@32(4), pt.x@36(4), pt.y@40(4), lPrivate@44(4) = 48

// Wait, pt is a POINT which is two LONGs (4+4). So no padding needed within pt.
// Total: 8+4+4(pad)+8+8+4+4+4+4 = 48 ✓

// So the C++ x64 layout should be:
//   uint64_t hwnd;         @0
//   uint32_t message;      @8
//   uint32_t pad1;         @12
//   uint64_t wParam;       @16
//   uint64_t lParam;       @24
//   uint32_t time;         @32
//   int32_t  pt_x;         @36
//   int32_t  pt_y;         @40
//   uint32_t lPrivate;     @44
// Total: 48 ✓

// On x86: 4+4+4+4+4+4+4+4 = 32

// ==========================================================================================================

template <int PtrSize>
struct MSG_POD;

// x86: 32 bytes
template <>
struct MSG_POD<4> {
    uint32_t hwnd      = 0; // offset  0
    uint32_t message   = 0; // offset  4
    uint32_t wParam    = 0; // offset  8
    uint32_t lParam    = 0; // offset 12
    uint32_t time      = 0; // offset 16
    uint32_t pt_x      = 0; // offset 20
    uint32_t pt_y      = 0; // offset 24
    uint32_t lPrivate  = 0; // offset 28
    // total = 32
};

// x64: 48 bytes
template <>
struct MSG_POD<8> {
    uint64_t hwnd      = 0; // offset  0
    uint32_t message   = 0; // offset  8
    uint32_t pad1      = 0; // offset 12 → align wParam to 16
    uint64_t wParam    = 0; // offset 16
    uint64_t lParam    = 0; // offset 24
    uint32_t time      = 0; // offset 32
    int32_t  pt_x      = 0; // offset 36
    int32_t  pt_y      = 0; // offset 40
    uint32_t lPrivate  = 0; // offset 44
    // total = 48
};

template <int PtrSize>
struct MSG : public EmuStructHelper<MSG<PtrSize>>, public MSG_POD<PtrSize> {
    std::string get_mem_tag() const override { return "msg"; }
};

// ==========================================================================================================
// KBDLLHOOKSTRUCT: 24 bytes (x64) / 16 bytes (x86) - actually fixed-size with Ptr fields
// x86: vkCode(4)+scanCode(4)+flags(4)+time(4)+dwExtraInfo(4) = 20
// x64: vkCode(4)+scanCode(4)+flags(4)+time(4)+pad(4)+dwExtraInfo(8) = 28
// ==========================================================================================================
template <int PtrSize>
struct KBDLLHOOKSTRUCT_POD;

template <>
struct KBDLLHOOKSTRUCT_POD<4> {
    uint32_t vkCode      = 0; // offset  0
    uint32_t scanCode    = 0; // offset  4
    uint32_t flags       = 0; // offset  8
    uint32_t time        = 0; // offset 12
    uint32_t dwExtraInfo = 0; // offset 16
    // total = 20
};

template <>
struct KBDLLHOOKSTRUCT_POD<8> {
    uint32_t vkCode      = 0; // offset  0
    uint32_t scanCode    = 0; // offset  4
    uint32_t flags       = 0; // offset  8
    uint32_t time        = 0; // offset 12
    uint64_t dwExtraInfo = 0; // offset 16
    // total = 24
};

template <int PtrSize>
struct KBDLLHOOKSTRUCT : public EmuStructHelper<KBDLLHOOKSTRUCT<PtrSize>>, public KBDLLHOOKSTRUCT_POD<PtrSize> {
    std::string get_mem_tag() const override { return "kbdllhookstruct"; }
};

// ==========================================================================================================
// USEROBJECTFLAGS: 12 bytes (3*uint32)
// ==========================================================================================================
struct USEROBJECTFLAGS_POD {
    uint32_t fInherit   = 0; // offset 0
    uint32_t fReserved  = 0; // offset 4
    uint32_t dwFlags    = 0; // offset 8
    // total = 12
};
struct USEROBJECTFLAGS : public EmuStructHelper<USEROBJECTFLAGS>, public USEROBJECTFLAGS_POD {
    std::string get_mem_tag() const override { return "userobjectflags"; }
};

// ==========================================================================================================
// WNDCLASSEX: ptr-size polymorphic (many Ptr fields)
// x86: cbSize(4)+style(4)+lpfnWndProc(4)+cbClsExtra(4)+cbWndExtra(4)+hInstance(4)+hIcon(4)+hCursor(4)
//      +hbrBackground(4)+lpszMenuName(4)+lpszClassName(4)+hIconSm(4) = 48
// x64: cbSize(4)+style(4)+lpfnWndProc(8)+cbClsExtra(4)+cbWndExtra(4)+pad1(4)+hInstance(8)
//      +hIcon(8)+hCursor(8)+hbrBackground(8)+lpszMenuName(8)+lpszClassName(8)+hIconSm(8) = 84
// ==========================================================================================================
template <int PtrSize>
struct WNDCLASSEX_POD;

template <>
struct WNDCLASSEX_POD<4> {
    uint32_t cbSize        = 0; // offset  0
    uint32_t style         = 0; // offset  4
    uint32_t lpfnWndProc   = 0; // offset  8
    uint32_t cbClsExtra    = 0; // offset 12
    uint32_t cbWndExtra    = 0; // offset 16
    uint32_t hInstance     = 0; // offset 20
    uint32_t hIcon         = 0; // offset 24
    uint32_t hCursor       = 0; // offset 28
    uint32_t hbrBackground = 0; // offset 32
    uint32_t lpszMenuName  = 0; // offset 36
    uint32_t lpszClassName = 0; // offset 40
    uint32_t hIconSm       = 0; // offset 44
    // total = 48
};

template <>
struct WNDCLASSEX_POD<8> {
    uint32_t cbSize        = 0; // offset  0
    uint32_t style         = 0; // offset  4
    uint64_t lpfnWndProc   = 0; // offset  8
    uint32_t cbClsExtra    = 0; // offset 16
    uint32_t cbWndExtra    = 0; // offset 20
    uint64_t hInstance     = 0; // offset 24 (24 is 8-aligned ✓)
    uint64_t hIcon         = 0; // offset 32
    uint64_t hCursor       = 0; // offset 40
    uint64_t hbrBackground = 0; // offset 48
    uint64_t lpszMenuName  = 0; // offset 56
    uint64_t lpszClassName = 0; // offset 64
    uint64_t hIconSm       = 0; // offset 72
    // total = 80
};

template <int PtrSize>
struct WNDCLASSEX : public EmuStructHelper<WNDCLASSEX<PtrSize>>, public WNDCLASSEX_POD<PtrSize> {
    std::string get_mem_tag() const override { return "wndclassex"; }
};

#pragma pack(pop)

}}} // namespace speakeasy::deffs::windows

#endif // SPEAKEASY_DEFS_NEW_WINDOWS_USER32_H
