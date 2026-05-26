// user32.h  Windows User32 type definitions
//
// Maps to: speakeasy/winenv/defs/windows/user32.py
//
// Structures and constants for the Windows User32 API,
// including window messages, hooks, and window classes.

#ifndef SPEAKEASY_DEFS_WINDOWS_USER32_H
#define SPEAKEASY_DEFS_WINDOWS_USER32_H

#include <cstdint>
#include <vector>
#include "../../../struct.h"

namespace speakeasy { namespace defs { namespace windows {

//  Window Hook constants 

constexpr int32_t WH_CALLWNDPROC     = 4;
constexpr int32_t WH_CALLWNDPROCRET  = 12;
constexpr int32_t WH_CBT             = 5;
constexpr int32_t WH_DEBUG           = 9;
constexpr int32_t WH_FOREGROUNDIDLE  = 11;
constexpr int32_t WH_GETMESSAGE      = 3;
constexpr int32_t WH_JOURNALPLAYBACK = 1;
constexpr int32_t WH_JOURNALRECORD   = 0;
constexpr int32_t WH_KEYBOARD        = 2;
constexpr int32_t WH_KEYBOARD_LL     = 13;
constexpr int32_t WH_MOUSE           = 7;
constexpr int32_t WH_MOUSE_LL        = 14;
constexpr int32_t WH_MSGFILTER       = -1;
constexpr int32_t WH_SHELL           = 10;
constexpr int32_t WH_SYSMSGFILTER    = 6;

//  Window Message constants 

constexpr uint32_t WM_KEYDOWN     = 0x0100;
constexpr uint32_t WM_SYSKEYDOWN  = 0x0104;
constexpr uint32_t WM_TIMER       = 0x0113;
constexpr uint32_t WM_PAINT       = 0x000F;
constexpr uint32_t WM_INITDIALOG  = 0x0110;

//  Structures 

struct MSG : speakeasy::EmuStruct {
    uint64_t hwnd     = 0;
    uint32_t message  = 0;
    uint32_t _align1  = 0;
    uint64_t wParam   = 0;
    uint64_t lParam   = 0;
    uint32_t time     = 0;
    uint32_t _align2  = 0;
    uint64_t pt_x     = 0;
    uint64_t pt_y     = 0;
    uint32_t lPrivate = 0;
    uint32_t _align3  = 0;

    size_t sizeof_obj() const override { return 64; }
    std::vector<uint8_t> get_bytes() const override {
        std::vector<uint8_t> b(64);
        speakeasy::write_le(b, 0,  hwnd,     8);
        speakeasy::write_le(b, 8,  message,  4);
        speakeasy::write_le(b, 16, wParam,   8);
        speakeasy::write_le(b, 24, lParam,   8);
        speakeasy::write_le(b, 32, time,     4);
        speakeasy::write_le(b, 40, pt_x,     8);
        speakeasy::write_le(b, 48, pt_y,     8);
        speakeasy::write_le(b, 56, lPrivate, 4);
        return b;
    }
};

struct KBDLLHOOKSTRUCT : speakeasy::EmuStruct {
    uint32_t vkCode    = 0;
    uint32_t scanCode  = 0;
    uint32_t flags     = 0;
    uint32_t time      = 0;
    uint64_t dwExtraInfo = 0;

    size_t sizeof_obj() const override { return 24; }
    std::vector<uint8_t> get_bytes() const override {
        std::vector<uint8_t> b(24);
        speakeasy::write_le(b, 0,  vkCode,      4);
        speakeasy::write_le(b, 4,  scanCode,    4);
        speakeasy::write_le(b, 8,  flags,       4);
        speakeasy::write_le(b, 12, time,        4);
        speakeasy::write_le(b, 16, dwExtraInfo, 8);
        return b;
    }
};

struct USEROBJECTFLAGS : speakeasy::EmuStruct {
    uint32_t fInherit   = 0;
    uint32_t fReserved  = 0;
    uint32_t dwFlags    = 0;

    size_t sizeof_obj() const override { return 12; }
    std::vector<uint8_t> get_bytes() const override {
        std::vector<uint8_t> b(12);
        speakeasy::write_le(b, 0, fInherit,  4);
        speakeasy::write_le(b, 4, fReserved, 4);
        speakeasy::write_le(b, 8, dwFlags,   4);
        return b;
    }
};

struct WNDCLASSEX : speakeasy::EmuStruct {
    uint32_t cbSize         = 0;
    uint32_t style          = 0;
    uint64_t lpfnWndProc    = 0;
    uint32_t cbClsExtra     = 0;
    uint32_t cbWndExtra     = 0;
    uint64_t hInstance      = 0;
    uint64_t hIcon          = 0;
    uint64_t hCursor        = 0;
    uint64_t hbrBackground  = 0;
    uint64_t lpszMenuName   = 0;
    uint64_t lpszClassName  = 0;
    uint64_t hIconSm        = 0;

    size_t sizeof_obj() const override { return 80; }
    std::vector<uint8_t> get_bytes() const override {
        std::vector<uint8_t> b(80);
        speakeasy::write_le(b, 0,  cbSize,        4);
        speakeasy::write_le(b, 4,  style,         4);
        speakeasy::write_le(b, 8,  lpfnWndProc,   8);
        speakeasy::write_le(b, 16, cbClsExtra,    4);
        speakeasy::write_le(b, 20, cbWndExtra,    4);
        speakeasy::write_le(b, 24, hInstance,     8);
        speakeasy::write_le(b, 32, hIcon,         8);
        speakeasy::write_le(b, 40, hCursor,       8);
        speakeasy::write_le(b, 48, hbrBackground, 8);
        speakeasy::write_le(b, 56, lpszMenuName,  8);
        speakeasy::write_le(b, 64, lpszClassName, 8);
        speakeasy::write_le(b, 72, hIconSm,       8);
        return b;
    }
};

}}} // namespace speakeasy::defs::windows

#endif // SPEAKEASY_DEFS_WINDOWS_USER32_H
