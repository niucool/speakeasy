// shell32.h — Windows Shell32 type definitions
//
// Maps to: speakeasy/winenv/defs/windows/shell32.py
//
// Structures and constants for the Windows Shell API (Shell32),
// including CSIDL identifiers and shell execution information.

#ifndef SPEAKEASY_DEFS_WINDOWS_SHELL32_H
#define SPEAKEASY_DEFS_WINDOWS_SHELL32_H

#include <cstdint>
#include <vector>
#include <string>
#include <map>
#include "../../../struct.h"

namespace speakeasy { namespace defs { namespace windows {

// ── CSIDL constants ───────────────────────────────────────────

constexpr uint32_t CSIDL_DESKTOP                  = 0x00;
constexpr uint32_t CSIDL_INTERNET                 = 0x01;
constexpr uint32_t CSIDL_PROGRAMS                 = 0x02;
constexpr uint32_t CSIDL_CONTROLS                 = 0x03;
constexpr uint32_t CSIDL_PRINTERS                 = 0x04;
constexpr uint32_t CSIDL_MYDOCUMENTS              = 0x05;
constexpr uint32_t CSIDL_FAVORITES                = 0x06;
constexpr uint32_t CSIDL_STARTUP                  = 0x07;
constexpr uint32_t CSIDL_RECENT                   = 0x08;
constexpr uint32_t CSIDL_SENDTO                   = 0x09;
constexpr uint32_t CSIDL_BITBUCKET                = 0x0A;
constexpr uint32_t CSIDL_STARTMENU                = 0x0B;
constexpr uint32_t CSIDL_MYMUSIC                  = 0x0D;
constexpr uint32_t CSIDL_MYVIDEO                  = 0x0E;
constexpr uint32_t CSIDL_DESKTOPDIRECTORY         = 0x10;
constexpr uint32_t CSIDL_DRIVES                   = 0x11;
constexpr uint32_t CSIDL_NETWORK                  = 0x12;
constexpr uint32_t CSIDL_NETHOOD                  = 0x13;
constexpr uint32_t CSIDL_FONTS                    = 0x14;
constexpr uint32_t CSIDL_TEMPLATES                = 0x15;
constexpr uint32_t CSIDL_COMMON_STARTMENU         = 0x16;
constexpr uint32_t CSIDL_COMMON_PROGRAMS          = 0x17;
constexpr uint32_t CSIDL_COMMON_STARTUP           = 0x18;
constexpr uint32_t CSIDL_COMMON_DESKTOPDIRECTORY  = 0x19;
constexpr uint32_t CSIDL_APPDATA                  = 0x1A;
constexpr uint32_t CSIDL_PRINTHOOD                = 0x1B;
constexpr uint32_t CSIDL_LOCAL_APPDATA            = 0x1C;
constexpr uint32_t CSIDL_ALTSTARTUP               = 0x1D;
constexpr uint32_t CSIDL_COMMON_ALTSTARTUP        = 0x1E;
constexpr uint32_t CSIDL_COMMON_FAVORITES         = 0x1F;
constexpr uint32_t CSIDL_INTERNET_CACHE           = 0x20;
constexpr uint32_t CSIDL_COOKIES                  = 0x21;
constexpr uint32_t CSIDL_HISTORY                  = 0x22;
constexpr uint32_t CSIDL_COMMON_APPDATA           = 0x23;
constexpr uint32_t CSIDL_WINDOWS                  = 0x24;
constexpr uint32_t CSIDL_SYSTEM                   = 0x25;
constexpr uint32_t CSIDL_PROGRAM_FILES            = 0x26;
constexpr uint32_t CSIDL_MYPICTURES               = 0x27;
constexpr uint32_t CSIDL_PROFILE                  = 0x28;
constexpr uint32_t CSIDL_SYSTEMX86                = 0x29;
constexpr uint32_t CSIDL_PROGRAM_FILESX86         = 0x2A;
constexpr uint32_t CSIDL_PROGRAM_FILES_COMMON     = 0x2B;
constexpr uint32_t CSIDL_PROGRAM_FILES_COMMONX86  = 0x2C;
constexpr uint32_t CSIDL_COMMON_DOCUMENTS         = 0x2D;
constexpr uint32_t CSIDL_COMMON_TEMPLATES         = 0x2E;
constexpr uint32_t CSIDL_COMMON_ADMINTOOLS        = 0x2F;
constexpr uint32_t CSIDL_ADMINTOOLS               = 0x30;
constexpr uint32_t CSIDL_CONNECTIONS              = 0x31;
constexpr uint32_t CSIDL_COMMON_MUSIC             = 0x35;
constexpr uint32_t CSIDL_COMMON_PICTURES          = 0x36;
constexpr uint32_t CSIDL_COMMON_VIDEO             = 0x37;
constexpr uint32_t CSIDL_RESOURCES                = 0x38;
constexpr uint32_t CSIDL_RESOURCES_LOCALIZED      = 0x39;
constexpr uint32_t CSIDL_CDBURN_AREA              = 0x3B;
constexpr uint32_t CSIDL_COMPUTERSNEARME          = 0x3D;
constexpr uint32_t CSIDL_PLAYLISTS                = 0x3F;
constexpr uint32_t CSIDL_SAMPLE_MUSIC             = 0x40;
constexpr uint32_t CSIDL_SAMPLE_PLAYLISTS         = 0x41;
constexpr uint32_t CSIDL_SAMPLE_PICTURES          = 0x42;
constexpr uint32_t CSIDL_SAMPLE_VIDEOS            = 0x43;
constexpr uint32_t CSIDL_PHOTOALBUMS              = 0x45;

/** Lookup a CSIDL value by name (reverse of CSIDL map in Python). */
inline std::string get_csidl_name(uint32_t csidl) {
    static const std::map<uint32_t, std::string> m = {
        {0x00, "CSIDL_DESKTOP"},
        {0x01, "CSIDL_INTERNET"},
        {0x02, "CSIDL_PROGRAMS"},
        {0x03, "CSIDL_CONTROLS"},
        {0x04, "CSIDL_PRINTERS"},
        {0x05, "CSIDL_MYDOCUMENTS"},
        {0x06, "CSIDL_FAVORITES"},
        {0x07, "CSIDL_STARTUP"},
        {0x08, "CSIDL_RECENT"},
        {0x09, "CSIDL_SENDTO"},
        {0x0A, "CSIDL_BITBUCKET"},
        {0x0B, "CSIDL_STARTMENU"},
        {0x0D, "CSIDL_MYMUSIC"},
        {0x0E, "CSIDL_MYVIDEO"},
        {0x10, "CSIDL_DESKTOPDIRECTORY"},
        {0x11, "CSIDL_DRIVES"},
        {0x12, "CSIDL_NETWORK"},
        {0x13, "CSIDL_NETHOOD"},
        {0x14, "CSIDL_FONTS"},
        {0x15, "CSIDL_TEMPLATES"},
        {0x16, "CSIDL_COMMON_STARTMENU"},
        {0x17, "CSIDL_COMMON_PROGRAMS"},
        {0x18, "CSIDL_COMMON_STARTUP"},
        {0x19, "CSIDL_COMMON_DESKTOPDIRECTORY"},
        {0x1A, "CSIDL_APPDATA"},
        {0x1B, "CSIDL_PRINTHOOD"},
        {0x1C, "CSIDL_LOCAL_APPDATA"},
        {0x1D, "CSIDL_ALTSTARTUP"},
        {0x1E, "CSIDL_COMMON_ALTSTARTUP"},
        {0x1F, "CSIDL_COMMON_FAVORITES"},
        {0x20, "CSIDL_INTERNET_CACHE"},
        {0x21, "CSIDL_COOKIES"},
        {0x22, "CSIDL_HISTORY"},
        {0x23, "CSIDL_COMMON_APPDATA"},
        {0x24, "CSIDL_WINDOWS"},
        {0x25, "CSIDL_SYSTEM"},
        {0x26, "CSIDL_PROGRAM_FILES"},
        {0x27, "CSIDL_MYPICTURES"},
        {0x28, "CSIDL_PROFILE"},
        {0x29, "CSIDL_SYSTEMX86"},
        {0x2A, "CSIDL_PROGRAM_FILESX86"},
        {0x2B, "CSIDL_PROGRAM_FILES_COMMON"},
        {0x2C, "CSIDL_PROGRAM_FILES_COMMONX86"},
        {0x2D, "CSIDL_COMMON_DOCUMENTS"},
        {0x2E, "CSIDL_COMMON_TEMPLATES"},
        {0x2F, "CSIDL_COMMON_ADMINTOOLS"},
        {0x30, "CSIDL_ADMINTOOLS"},
        {0x31, "CSIDL_CONNECTIONS"},
        {0x35, "CSIDL_COMMON_MUSIC"},
        {0x36, "CSIDL_COMMON_PICTURES"},
        {0x37, "CSIDL_COMMON_VIDEO"},
        {0x38, "CSIDL_RESOURCES"},
        {0x39, "CSIDL_RESOURCES_LOCALIZED"},
        {0x3B, "CSIDL_CDBURN_AREA"},
        {0x3D, "CSIDL_COMPUTERSNEARME"},
        {0x3F, "CSIDL_PLAYLISTS"},
        {0x40, "CSIDL_SAMPLE_MUSIC"},
        {0x41, "CSIDL_SAMPLE_PLAYLISTS"},
        {0x42, "CSIDL_SAMPLE_PICTURES"},
        {0x43, "CSIDL_SAMPLE_VIDEOS"},
        {0x45, "CSIDL_PHOTOALBUMS"},
    };
    auto it = m.find(csidl);
    return (it != m.end()) ? it->second : "CSIDL_UNKNOWN";
}

// ── Structures ────────────────────────────────────────────────

struct SHELLEXECUTEINFOA : speakeasy::EmuStruct {
    uint32_t cbSize            = 0;
    uint32_t fMask             = 0;
    uint64_t hwnd              = 0;
    uint64_t lpVerb            = 0;
    uint64_t lpFile            = 0;
    uint64_t lpParameters      = 0;
    uint64_t lpDirectory       = 0;
    int32_t  nShow             = 0;
    uint32_t _align1           = 0;
    uint64_t hInstApp          = 0;
    uint64_t lpIDList          = 0;
    uint64_t lpClass           = 0;
    uint64_t hkeyClass         = 0;
    uint32_t dwHotKey          = 0;
    uint32_t _align2           = 0;
    uint64_t DummyUnionName    = 0;
    uint64_t handle            = 0;

    size_t sizeof_obj() const override { return 112; }
    std::vector<uint8_t> get_bytes() const override {
        std::vector<uint8_t> b(112);
        speakeasy::write_le(b, 0,   cbSize,         4);
        speakeasy::write_le(b, 4,   fMask,          4);
        speakeasy::write_le(b, 8,   hwnd,           8);
        speakeasy::write_le(b, 16,  lpVerb,         8);
        speakeasy::write_le(b, 24,  lpFile,         8);
        speakeasy::write_le(b, 32,  lpParameters,   8);
        speakeasy::write_le(b, 40,  lpDirectory,    8);
        speakeasy::write_le(b, 48,  nShow,          4);
        speakeasy::write_le(b, 56,  hInstApp,       8);
        speakeasy::write_le(b, 64,  lpIDList,       8);
        speakeasy::write_le(b, 72,  lpClass,        8);
        speakeasy::write_le(b, 80,  hkeyClass,      8);
        speakeasy::write_le(b, 88,  dwHotKey,       4);
        speakeasy::write_le(b, 96,  DummyUnionName, 8);
        speakeasy::write_le(b, 104, handle,         8);
        return b;
    }
};

}}} // namespace speakeasy::defs::windows

#endif // SPEAKEASY_DEFS_WINDOWS_SHELL32_H
