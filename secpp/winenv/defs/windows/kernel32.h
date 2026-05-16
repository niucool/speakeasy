// kernel32.h — Windows kernel32 API type definitions
//
// Maps to: speakeasy/winenv/defs/windows/kernel32.py
//
// Structures used by kernel32 API handlers and user-mode emulation:
// PROCESSENTRY32, THREADENTRY32, MODULEENTRY32, PROCESS_INFORMATION,
// STARTUPINFO, WIN32_FIND_DATA, OSVERSIONINFO, SECURITY_ATTRIBUTES, OVERLAPPED, etc.

#ifndef SPEAKEASY_DEFS_WINDOWS_KERNEL32_H
#define SPEAKEASY_DEFS_WINDOWS_KERNEL32_H

#include <cstdint>
#include <vector>
#include "../../../struct.h"
#include "windows.h"

namespace speakeasy { namespace defs { namespace windows {

// ── Constants ─────────────────────────────────────────────────

constexpr uint32_t MAX_PATH           = 260;
constexpr uint32_t MAX_MODULE_NAME32  = 255;

// File attributes
constexpr uint32_t FILE_ATTRIBUTE_DIRECTORY = 0x10;
constexpr uint32_t FILE_ATTRIBUTE_NORMAL    = 0x80;

// Toolhelp snapshot flags
constexpr uint32_t TH32CS_INHERIT      = 0x80000000;
constexpr uint32_t TH32CS_SNAPHEAPLIST = 0x00000001;
constexpr uint32_t TH32CS_SNAPMODULE   = 0x00000008;
constexpr uint32_t TH32CS_SNAPMODULE32 = 0x00000010;
constexpr uint32_t TH32CS_SNAPPROCESS  = 0x00000002;
constexpr uint32_t TH32CS_SNAPTHREAD   = 0x00000004;

// Processor architecture
constexpr uint16_t PROCESSOR_ARCHITECTURE_AMD64 = 9;
constexpr uint16_t PROCESSOR_ARCHITECTURE_INTEL = 0;

// Drive types
constexpr uint32_t DRIVE_UNKNOWN      = 0;
constexpr uint32_t DRIVE_NO_ROOT_DIR   = 1;
constexpr uint32_t DRIVE_REMOVABLE    = 2;
constexpr uint32_t DRIVE_FIXED        = 3;
constexpr uint32_t DRIVE_REMOTE       = 4;
constexpr uint32_t DRIVE_CDROM        = 5;
constexpr uint32_t DRIVE_RAMDISK      = 6;

// Computer name format
constexpr uint32_t ComputerNameNetBIOS                   = 0;
constexpr uint32_t ComputerNameDnsHostname               = 1;
constexpr uint32_t ComputerNameDnsDomain                 = 2;
constexpr uint32_t ComputerNameDnsFullyQualified          = 3;
constexpr uint32_t ComputerNamePhysicalNetBIOS            = 4;
constexpr uint32_t ComputerNamePhysicalDnsHostname        = 5;
constexpr uint32_t ComputerNamePhysicalDnsDomain          = 6;
constexpr uint32_t ComputerNamePhysicalDnsFullyQualified  = 7;
constexpr uint32_t ComputerNameMax                       = 8;

// GetFileEx info levels
constexpr uint32_t GetFileExInfoStandard = 0;

// Exception continuation codes
constexpr uint32_t EXCEPTION_CONTINUE_SEARCH  = 0;
constexpr uint32_t EXCEPTION_EXECUTE_HANDLER  = 1;

// Thread priorities
constexpr uint32_t THREAD_PRIORITY_NORMAL = 0;

// Locale constants
constexpr uint32_t LOCALE_INVARIANT            = 0x7F;
constexpr uint32_t LOCALE_USER_DEFAULT         = 0x400;
constexpr uint32_t LOCALE_SYSTEM_DEFAULT       = 0x800;
constexpr uint32_t LOCALE_CUSTOM_DEFAULT       = 0xC00;
constexpr uint32_t LOCALE_CUSTOM_UNSPECIFIED   = 0x1000;
constexpr uint32_t LOCALE_CUSTOM_UI_DEFAULT    = 0x1400;
constexpr uint32_t LOCALE_SENGLISHLANGUAGENAME = 0x1001;
constexpr uint32_t LOCALE_SENGLISHCOUNTRYNAME  = 0x1002;

// ── PROCESS_INFORMATION ───────────────────────────────────────

struct PROCESS_INFORMATION : speakeasy::EmuStruct {
    uint64_t hProcess    = 0;  // HANDLE
    uint64_t hThread     = 0;  // HANDLE
    uint32_t dwProcessId = 0;
    uint32_t dwThreadId  = 0;

    size_t sizeof_obj() const override {
        return (sizeof(uint64_t) == 8) ? 24 : 16;
    }
    std::vector<uint8_t> get_bytes() const override {
        size_t sz = sizeof_obj();
        std::vector<uint8_t> b(sz, 0);
        if (sz == 24) {
            speakeasy::write_le(b, 0,  hProcess, 8);
            speakeasy::write_le(b, 8,  hThread, 8);
            speakeasy::write_le(b, 16, dwProcessId, 4);
            speakeasy::write_le(b, 20, dwThreadId, 4);
        } else {
            speakeasy::write_le(b, 0, hProcess, 4);
            speakeasy::write_le(b, 4, hThread, 4);
            speakeasy::write_le(b, 8, dwProcessId, 4);
            speakeasy::write_le(b, 12, dwThreadId, 4);
        }
        return b;
    }
};

// ── STARTUPINFO ───────────────────────────────────────────────

struct STARTUPINFO : speakeasy::EmuStruct {
    uint32_t cb              = sizeof(STARTUPINFO);
    uint64_t lpReserved      = 0;  // LPWSTR
    uint64_t lpDesktop       = 0;  // LPWSTR
    uint64_t lpTitle         = 0;  // LPWSTR
    uint32_t dwX             = 0;
    uint32_t dwY             = 0;
    uint32_t dwXSize         = 0;
    uint32_t dwYSize         = 0;
    uint32_t dwXCountChars   = 0;
    uint32_t dwYCountChars   = 0;
    uint32_t dwFillAttribute = 0;
    uint32_t dwFlags         = 0;
    uint16_t wShowWindow     = 0;
    uint16_t cbReserved2     = 0;
    uint64_t lpReserved2     = 0;  // LPBYTE
    uint64_t hStdInput       = 0;  // HANDLE
    uint64_t hStdOutput      = 0;  // HANDLE
    uint64_t hStdError       = 0;  // HANDLE

    size_t sizeof_obj() const override {
        return (sizeof(uint64_t) == 8) ? 104 : 68;
    }
    std::vector<uint8_t> get_bytes() const override {
        size_t sz = sizeof_obj();
        std::vector<uint8_t> b(sz, 0);
        speakeasy::write_le(b, 0, cb, 4);
        if (sz == 104) {
            // x64 layout
            speakeasy::write_le(b, 4,  0, 4);  // padding
            speakeasy::write_le(b, 8,  lpReserved, 8);
            speakeasy::write_le(b, 16, lpDesktop, 8);
            speakeasy::write_le(b, 24, lpTitle, 8);
            speakeasy::write_le(b, 32, dwX, 4);
            speakeasy::write_le(b, 36, dwY, 4);
            speakeasy::write_le(b, 40, dwXSize, 4);
            speakeasy::write_le(b, 44, dwYSize, 4);
            speakeasy::write_le(b, 48, dwXCountChars, 4);
            speakeasy::write_le(b, 52, dwYCountChars, 4);
            speakeasy::write_le(b, 56, dwFillAttribute, 4);
            speakeasy::write_le(b, 60, dwFlags, 4);
            speakeasy::write_le(b, 64, wShowWindow, 2);
            speakeasy::write_le(b, 66, cbReserved2, 2);
            speakeasy::write_le(b, 68, lpReserved2, 8);
            speakeasy::write_le(b, 76, hStdInput, 8);
            speakeasy::write_le(b, 84, hStdOutput, 8);
            speakeasy::write_le(b, 92, hStdError, 8);
        } else {
            // x86 layout
            speakeasy::write_le(b, 4,  lpReserved, 4);
            speakeasy::write_le(b, 8,  lpDesktop, 4);
            speakeasy::write_le(b, 12, lpTitle, 4);
            speakeasy::write_le(b, 16, dwX, 4);
            speakeasy::write_le(b, 20, dwY, 4);
            speakeasy::write_le(b, 24, dwXSize, 4);
            speakeasy::write_le(b, 28, dwYSize, 4);
            speakeasy::write_le(b, 32, dwXCountChars, 4);
            speakeasy::write_le(b, 36, dwYCountChars, 4);
            speakeasy::write_le(b, 40, dwFillAttribute, 4);
            speakeasy::write_le(b, 44, dwFlags, 4);
            speakeasy::write_le(b, 48, wShowWindow, 2);
            speakeasy::write_le(b, 50, cbReserved2, 2);
            speakeasy::write_le(b, 52, lpReserved2, 4);
            speakeasy::write_le(b, 56, hStdInput, 4);
            speakeasy::write_le(b, 60, hStdOutput, 4);
            speakeasy::write_le(b, 64, hStdError, 4);
        }
        return b;
    }
};

// ── PROCESSENTRY32 (Wide-character, Toolhelp API) ─────────────

struct PROCESSENTRY32 : speakeasy::EmuStruct {
    uint32_t dwSize              = sizeof(PROCESSENTRY32);
    uint32_t cntUsage            = 0;
    uint32_t th32ProcessID       = 0;
    uint64_t th32DefaultHeapID   = 0;  // ULONG_PTR
    uint32_t th32ModuleID        = 0;
    uint32_t cntThreads          = 0;
    uint32_t th32ParentProcessID = 0;
    int32_t  pcPriClassBase      = 0;
    uint32_t dwFlags             = 0;
    uint16_t szExeFile[260]      = {};  // WCHAR[MAX_PATH]

    size_t sizeof_obj() const override {
        return (sizeof(uint64_t) == 8) ? 568 : 556;
    }
    std::vector<uint8_t> get_bytes() const override {
        size_t sz = sizeof_obj();
        std::vector<uint8_t> b(sz, 0);
        speakeasy::write_le(b, 0, dwSize, 4);
        speakeasy::write_le(b, 4, cntUsage, 4);
        speakeasy::write_le(b, 8, th32ProcessID, 4);
        if (sz == 568) {
            // x64: padding before ULONG_PTR
            speakeasy::write_le(b, 12, 0, 4);  // padding
            speakeasy::write_le(b, 16, th32DefaultHeapID, 8);
            speakeasy::write_le(b, 24, th32ModuleID, 4);
            speakeasy::write_le(b, 28, cntThreads, 4);
            speakeasy::write_le(b, 32, th32ParentProcessID, 4);
            speakeasy::write_le(b, 36, pcPriClassBase, 4);
            speakeasy::write_le(b, 40, dwFlags, 4);
            // szExeFile starts at offset 48
            for (size_t i = 0; i < 260; ++i)
                speakeasy::write_le(b, 48 + i * 2, szExeFile[i], 2);
        } else {
            // x86: ULONG_PTR is 4 bytes, no padding
            speakeasy::write_le(b, 12, th32DefaultHeapID, 4);
            speakeasy::write_le(b, 16, th32ModuleID, 4);
            speakeasy::write_le(b, 20, cntThreads, 4);
            speakeasy::write_le(b, 24, th32ParentProcessID, 4);
            speakeasy::write_le(b, 28, pcPriClassBase, 4);
            speakeasy::write_le(b, 32, dwFlags, 4);
            // szExeFile starts at offset 36
            for (size_t i = 0; i < 260; ++i)
                speakeasy::write_le(b, 36 + i * 2, szExeFile[i], 2);
        }
        return b;
    }
};

// ── THREADENTRY32 (Toolhelp API) ──────────────────────────────

struct THREADENTRY32 : speakeasy::EmuStruct {
    uint32_t dwSize              = sizeof(THREADENTRY32);
    uint32_t cntUsage            = 0;
    uint32_t th32ThreadID        = 0;
    uint32_t th32OwnerProcessID  = 0;
    int32_t  tpBasePri           = 0;
    int32_t  tpDeltaPri          = 0;
    uint32_t dwFlags             = 0;

    size_t sizeof_obj() const override { return 28; }
    std::vector<uint8_t> get_bytes() const override {
        std::vector<uint8_t> b(28, 0);
        speakeasy::write_le(b, 0,  dwSize, 4);
        speakeasy::write_le(b, 4,  cntUsage, 4);
        speakeasy::write_le(b, 8,  th32ThreadID, 4);
        speakeasy::write_le(b, 12, th32OwnerProcessID, 4);
        speakeasy::write_le(b, 16, tpBasePri, 4);
        speakeasy::write_le(b, 20, tpDeltaPri, 4);
        speakeasy::write_le(b, 24, dwFlags, 4);
        return b;
    }
};

// ── MODULEENTRY32 (Wide-character, Toolhelp API) ──────────────

struct MODULEENTRY32 : speakeasy::EmuStruct {
    uint32_t dwSize              = sizeof(MODULEENTRY32);
    uint32_t th32ModuleID        = 0;
    uint32_t th32ProcessID       = 0;
    uint32_t GlblcntUsage        = 0;
    uint32_t ProccntUsage        = 0;
    uint64_t modBaseAddr         = 0;  // uint8_t*
    uint32_t modBaseSize         = 0;
    uint32_t hModule             = 0;  // HMODULE (32-bit in all toolhelp APIs)
    uint16_t szModule[256]       = {};  // WCHAR[MAX_MODULE_NAME32 + 1]
    uint16_t szExePath[260]      = {};  // WCHAR[MAX_PATH]

    size_t sizeof_obj() const override {
        return (sizeof(uint64_t) == 8) ? 1072 : 1060;
    }
    std::vector<uint8_t> get_bytes() const override {
        size_t sz = sizeof_obj();
        std::vector<uint8_t> b(sz, 0);
        speakeasy::write_le(b, 0, dwSize, 4);
        speakeasy::write_le(b, 4, th32ModuleID, 4);
        speakeasy::write_le(b, 8, th32ProcessID, 4);
        speakeasy::write_le(b, 12, GlblcntUsage, 4);
        speakeasy::write_le(b, 16, ProccntUsage, 4);
        if (sz == 1072) {
            // x64: padding before pointer
            speakeasy::write_le(b, 20, 0, 4);
            speakeasy::write_le(b, 24, modBaseAddr, 8);
            speakeasy::write_le(b, 32, modBaseSize, 4);
            speakeasy::write_le(b, 36, hModule, 4);
            // szModule at offset 40
            for (size_t i = 0; i < 256; ++i)
                speakeasy::write_le(b, 40 + i * 2, szModule[i], 2);
            // szExePath at offset 40 + 512 = 552
            for (size_t i = 0; i < 260; ++i)
                speakeasy::write_le(b, 552 + i * 2, szExePath[i], 2);
        } else {
            // x86: no padding
            speakeasy::write_le(b, 20, modBaseAddr, 4);
            speakeasy::write_le(b, 24, modBaseSize, 4);
            speakeasy::write_le(b, 28, hModule, 4);
            // szModule at offset 32
            for (size_t i = 0; i < 256; ++i)
                speakeasy::write_le(b, 32 + i * 2, szModule[i], 2);
            // szExePath at offset 32 + 512 = 544
            for (size_t i = 0; i < 260; ++i)
                speakeasy::write_le(b, 544 + i * 2, szExePath[i], 2);
        }
        return b;
    }
};

// ── WIN32_FIND_DATA (Wide-character) ──────────────────────────

struct WIN32_FIND_DATA : speakeasy::EmuStruct {
    uint32_t dwFileAttributes    = 0;
    FILETIME ftCreationTime;
    FILETIME ftLastAccessTime;
    FILETIME ftLastWriteTime;
    uint32_t nFileSizeHigh       = 0;
    uint32_t nFileSizeLow        = 0;
    uint32_t dwReserved0         = 0;
    uint32_t dwReserved1         = 0;
    uint16_t cFileName[260]      = {};  // WCHAR[MAX_PATH]
    uint16_t cAlternateFileName[14] = {};  // WCHAR[14]

    size_t sizeof_obj() const override { return 592; }
    std::vector<uint8_t> get_bytes() const override {
        constexpr size_t SZ = 592;
        std::vector<uint8_t> b(SZ, 0);
        size_t off = 0;
        speakeasy::write_le(b, 0,  dwFileAttributes, 4);
        // ftCreationTime at 4 (FILETIME = 8 bytes)
        auto ft1 = ftCreationTime.get_bytes();
        std::copy(ft1.begin(), ft1.end(), b.begin() + 4);
        // ftLastAccessTime at 12 (FILETIME = 8 bytes)
        auto ft2 = ftLastAccessTime.get_bytes();
        std::copy(ft2.begin(), ft2.end(), b.begin() + 12);
        // ftLastWriteTime at 20 (FILETIME = 8 bytes)
        auto ft3 = ftLastWriteTime.get_bytes();
        std::copy(ft3.begin(), ft3.end(), b.begin() + 20);
        speakeasy::write_le(b, 28, nFileSizeHigh, 4);
        speakeasy::write_le(b, 32, nFileSizeLow, 4);
        speakeasy::write_le(b, 36, dwReserved0, 4);
        speakeasy::write_le(b, 40, dwReserved1, 4);
        // cFileName at offset 44
        for (size_t i = 0; i < 260; ++i)
            speakeasy::write_le(b, 44 + i * 2, cFileName[i], 2);
        // cAlternateFileName at offset 44 + 520 = 564
        for (size_t i = 0; i < 14; ++i)
            speakeasy::write_le(b, 564 + i * 2, cAlternateFileName[i], 2);
        return b;
    }
};

// ── WIN32_FILE_ATTRIBUTE_DATA ─────────────────────────────────

struct WIN32_FILE_ATTRIBUTE_DATA : speakeasy::EmuStruct {
    uint32_t dwFileAttributes    = 0;
    FILETIME ftCreationTime;
    FILETIME ftLastAccessTime;
    FILETIME ftLastWriteTime;
    uint32_t nFileSizeHigh       = 0;
    uint32_t nFileSizeLow        = 0;

    size_t sizeof_obj() const override { return 36; }
    std::vector<uint8_t> get_bytes() const override {
        std::vector<uint8_t> b(36, 0);
        speakeasy::write_le(b, 0, dwFileAttributes, 4);
        auto ft1 = ftCreationTime.get_bytes();
        std::copy(ft1.begin(), ft1.end(), b.begin() + 4);
        auto ft2 = ftLastAccessTime.get_bytes();
        std::copy(ft2.begin(), ft2.end(), b.begin() + 12);
        auto ft3 = ftLastWriteTime.get_bytes();
        std::copy(ft3.begin(), ft3.end(), b.begin() + 20);
        speakeasy::write_le(b, 28, nFileSizeHigh, 4);
        speakeasy::write_le(b, 32, nFileSizeLow, 4);
        return b;
    }
};

// ── OSVERSIONINFO ─────────────────────────────────────────────

struct OSVERSIONINFO : speakeasy::EmuStruct {
    uint32_t dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
    uint32_t dwMajorVersion      = 0;
    uint32_t dwMinorVersion      = 0;
    uint32_t dwBuildNumber       = 0;
    uint32_t dwPlatformId        = 0;
    uint8_t  szCSDVersion[128]   = {};  // CHAR[128]

    size_t sizeof_obj() const override { return 148; }
    std::vector<uint8_t> get_bytes() const override {
        std::vector<uint8_t> b(148, 0);
        speakeasy::write_le(b, 0,  dwOSVersionInfoSize, 4);
        speakeasy::write_le(b, 4,  dwMajorVersion, 4);
        speakeasy::write_le(b, 8,  dwMinorVersion, 4);
        speakeasy::write_le(b, 12, dwBuildNumber, 4);
        speakeasy::write_le(b, 16, dwPlatformId, 4);
        for (size_t i = 0; i < 128; ++i)
            b[20 + i] = szCSDVersion[i];
        return b;
    }
};

// ── OSVERSIONINFOEX ───────────────────────────────────────────

struct OSVERSIONINFOEX : speakeasy::EmuStruct {
    uint32_t dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
    uint32_t dwMajorVersion      = 0;
    uint32_t dwMinorVersion      = 0;
    uint32_t dwBuildNumber       = 0;
    uint32_t dwPlatformId        = 0;
    uint8_t  szCSDVersion[128]   = {};
    uint16_t wServicePackMajor   = 0;
    uint16_t wServicePackMinor   = 0;
    uint16_t wSuiteMask          = 0;
    uint8_t  wProductType        = 0;
    uint8_t  wReserved           = 0;

    size_t sizeof_obj() const override { return 156; }
    std::vector<uint8_t> get_bytes() const override {
        std::vector<uint8_t> b(156, 0);
        speakeasy::write_le(b, 0,   dwOSVersionInfoSize, 4);
        speakeasy::write_le(b, 4,   dwMajorVersion, 4);
        speakeasy::write_le(b, 8,   dwMinorVersion, 4);
        speakeasy::write_le(b, 12,  dwBuildNumber, 4);
        speakeasy::write_le(b, 16,  dwPlatformId, 4);
        for (size_t i = 0; i < 128; ++i)
            b[20 + i] = szCSDVersion[i];
        speakeasy::write_le(b, 148, wServicePackMajor, 2);
        speakeasy::write_le(b, 150, wServicePackMinor, 2);
        speakeasy::write_le(b, 152, wSuiteMask, 2);
        speakeasy::write_le(b, 154, wProductType, 1);
        speakeasy::write_le(b, 155, wReserved, 1);
        return b;
    }
};

// ── SECURITY_ATTRIBUTES ───────────────────────────────────────

struct SECURITY_ATTRIBUTES : speakeasy::EmuStruct {
    uint32_t nLength              = sizeof(SECURITY_ATTRIBUTES);
    uint64_t lpSecurityDescriptor = 0;  // LPVOID
    int32_t  bInheritHandle       = 0;  // BOOL

    size_t sizeof_obj() const override {
        return (sizeof(uint64_t) == 8) ? 24 : 12;
    }
    std::vector<uint8_t> get_bytes() const override {
        size_t sz = sizeof_obj();
        std::vector<uint8_t> b(sz, 0);
        speakeasy::write_le(b, 0, nLength, 4);
        if (sz == 24) {
            speakeasy::write_le(b, 4,  0, 4);  // padding
            speakeasy::write_le(b, 8,  lpSecurityDescriptor, 8);
            speakeasy::write_le(b, 16, bInheritHandle, 4);
        } else {
            speakeasy::write_le(b, 4, lpSecurityDescriptor, 4);
            speakeasy::write_le(b, 8, bInheritHandle, 4);
        }
        return b;
    }
};

// ── OVERLAPPED ────────────────────────────────────────────────

struct OVERLAPPED : speakeasy::EmuStruct {
    uint64_t Internal     = 0;  // ULONG_PTR
    uint64_t InternalHigh = 0;  // ULONG_PTR
    uint32_t Offset       = 0;  // DWORD
    uint32_t OffsetHigh   = 0;  // DWORD
    uint64_t hEvent       = 0;  // HANDLE

    size_t sizeof_obj() const override {
        return (sizeof(uint64_t) == 8) ? 32 : 20;
    }
    std::vector<uint8_t> get_bytes() const override {
        size_t sz = sizeof_obj();
        std::vector<uint8_t> b(sz, 0);
        if (sz == 32) {
            speakeasy::write_le(b, 0,  Internal, 8);
            speakeasy::write_le(b, 8,  InternalHigh, 8);
            speakeasy::write_le(b, 16, Offset, 4);
            speakeasy::write_le(b, 20, OffsetHigh, 4);
            speakeasy::write_le(b, 24, 0, 4);  // padding
            speakeasy::write_le(b, 28, hEvent, 8);
        } else {
            speakeasy::write_le(b, 0, Internal, 4);
            speakeasy::write_le(b, 4, InternalHigh, 4);
            // Offset and OffsetHigh packed at 8, the union Pointer overlays
            speakeasy::write_le(b, 8, Offset, 4);
            speakeasy::write_le(b, 12, OffsetHigh, 4);
            speakeasy::write_le(b, 16, hEvent, 4);
        }
        return b;
    }
};

}}} // namespaces

#endif // SPEAKEASY_DEFS_WINDOWS_KERNEL32_H
