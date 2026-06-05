// kernel32.h  Windows KERNEL32 type definitions (new EmuStructHelper CRTP)
//
// Maps to: speakeasy/winenv/defs/windows/kernel32.py
//
// Uses the new EmuStructHelper CRTP approach for auto serialize/deserialize.
// All structs use #pragma pack(push, 1).
//
// Namespace speakeasy::defs::new_structs to avoid conflicts with existing defs.

#ifndef SPEAKEASY_DEFS_NEW_WINDOWS_KERNEL32_H
#define SPEAKEASY_DEFS_NEW_WINDOWS_KERNEL32_H

#include <cstdint>
#include <string>
#include "struct.h"

namespace speakeasy { namespace defs { namespace new_structs {

#pragma pack(push, 1)

// ==========================================================================================================
// Constants
// ==========================================================================================================
#ifndef SPEAKEASY_DEFS_NEW_WINSOCK_WS2_32_H
constexpr int kWSADescriptionLen     = 256;
constexpr int kWSASysStatusLen       = 128;
#endif
constexpr int kMaxPath               = 260;
constexpr int kMaxModuleName32       = 255;
constexpr int kFileAttributeNormal   = 0x80;

constexpr int kTh32csInherit      = 0x80000000;
constexpr int kTh32csSnapHeapList = 0x00000001;
constexpr int kTh32csSnapModule   = 0x00000008;
constexpr int kTh32csSnapModule32 = 0x00000010;
constexpr int kTh32csSnapProcess  = 0x00000002;
constexpr int kTh32csSnapThread   = 0x00000004;

constexpr int kProcessorArchitectureAmd64 = 9;
constexpr int kProcessorArchitectureIntel = 0;

// ==========================================================================================================
// FILETIME: 8 bytes (2*uint32)
// ==========================================================================================================
struct FILETIME_POD {
    uint32_t dwLowDateTime  = 0; // offset 0
    uint32_t dwHighDateTime = 0; // offset 4
    // total = 8
};
struct FILETIME : public EmuStructHelper<FILETIME>, public FILETIME_POD {
    std::string get_mem_tag() const override { return "filetime"; }
};

// ==========================================================================================================
// PROCESSENTRY32: ptr-size polymorphic (has Ptr field th32DefaultHeapID)
// x86: dwSize(4)+cntUsage(4)+th32ProcessID(4)+th32DefaultHeapID(4)+th32ModuleID(4)+cntThreads(4)
//      +th32ParentProcessID(4)+pcPriClassBase(4)+dwFlags(4)+szExeFile(260) = 296
// x64: dwSize(4)+cntUsage(4)+th32ProcessID(4)+pad(4)+th32DefaultHeapID(8)+th32ModuleID(4)+cntThreads(4)
//      +th32ParentProcessID(4)+pcPriClassBase(4)+dwFlags(4)+szExeFile(260) = 304
// ==========================================================================================================
template <int PtrSize>
struct PROCESSENTRY32_POD;

template <>
struct PROCESSENTRY32_POD<4> {
    uint32_t dwSize              = 0;   // offset   0
    uint32_t cntUsage            = 0;   // offset   4
    uint32_t th32ProcessID       = 0;   // offset   8
    uint32_t th32DefaultHeapID   = 0;   // offset  12
    uint32_t th32ModuleID        = 0;   // offset  16
    uint32_t cntThreads          = 0;   // offset  20
    uint32_t th32ParentProcessID = 0;   // offset  24
    uint32_t pcPriClassBase      = 0;   // offset  28
    uint32_t dwFlags             = 0;   // offset  32
    uint8_t  szExeFile[260]      = {};  // offset  36
    // total = 296
};

template <>
struct PROCESSENTRY32_POD<8> {
    uint32_t dwSize              = 0;   // offset   0
    uint32_t cntUsage            = 0;   // offset   4
    uint32_t th32ProcessID       = 0;   // offset   8
    uint32_t pad1                = 0;   // offset  12 → align th32DefaultHeapID
    uint64_t th32DefaultHeapID   = 0;   // offset  16
    uint32_t th32ModuleID        = 0;   // offset  24
    uint32_t cntThreads          = 0;   // offset  28
    uint32_t th32ParentProcessID = 0;   // offset  32
    uint32_t pcPriClassBase      = 0;   // offset  36
    uint32_t dwFlags             = 0;   // offset  40
    uint8_t  szExeFile[260]      = {};  // offset  44
    // total = 304
};

template <int PtrSize>
struct PROCESSENTRY32 : public EmuStructHelper<PROCESSENTRY32<PtrSize>>, public PROCESSENTRY32_POD<PtrSize> {
    std::string get_mem_tag() const override { return "processentry32"; }
};

// ==========================================================================================================
// THREADENTRY32: fixed-size, 28 bytes (7*uint32)
// ==========================================================================================================
struct THREADENTRY32_POD {
    uint32_t dwSize              = 0;   // offset  0
    uint32_t cntUsage            = 0;   // offset  4
    uint32_t th32ThreadID        = 0;   // offset  8
    uint32_t th32OwnerProcessID  = 0;   // offset 12
    uint32_t tpBasePri           = 0;   // offset 16
    uint32_t tpDeltaPri          = 0;   // offset 20
    uint32_t dwFlags             = 0;   // offset 24
    // total = 28
};
struct THREADENTRY32 : public EmuStructHelper<THREADENTRY32>, public THREADENTRY32_POD {
    std::string get_mem_tag() const override { return "threadentry32"; }
};

// ==========================================================================================================
// MODULEENTRY32: ptr-size polymorphic (has Ptr field modBaseAddr)
// x86: dwSize(4)+th32ModuleID(4)+th32ProcessID(4)+GlblcntUsage(4)+ProccntUsage(4)+modBaseAddr(4)
//      +modBaseSize(4)+hModule(4)+szModule(256)+szExePath(260) = 548
// x64: dwSize(4)+th32ModuleID(4)+th32ProcessID(4)+GlblcntUsage(4)+ProccntUsage(4)+pad(4)
//      +modBaseAddr(8)+modBaseSize(4)+hModule(4)+szModule(256)+szExePath(260) = 556
// ==========================================================================================================
template <int PtrSize>
struct MODULEENTRY32_POD;

template <>
struct MODULEENTRY32_POD<4> {
    uint32_t dwSize              = 0;   // offset   0
    uint32_t th32ModuleID        = 0;   // offset   4
    uint32_t th32ProcessID       = 0;   // offset   8
    uint32_t GlblcntUsage        = 0;   // offset  12
    uint32_t ProccntUsage        = 0;   // offset  16
    uint32_t modBaseAddr         = 0;   // offset  20
    uint32_t modBaseSize         = 0;   // offset  24
    uint32_t hModule             = 0;   // offset  28
    uint8_t  szModule[256]       = {};  // offset  32
    uint8_t  szExePath[260]      = {};  // offset 288
    // total = 548
};

template <>
struct MODULEENTRY32_POD<8> {
    uint32_t dwSize              = 0;   // offset   0
    uint32_t th32ModuleID        = 0;   // offset   4
    uint32_t th32ProcessID       = 0;   // offset   8
    uint32_t GlblcntUsage        = 0;   // offset  12
    uint32_t ProccntUsage        = 0;   // offset  16
    uint32_t pad1                = 0;   // offset  20 → align modBaseAddr
    uint64_t modBaseAddr         = 0;   // offset  24
    uint32_t modBaseSize         = 0;   // offset  32
    uint32_t pad2                = 0;   // offset  36 → align hModule
    uint64_t hModule             = 0;   // offset  40
    uint8_t  szModule[256]       = {};  // offset  48
    uint8_t  szExePath[260]      = {};  // offset 304
    uint32_t pad3                = 0;   // offset 564 → trailing 8-byte struct alignment
    // total = 568
};

template <int PtrSize>
struct MODULEENTRY32 : public EmuStructHelper<MODULEENTRY32<PtrSize>>, public MODULEENTRY32_POD<PtrSize> {
    std::string get_mem_tag() const override { return "moduleentry32"; }
};

// ==========================================================================================================
// PROCESS_INFORMATION: ptr-size polymorphic
// x86: hProcess(4)+hThread(4)+dwProcessId(4)+dwThreadId(4) = 16
// x64: hProcess(8)+hThread(8)+dwProcessId(4)+dwThreadId(4) = 24
// ==========================================================================================================
template <int PtrSize>
struct PROCESS_INFORMATION_POD;

template <>
struct PROCESS_INFORMATION_POD<4> {
    uint32_t hProcess    = 0;   // offset 0
    uint32_t hThread     = 0;   // offset 4
    uint32_t dwProcessId = 0;   // offset 8
    uint32_t dwThreadId  = 0;   // offset 12
    // total = 16
};

template <>
struct PROCESS_INFORMATION_POD<8> {
    uint64_t hProcess    = 0;   // offset 0
    uint64_t hThread     = 0;   // offset 8
    uint32_t dwProcessId = 0;   // offset 16
    uint32_t dwThreadId  = 0;   // offset 20
    // total = 24
};

template <int PtrSize>
struct PROCESS_INFORMATION : public EmuStructHelper<PROCESS_INFORMATION<PtrSize>>, public PROCESS_INFORMATION_POD<PtrSize> {
    std::string get_mem_tag() const override { return "process_information"; }
};

// ==========================================================================================================
// MEMORY_BASIC_INFORMATION: ptr-size polymorphic
// x86: BaseAddress(4)+AllocationBase(4)+AllocationProtect(4)+RegionSize(4)+State(4)+Protect(4)+Type(4) = 28
// x64: BaseAddress(8)+AllocationBase(8)+AllocationProtect(4)+pad(4)+RegionSize(8)+State(4)+Protect(4)+Type(4) = 44
// ==========================================================================================================
template <int PtrSize>
struct MEMORY_BASIC_INFORMATION_POD;

template <>
struct MEMORY_BASIC_INFORMATION_POD<4> {
    uint32_t BaseAddress        = 0;   // offset  0
    uint32_t AllocationBase     = 0;   // offset  4
    uint32_t AllocationProtect  = 0;   // offset  8
    uint32_t RegionSize         = 0;   // offset 12
    uint32_t State              = 0;   // offset 16
    uint32_t Protect            = 0;   // offset 20
    uint32_t Type               = 0;   // offset 24
    // total = 28
};

template <>
struct MEMORY_BASIC_INFORMATION_POD<8> {
    uint64_t BaseAddress        = 0;   // offset  0
    uint64_t AllocationBase     = 0;   // offset  8
    uint32_t AllocationProtect  = 0;   // offset 16
    uint32_t pad1               = 0;   // offset 20 → align RegionSize
    uint64_t RegionSize         = 0;   // offset 24
    uint32_t State              = 0;   // offset 32
    uint32_t Protect            = 0;   // offset 36
    uint32_t Type               = 0;   // offset 40
    uint32_t pad2               = 0;   // offset 44 → trailing pad for 8-byte struct alignment
    // total = 48
};

template <int PtrSize>
struct MEMORY_BASIC_INFORMATION : public EmuStructHelper<MEMORY_BASIC_INFORMATION<PtrSize>>, public MEMORY_BASIC_INFORMATION_POD<PtrSize> {
    std::string get_mem_tag() const override { return "memory_basic_information"; }
};

// ==========================================================================================================
// WIN32_FIND_DATA: fixed-size (no Ptr fields, has embedded FILETIME)
// dwFileAttributes(4)+ftCreationTime(8)+ftLastAccessTime(8)+ftLastWriteTime(8)
// +nFileSizeHigh(4)+nFileSizeLow(4)+dwReserved0(4)+dwReserved1(4)+cFileName(260)+cAlternateFileName(14)
// = 318
// ==========================================================================================================
struct WIN32_FIND_DATA_POD {
    uint32_t dwFileAttributes            = 0;   // offset   0
    FILETIME_POD ftCreationTime;                // offset   4 (8 bytes)
    FILETIME_POD ftLastAccessTime;              // offset  12 (8 bytes)
    FILETIME_POD ftLastWriteTime;               // offset  20 (8 bytes)
    uint32_t nFileSizeHigh              = 0;   // offset  28
    uint32_t nFileSizeLow               = 0;   // offset  32
    uint32_t dwReserved0                = 0;   // offset  36
    uint32_t dwReserved1                = 0;   // offset  40
    uint8_t  cFileName[260]             = {};  // offset  44
    uint8_t  cAlternateFileName[14]     = {};  // offset 304
    uint8_t  pad[2]                     = {};  // offset 318 → trailing pad
    // total = 320
};
struct WIN32_FIND_DATA : public EmuStructHelper<WIN32_FIND_DATA>, public WIN32_FIND_DATA_POD {
    std::string get_mem_tag() const override { return "win32_find_data"; }
};

// ==========================================================================================================
// WIN32_FILE_ATTRIBUTE_DATA: fixed-size, 36 bytes
// dwFileAttributes(4)+3*FILETIME(24)+2*uint32(8) = 36
// ==========================================================================================================
struct WIN32_FILE_ATTRIBUTE_DATA_POD {
    uint32_t dwFileAttributes                = 0;   // offset  0
    FILETIME_POD ftCreationTime;                    // offset  4 (8 bytes)
    FILETIME_POD ftLastAccessTime;                  // offset 12 (8 bytes)
    FILETIME_POD ftLastWriteTime;                   // offset 20 (8 bytes)
    uint32_t nFileSizeHigh                  = 0;   // offset 28
    uint32_t nFileSizeLow                   = 0;   // offset 32
    // total = 36
};
struct WIN32_FILE_ATTRIBUTE_DATA : public EmuStructHelper<WIN32_FILE_ATTRIBUTE_DATA>, public WIN32_FILE_ATTRIBUTE_DATA_POD {
    std::string get_mem_tag() const override { return "win32_file_attribute_data"; }
};

// ==========================================================================================================
// SYSTEM_INFO: ptr-size polymorphic
// x86: u16(2)+pad(2)+u32(4)+Ptr(4)+Ptr(4)+Ptr(4)+u32(4)+u32(4)+u32(4)+u16(2)+u16(2) = 36
// x64: u16(2)+pad(2)+u32(4)+pad(4)+Ptr(8)+Ptr(8)+Ptr(8)+u32(4)+u32(4)+u32(4)+u16(2)+u16(2) = 52
// ==========================================================================================================
template <int PtrSize>
struct SYSTEM_INFO_POD;

template <>
struct SYSTEM_INFO_POD<4> {
    uint16_t wProcessorArchitecture        = 0;   // offset  0
    uint8_t  _pad0[2]                     = {};  // offset  2 → align dwPageSize to 4
    uint32_t dwPageSize                    = 0;   // offset  4
    uint32_t lpMinimumApplicationAddress   = 0;   // offset  8
    uint32_t lpMaximumApplicationAddress   = 0;   // offset 12
    uint32_t dwActiveProcessorMask         = 0;   // offset 16
    uint32_t dwNumberOfProcessors          = 0;   // offset 20
    uint32_t dwProcessorType               = 0;   // offset 24
    uint32_t dwAllocationGranularity       = 0;   // offset 28
    uint16_t wProcessorLevel               = 0;   // offset 32
    uint16_t wProcessorRevision            = 0;   // offset 34
    // total = 36
};

// x64: 48 bytes
template <>
struct SYSTEM_INFO_POD<8> {
    uint16_t wProcessorArchitecture        = 0;   // offset  0
    uint8_t  _pad0[2]                     = {};  // offset  2 → align dwPageSize to 4
    uint32_t dwPageSize                    = 0;   // offset  4
    uint64_t lpMinimumApplicationAddress   = 0;   // offset  8
    uint64_t lpMaximumApplicationAddress   = 0;   // offset 16
    uint64_t dwActiveProcessorMask         = 0;   // offset 24
    uint32_t dwNumberOfProcessors          = 0;   // offset 32
    uint32_t dwProcessorType               = 0;   // offset 36
    uint32_t dwAllocationGranularity       = 0;   // offset 40
    uint16_t wProcessorLevel               = 0;   // offset 44
    uint16_t wProcessorRevision            = 0;   // offset 46
    // total = 48
};

template <int PtrSize>
struct SYSTEM_INFO : public EmuStructHelper<SYSTEM_INFO<PtrSize>>, public SYSTEM_INFO_POD<PtrSize> {
    std::string get_mem_tag() const override { return "system_info"; }
};

// ==========================================================================================================
// SYSTEMTIME: fixed-size, 16 bytes (8*uint16)
// ==========================================================================================================
struct SYSTEMTIME_POD {
    uint16_t wYear          = 0;   // offset  0
    uint16_t wMonth         = 0;   // offset  2
    uint16_t wDayOfWeek     = 0;   // offset  4
    uint16_t wDay           = 0;   // offset  6
    uint16_t wHour          = 0;   // offset  8
    uint16_t wMinute        = 0;   // offset 10
    uint16_t wSecond        = 0;   // offset 12
    uint16_t wMilliseconds  = 0;   // offset 14
    // total = 16
};
struct SYSTEMTIME : public EmuStructHelper<SYSTEMTIME>, public SYSTEMTIME_POD {
    std::string get_mem_tag() const override { return "systemtime"; }
};

// ==========================================================================================================
// STARTUPINFO: ptr-size polymorphic
// x86: cb(4)+lpReserved(4)+lpDesktop(4)+lpTitle(4)+dwX(4)+dwY(4)+dwXSize(4)+dwYSize(4)
//      +dwXCountChars(4)+dwYCountChars(4)+dwFillAttribute(4)+dwFlags(4)+wShowWindow(2)+cbReserved2(2)
//      +lpReserved2(4)+hStdInput(4)+hStdOutput(4)+hStdError(4) = 68
// x64: cb(4)+pad(4)+lpReserved(8)+lpDesktop(8)+lpTitle(8)+dwX(4)+dwY(4)+dwXSize(4)+dwYSize(4)
//      +dwXCountChars(4)+dwYCountChars(4)+dwFillAttribute(4)+dwFlags(4)+wShowWindow(2)+cbReserved2(2)
//      +pad(4)+lpReserved2(8)+hStdInput(8)+hStdOutput(8)+hStdError(8) = 104
// ==========================================================================================================
template <int PtrSize>
struct STARTUPINFO_POD;

template <>
struct STARTUPINFO_POD<4> {
    uint32_t cb              = 0;   // offset  0
    uint32_t lpReserved      = 0;   // offset  4
    uint32_t lpDesktop       = 0;   // offset  8
    uint32_t lpTitle         = 0;   // offset 12
    uint32_t dwX             = 0;   // offset 16
    uint32_t dwY             = 0;   // offset 20
    uint32_t dwXSize         = 0;   // offset 24
    uint32_t dwYSize         = 0;   // offset 28
    uint32_t dwXCountChars   = 0;   // offset 32
    uint32_t dwYCountChars   = 0;   // offset 36
    uint32_t dwFillAttribute = 0;   // offset 40
    uint32_t dwFlags         = 0;   // offset 44
    uint16_t wShowWindow     = 0;   // offset 48
    uint16_t cbReserved2     = 0;   // offset 50
    uint32_t lpReserved2     = 0;   // offset 52
    uint32_t hStdInput       = 0;   // offset 56
    uint32_t hStdOutput      = 0;   // offset 60
    uint32_t hStdError       = 0;   // offset 64
    // total = 68
};

template <>
struct STARTUPINFO_POD<8> {
    uint32_t cb              = 0;   // offset  0
    uint32_t pad1            = 0;   // offset  4 → align lpReserved
    uint64_t lpReserved      = 0;   // offset  8
    uint64_t lpDesktop       = 0;   // offset 16
    uint64_t lpTitle         = 0;   // offset 24
    uint32_t dwX             = 0;   // offset 32
    uint32_t dwY             = 0;   // offset 36
    uint32_t dwXSize         = 0;   // offset 40
    uint32_t dwYSize         = 0;   // offset 44
    uint32_t dwXCountChars   = 0;   // offset 48
    uint32_t dwYCountChars   = 0;   // offset 52
    uint32_t dwFillAttribute = 0;   // offset 56
    uint32_t dwFlags         = 0;   // offset 60
    uint16_t wShowWindow     = 0;   // offset 64
    uint16_t cbReserved2     = 0;   // offset 66
    uint32_t pad2            = 0;   // offset 68 → align lpReserved2
    uint64_t lpReserved2     = 0;   // offset 72
    uint64_t hStdInput       = 0;   // offset 80
    uint64_t hStdOutput      = 0;   // offset 88
    uint64_t hStdError       = 0;   // offset 96
    // total = 104
};

template <int PtrSize>
struct STARTUPINFO : public EmuStructHelper<STARTUPINFO<PtrSize>>, public STARTUPINFO_POD<PtrSize> {
    std::string get_mem_tag() const override { return "startupinfo"; }
};

// ==========================================================================================================
// OSVERSIONINFO: fixed-size, 148 bytes (5*uint32 + uint8[128])
// ==========================================================================================================
struct OSVERSIONINFO_POD {
    uint32_t dwOSVersionInfoSize = 0;   // offset   0
    uint32_t dwMajorVersion      = 0;   // offset   4
    uint32_t dwMinorVersion      = 0;   // offset   8
    uint32_t dwBuildNumber       = 0;   // offset  12
    uint32_t dwPlatformId        = 0;   // offset  16
    uint8_t  szCSDVersion[128]   = {};  // offset  20
    // total = 148
};
struct OSVERSIONINFO : public EmuStructHelper<OSVERSIONINFO>, public OSVERSIONINFO_POD {
    std::string get_mem_tag() const override { return "osversioninfo"; }
};

// ==========================================================================================================
// OSVERSIONINFOEX: fixed-size, 156 bytes
// Windows: 5*uint32(20) + CHAR[128](128) + 3*uint16(6) + uint8 + uint8 = 156
// ==========================================================================================================
struct OSVERSIONINFOEX_POD {
    // Flattened OSVERSIONINFO (20 + 128 = 148 bytes)
    uint32_t dwOSVersionInfoSize = 0;   // offset   0
    uint32_t dwMajorVersion      = 0;   // offset   4
    uint32_t dwMinorVersion      = 0;   // offset   8
    uint32_t dwBuildNumber       = 0;   // offset  12
    uint32_t dwPlatformId        = 0;   // offset  16
    uint8_t  szCSDVersion[128]   = {};  // offset  20 (128 bytes, CHAR array)
    // Extra fields
    uint16_t wServicePackMajor   = 0;   // offset 148
    uint16_t wServicePackMinor   = 0;   // offset 150
    uint16_t wSuiteMask          = 0;   // offset 152
    uint8_t  wProductType        = 0;   // offset 154
    uint8_t  wReserved           = 0;   // offset 155
    // total = 156
};
struct OSVERSIONINFOEX : public EmuStructHelper<OSVERSIONINFOEX>, public OSVERSIONINFOEX_POD {
    std::string get_mem_tag() const override { return "osversioninfoex"; }
};

#pragma pack(pop)

}}} // namespace speakeasy::defs::new_structs

#endif // SPEAKEASY_DEFS_NEW_WINDOWS_KERNEL32_H
