// windows.h  Common Windows user-mode type definitions
//
// Maps to: speakeasy/winenv/defs/windows/windows.py

#ifndef SPEAKEASY_DEFS_WINDOWS_H
#define SPEAKEASY_DEFS_WINDOWS_H

#include <cstdint>
#include <vector>
#include "../../../struct.h"

//
// Platform compatibility:
// - On Linux/macOS: uses our EmuStruct-based POD structs for serialization
// - On Windows: the system <windows.h> already provides these types.
//   This header is NOT included when the real SDK types are available.
//   Code should use `#ifdef _WIN32` to select the appropriate type source.

#ifndef _WIN32
// Use our custom EmuStruct-based types on non-Windows platforms

namespace speakeasy { namespace defs { namespace windows {

//  FILETIME 

struct FILETIME : speakeasy::EmuStruct {
    uint32_t dwLowDateTime  = 0;
    uint32_t dwHighDateTime = 0;

    size_t sizeof_obj() const override { return 8; }
    std::vector<uint8_t> get_bytes() const override {
        std::vector<uint8_t> b(8);
        speakeasy::write_le(b, 0, dwLowDateTime, 4);
        speakeasy::write_le(b, 4, dwHighDateTime, 4);
        return b;
    }
};

//  SYSTEMTIME 

struct SYSTEMTIME : speakeasy::EmuStruct {
    uint16_t wYear         = 0;
    uint16_t wMonth        = 0;
    uint16_t wDayOfWeek    = 0;
    uint16_t wDay          = 0;
    uint16_t wHour         = 0;
    uint16_t wMinute       = 0;
    uint16_t wSecond       = 0;
    uint16_t wMilliseconds = 0;

    size_t sizeof_obj() const override { return 16; }
    std::vector<uint8_t> get_bytes() const override {
        std::vector<uint8_t> b(16);
        speakeasy::write_le(b, 0,  wYear, 2);
        speakeasy::write_le(b, 2,  wMonth, 2);
        speakeasy::write_le(b, 4,  wDayOfWeek, 2);
        speakeasy::write_le(b, 6,  wDay, 2);
        speakeasy::write_le(b, 8,  wHour, 2);
        speakeasy::write_le(b, 10, wMinute, 2);
        speakeasy::write_le(b, 12, wSecond, 2);
        speakeasy::write_le(b, 14, wMilliseconds, 2);
        return b;
    }
};

//  SYSTEM_INFO 

struct SYSTEM_INFO : speakeasy::EmuStruct {
    uint16_t wProcessorArchitecture = 0;
    uint16_t wReserved              = 0;
    uint32_t dwPageSize             = 0x1000;
    uint64_t lpMinimumApplicationAddress = 0;
    uint64_t lpMaximumApplicationAddress = 0;
    uint64_t dwActiveProcessorMask  = 0;
    uint32_t dwNumberOfProcessors   = 1;
    uint32_t dwProcessorType        = 0;
    uint32_t dwAllocationGranularity = 0x10000;
    uint16_t wProcessorLevel        = 0;
    uint16_t wProcessorRevision     = 0;

    size_t sizeof_obj() const override {
        return (sizeof(uint64_t) == 8) ? 48 : 36;
    }
    std::vector<uint8_t> get_bytes() const override {
        size_t sz = sizeof_obj();
        std::vector<uint8_t> b(sz, 0);
        speakeasy::write_le(b, 0, wProcessorArchitecture, 2);
        speakeasy::write_le(b, 2, wReserved, 2);
        speakeasy::write_le(b, 4, dwPageSize, 4);
        if (sz == 48) {
            speakeasy::write_le(b, 8,  lpMinimumApplicationAddress, 8);
            speakeasy::write_le(b, 16, lpMaximumApplicationAddress, 8);
            speakeasy::write_le(b, 24, dwActiveProcessorMask, 8);
            speakeasy::write_le(b, 32, dwNumberOfProcessors, 4);
            speakeasy::write_le(b, 36, dwProcessorType, 4);
            speakeasy::write_le(b, 40, dwAllocationGranularity, 4);
            speakeasy::write_le(b, 44, wProcessorLevel, 2);
            speakeasy::write_le(b, 46, wProcessorRevision, 2);
        } else {
            speakeasy::write_le(b, 8,  lpMinimumApplicationAddress, 4);
            speakeasy::write_le(b, 12, lpMaximumApplicationAddress, 4);
            speakeasy::write_le(b, 16, dwActiveProcessorMask, 4);
            speakeasy::write_le(b, 20, dwNumberOfProcessors, 4);
            speakeasy::write_le(b, 24, dwProcessorType, 4);
            speakeasy::write_le(b, 28, dwAllocationGranularity, 4);
            speakeasy::write_le(b, 32, wProcessorLevel, 2);
            speakeasy::write_le(b, 34, wProcessorRevision, 2);
        }
        return b;
    }
};

//  MEMORY_BASIC_INFORMATION 

struct MEMORY_BASIC_INFORMATION : speakeasy::EmuStruct {
    uint64_t BaseAddress       = 0;
    uint64_t AllocationBase    = 0;
    uint32_t AllocationProtect = 0;
    uint32_t RegionSize        = 0;
    uint32_t State             = 0;  // MEM_COMMIT, MEM_FREE, MEM_RESERVE
    uint32_t Protect           = 0;
    uint32_t Type              = 0;  // MEM_IMAGE, MEM_MAPPED, MEM_PRIVATE

    size_t sizeof_obj() const override { return 48; }
    std::vector<uint8_t> get_bytes() const override {
        std::vector<uint8_t> b(48, 0);
        size_t ptr = (sizeof(uint64_t) == 8) ? 8 : 4;
        speakeasy::write_le(b, 0,  BaseAddress, ptr);
        speakeasy::write_le(b, ptr, AllocationBase, ptr);
        speakeasy::write_le(b, ptr*2, AllocationProtect, 4);
        // padding depends on ptr size
        size_t off = ptr*2 + 4;
        if (ptr == 8) off += 4;  // alignment padding for x64
        speakeasy::write_le(b, off, RegionSize, 4);
        off += 4;
        if (ptr == 8) off += 4;
        speakeasy::write_le(b, off, State, 4);
        off += 4;
        if (ptr == 8) off += 4;
        speakeasy::write_le(b, off, Protect, 4);
        off += 4;
        if (ptr == 8) off += 4;
        speakeasy::write_le(b, off, Type, 4);
        return b;
    }
};

//  Memory flags 

constexpr uint32_t MEM_COMMIT  = 0x1000;
constexpr uint32_t MEM_RESERVE = 0x2000;
constexpr uint32_t MEM_FREE    = 0x10000;
constexpr uint32_t MEM_IMAGE   = 0x1000000;
constexpr uint32_t MEM_MAPPED  = 0x40000;
constexpr uint32_t MEM_PRIVATE = 0x20000;

//  Page protection 

constexpr uint32_t PAGE_NOACCESS          = 0x01;
constexpr uint32_t PAGE_READONLY          = 0x02;
constexpr uint32_t PAGE_READWRITE         = 0x04;
constexpr uint32_t PAGE_WRITECOPY         = 0x08;
constexpr uint32_t PAGE_EXECUTE           = 0x10;
constexpr uint32_t PAGE_EXECUTE_READ      = 0x20;
constexpr uint32_t PAGE_EXECUTE_READWRITE = 0x40;
constexpr uint32_t PAGE_EXECUTE_WRITECOPY = 0x80;

}}} // namespaces

#else  // _WIN32
// On Windows, the system SDK provides these types.
// Include <windows.h> and use the real types directly.
// The speakeasy::defs::windows namespace is still available as aliases.
#include <windows.h>
namespace speakeasy { namespace defs { namespace windows {
    using ::FILETIME;
    using ::SYSTEMTIME;
    using ::SYSTEM_INFO;
    // MEMORY_BASIC_INFORMATION is defined differently on Win32/Win64
    // Use the system version directly.
}}} // namespaces
#endif // _WIN32

#endif // SPEAKEASY_DEFS_WINDOWS_H