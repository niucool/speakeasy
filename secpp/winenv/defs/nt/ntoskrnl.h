// ntoskrnl.h — Windows NT kernel type definitions
//
// Maps to: speakeasy/winenv/defs/nt/ntoskrnl.py
//
// Core NT kernel structures used by API handlers and kernel emulation:
// UNICODE_STRING, OBJECT_ATTRIBUTES, SYSTEM_INFORMATION classes, etc.

#ifndef SPEAKEASY_DEFS_NT_NTOSKRNL_H
#define SPEAKEASY_DEFS_NT_NTOSKRNL_H

#include <cstdint>
#include <vector>
#include "../../../struct.h"

namespace speakeasy { namespace defs { namespace nt {

// ── Common NT structures ─────────────────────────────────────

struct KSYSTEM_TIME : speakeasy::EmuStruct {
    uint32_t LowPart    = 0;
    uint32_t High1Time  = 0;
    uint32_t High2Time  = 0;

    size_t sizeof_obj() const override { return 12; }
    std::vector<uint8_t> get_bytes() const override {
        std::vector<uint8_t> b(12);
        speakeasy::write_le(b, 0, LowPart, 4);
        speakeasy::write_le(b, 4, High1Time, 4);
        speakeasy::write_le(b, 8, High2Time, 4);
        return b;
    }
};

struct UNICODE_STRING : speakeasy::EmuStruct {
    uint16_t Length         = 0;
    uint16_t MaximumLength  = 0;
    uint64_t Buffer         = 0;  // Ptr → address of UTF-16 string

    size_t sizeof_obj() const override {
        return (sizeof(uint64_t) == 8) ? 16 : 8;
    }
    std::vector<uint8_t> get_bytes() const override {
        size_t sz = sizeof_obj();
        std::vector<uint8_t> b(sz);
        speakeasy::write_le(b, 0, Length, 2);
        speakeasy::write_le(b, 2, MaximumLength, 2);
        if (sz == 16) {
            speakeasy::write_le(b, 4, 0, 4);  // padding
            speakeasy::write_le(b, 8, Buffer, 8);
        } else {
            speakeasy::write_le(b, 4, Buffer, 4);
        }
        return b;
    }
};

struct STRING : speakeasy::EmuStruct {
    uint16_t Length         = 0;
    uint16_t MaximumLength  = 0;
    uint64_t Buffer         = 0;  // Ptr → address of ANSI string

    size_t sizeof_obj() const override { return UNICODE_STRING().sizeof_obj(); }
    std::vector<uint8_t> get_bytes() const override {
        UNICODE_STRING us;
        us.Length = Length;
        us.MaximumLength = MaximumLength;
        us.Buffer = Buffer;
        return us.get_bytes();
    }
};

struct OBJECT_ATTRIBUTES : speakeasy::EmuStruct {
    uint32_t Length             = 0;
    uint64_t RootDirectory      = 0;  // HANDLE
    uint64_t ObjectName         = 0;  // PUNICODE_STRING
    uint32_t Attributes         = 0;
    uint64_t SecurityDescriptor = 0;  // PVOID
    uint64_t SecurityQoS        = 0;  // PVOID

    size_t sizeof_obj() const override {
        return (sizeof(uint64_t) == 8) ? 48 : 24;
    }
    std::vector<uint8_t> get_bytes() const override {
        size_t sz = sizeof_obj();
        std::vector<uint8_t> b(sz, 0);
        speakeasy::write_le(b, 0, Length, 4);
        if (sz == 48) {
            speakeasy::write_le(b, 4, 0, 4);  // padding
            speakeasy::write_le(b, 8, RootDirectory, 8);
            speakeasy::write_le(b, 16, ObjectName, 8);
            speakeasy::write_le(b, 24, Attributes, 4);
            speakeasy::write_le(b, 28, 0, 4);  // padding
            speakeasy::write_le(b, 32, SecurityDescriptor, 8);
            speakeasy::write_le(b, 40, SecurityQoS, 8);
        } else {
            speakeasy::write_le(b, 4, RootDirectory, 4);
            speakeasy::write_le(b, 8, ObjectName, 4);
            speakeasy::write_le(b, 12, Attributes, 4);
            speakeasy::write_le(b, 16, SecurityDescriptor, 4);
            speakeasy::write_le(b, 20, SecurityQoS, 4);
        }
        return b;
    }
};

struct IO_STATUS_BLOCK : speakeasy::EmuStruct {
    uint64_t Status     = 0;  // NTSTATUS or PVOID
    uint64_t Information = 0; // ULONG_PTR

    size_t sizeof_obj() const override {
        return (sizeof(uint64_t) == 8) ? 16 : 8;
    }
    std::vector<uint8_t> get_bytes() const override {
        size_t sz = sizeof_obj();
        std::vector<uint8_t> b(sz);
        speakeasy::write_le(b, 0, Status, sz / 2);
        speakeasy::write_le(b, sz / 2, Information, sz / 2);
        return b;
    }
};

struct LARGE_INTEGER : speakeasy::EmuStruct {
    uint64_t QuadPart = 0;

    size_t sizeof_obj() const override { return 8; }
    std::vector<uint8_t> get_bytes() const override {
        std::vector<uint8_t> b(8);
        speakeasy::write_le(b, 0, QuadPart, 8);
        return b;
    }
};

// ── SYSTEM_INFORMATION structures ────────────────────────────

struct SYSTEM_TIMEOFDAY_INFORMATION : speakeasy::EmuStruct {
    uint64_t BootTime       = 0;
    uint64_t CurrentTime    = 0;
    uint64_t TimeZoneBias   = 0;
    uint32_t TimeZoneId     = 0;
    uint32_t Reserved       = 0;
    uint64_t BootTimeBias   = 0;
    uint64_t SleepTimeBias  = 0;

    size_t sizeof_obj() const override { return 48; }
    std::vector<uint8_t> get_bytes() const override {
        std::vector<uint8_t> b(48);
        speakeasy::write_le(b, 0,  BootTime, 8);
        speakeasy::write_le(b, 8,  CurrentTime, 8);
        speakeasy::write_le(b, 16, TimeZoneBias, 8);
        speakeasy::write_le(b, 24, TimeZoneId, 4);
        speakeasy::write_le(b, 28, Reserved, 4);
        speakeasy::write_le(b, 32, BootTimeBias, 8);
        speakeasy::write_le(b, 40, SleepTimeBias, 8);
        return b;
    }
};

struct SYSTEM_PROCESS_INFORMATION : speakeasy::EmuStruct {
    uint32_t NextEntryOffset                = 0;
    uint32_t NumberOfThreads                = 0;
    uint8_t  Reserved1[48]                  = {};
    UNICODE_STRING ImageName;
    uint32_t BasePriority                   = 0;
    uint64_t UniqueProcessId               = 0;
    uint64_t InheritedFromUniqueProcessId   = 0;
    uint32_t HandleCount                    = 0;
    uint32_t SessionId                      = 0;
    uint64_t UniqueProcessKey              = 0;
    uint64_t PeakVirtualSize               = 0;
    uint64_t VirtualSize                   = 0;
    uint32_t PageFaultCount                = 0;
    uint64_t PeakWorkingSetSize            = 0;
    uint64_t WorkingSetSize                = 0;
    uint64_t QuotaPeakPagedPoolUsage       = 0;
    uint64_t QuotaPagedPoolUsage           = 0;
    uint64_t QuotaPeakNonPagedPoolUsage    = 0;
    uint64_t QuotaNonPagedPoolUsage        = 0;
    uint64_t PagefileUsage                 = 0;
    uint64_t PeakPagefileUsage             = 0;
    uint64_t PrivatePageCount              = 0;

    size_t sizeof_obj() const override {
        return 48 + ImageName.sizeof_obj() + 12 * 4 + 10 * 8;
    }
};

}}} // namespaces

#endif // SPEAKEASY_DEFS_NT_NTOSKRNL_H