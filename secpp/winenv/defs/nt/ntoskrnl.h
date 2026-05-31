// ntoskrnl.h  Windows NT kernel type definitions
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

//  Common NT structures 

struct LIST_ENTRY : speakeasy::EmuStruct {
    uint64_t Flink = 0;
    uint64_t Blink = 0;

    int ptr_size = 4;
    LIST_ENTRY(int ptr_sz = 8) : ptr_size(ptr_sz) {}

    size_t sizeof_obj() const override {
        return ptr_size * 2;
    }
    std::vector<uint8_t> get_bytes() const override {
        std::vector<uint8_t> b(ptr_size * 2, 0);
        speakeasy::write_le(b, 0, Flink, ptr_size);
        speakeasy::write_le(b, ptr_size, Blink, ptr_size);
        return b;
    }
    void from_bytes(const std::vector<uint8_t>& data) override {
        Flink = speakeasy::read_le(data, 0, ptr_size);
        Blink = speakeasy::read_le(data, ptr_size, ptr_size);
    }
};

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
    uint64_t Buffer         = 0;  // Ptr  address of UTF-16 string

    int ptr_size = 4;
    UNICODE_STRING(int ptr_sz = 8) : ptr_size(ptr_sz) {}

    size_t sizeof_obj() const override {
        return (ptr_size == 8) ? 16 : 8;
    }
    std::vector<uint8_t> get_bytes() const override {
        size_t sz = sizeof_obj();
        std::vector<uint8_t> b(sz, 0);
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
    void from_bytes(const std::vector<uint8_t>& data) override {
        Length = static_cast<uint16_t>(speakeasy::read_le(data, 0, 2));
        MaximumLength = static_cast<uint16_t>(speakeasy::read_le(data, 2, 2));
        size_t sz = sizeof_obj();
        if (sz == 16) {
            Buffer = speakeasy::read_le(data, 8, 8);
        } else {
            Buffer = speakeasy::read_le(data, 4, 4);
        }
    }
};

struct STRING : speakeasy::EmuStruct {
    uint16_t Length         = 0;
    uint16_t MaximumLength  = 0;
    uint64_t Buffer         = 0;  // Ptr  address of ANSI string

    int ptr_size = 4;
    STRING(int ptr_sz = 8) : ptr_size(ptr_sz) {}

    size_t sizeof_obj() const override { return (ptr_size == 8) ? 16 : 8; }
    std::vector<uint8_t> get_bytes() const override {
        UNICODE_STRING us(ptr_size);
        us.Length = Length;
        us.MaximumLength = MaximumLength;
        us.Buffer = Buffer;
        return us.get_bytes();
    }
    void from_bytes(const std::vector<uint8_t>& data) override {
        UNICODE_STRING us(ptr_size);
        us.from_bytes(data);
        Length = us.Length;
        MaximumLength = us.MaximumLength;
        Buffer = us.Buffer;
    }
};

struct OBJECT_ATTRIBUTES : speakeasy::EmuStruct {
    uint32_t Length             = 0;
    uint64_t RootDirectory      = 0;  // HANDLE
    uint64_t ObjectName         = 0;  // PUNICODE_STRING
    uint32_t Attributes         = 0;
    uint64_t SecurityDescriptor = 0;  // PVOID
    uint64_t SecurityQoS        = 0;  // PVOID

    int ptr_size = 4;
    OBJECT_ATTRIBUTES(int ptr_sz = 8) : ptr_size(ptr_sz) {}

    size_t sizeof_obj() const override {
        return (ptr_size == 8) ? 48 : 24;
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
    void from_bytes(const std::vector<uint8_t>& data) override {
        Length = static_cast<uint32_t>(speakeasy::read_le(data, 0, 4));
        size_t sz = sizeof_obj();
        if (sz == 48) {
            RootDirectory = speakeasy::read_le(data, 8, 8);
            ObjectName = speakeasy::read_le(data, 16, 8);
            Attributes = static_cast<uint32_t>(speakeasy::read_le(data, 24, 4));
            SecurityDescriptor = speakeasy::read_le(data, 32, 8);
            SecurityQoS = speakeasy::read_le(data, 40, 8);
        } else {
            RootDirectory = speakeasy::read_le(data, 4, 4);
            ObjectName = speakeasy::read_le(data, 8, 4);
            Attributes = static_cast<uint32_t>(speakeasy::read_le(data, 12, 4));
            SecurityDescriptor = speakeasy::read_le(data, 16, 4);
            SecurityQoS = speakeasy::read_le(data, 20, 4);
        }
    }
};

struct IO_STATUS_BLOCK : speakeasy::EmuStruct {
    uint64_t Status     = 0;  // NTSTATUS or PVOID
    uint64_t Information = 0; // ULONG_PTR

    int ptr_size = 4;
    IO_STATUS_BLOCK(int ptr_sz = 8) : ptr_size(ptr_sz) {}

    size_t sizeof_obj() const override {
        return (ptr_size == 8) ? 16 : 8;
    }
    std::vector<uint8_t> get_bytes() const override {
        size_t sz = sizeof_obj();
        std::vector<uint8_t> b(sz, 0);
        speakeasy::write_le(b, 0, Status, sz / 2);
        speakeasy::write_le(b, sz / 2, Information, sz / 2);
        return b;
    }
    void from_bytes(const std::vector<uint8_t>& data) override {
        size_t sz = sizeof_obj();
        Status = speakeasy::read_le(data, 0, sz / 2);
        Information = speakeasy::read_le(data, sz / 2, sz / 2);
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

//  SYSTEM_INFORMATION structures 

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

//  Dummy sync and process structures 

struct EPROCESS : speakeasy::EmuStruct {
    size_t sizeof_obj() const override { return 4096; }
    std::vector<uint8_t> get_bytes() const override { return std::vector<uint8_t>(4096, 0xff); }
};

struct ETHREAD : speakeasy::EmuStruct {
    size_t sizeof_obj() const override { return 4096; }
    std::vector<uint8_t> get_bytes() const override { return std::vector<uint8_t>(4096, 0xff); }
};

struct KEVENT : speakeasy::EmuStruct {
    size_t sizeof_obj() const override { return 4096; }
    std::vector<uint8_t> get_bytes() const override { return std::vector<uint8_t>(4096, 0); }
};

struct MUTANT : speakeasy::EmuStruct {
    size_t sizeof_obj() const override { return 4096; }
    std::vector<uint8_t> get_bytes() const override { return std::vector<uint8_t>(4096, 0); }
};

//  PEB Ldr Linked Lists and Module entries 

struct PEB_LDR_DATA : speakeasy::EmuStruct {
    uint32_t Length = 0;
    uint8_t Initialized[4] = {};
    uint64_t SsHandle = 0;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    uint64_t EntryInProgress = 0;
    uint8_t ShutdownInProgress = 0;
    uint64_t ShutdownThreadId = 0;

    int ptr_size = 4;
    PEB_LDR_DATA(int ptr_sz = 8)
        : ptr_size(ptr_sz),
          InLoadOrderModuleList(ptr_sz),
          InMemoryOrderModuleList(ptr_sz),
          InInitializationOrderModuleList(ptr_sz) {}

    size_t sizeof_obj() const override {
        return 4 + 4 + ptr_size + 3 * InLoadOrderModuleList.sizeof_obj() + ptr_size + 4 + ptr_size;
    }
    std::vector<uint8_t> get_bytes() const override {
        std::vector<uint8_t> b(sizeof_obj(), 0);
        speakeasy::write_le(b, 0, Length, 4);
        for (int i = 0; i < 4; ++i) b[4 + i] = Initialized[i];
        size_t off = 8;
        speakeasy::write_le(b, off, SsHandle, ptr_size); off += ptr_size;

        auto list_bytes = InLoadOrderModuleList.get_bytes();
        size_t list_sz = list_bytes.size();
        std::copy(list_bytes.begin(), list_bytes.end(), b.begin() + off); off += list_sz;

        list_bytes = InMemoryOrderModuleList.get_bytes();
        std::copy(list_bytes.begin(), list_bytes.end(), b.begin() + off); off += list_sz;

        list_bytes = InInitializationOrderModuleList.get_bytes();
        std::copy(list_bytes.begin(), list_bytes.end(), b.begin() + off); off += list_sz;

        speakeasy::write_le(b, off, EntryInProgress, ptr_size); off += ptr_size;
        b[off] = ShutdownInProgress; off += 4;
        speakeasy::write_le(b, off, ShutdownThreadId, ptr_size);
        return b;
    }
    void from_bytes(const std::vector<uint8_t>& data) override {
        Length = static_cast<uint32_t>(speakeasy::read_le(data, 0, 4));
        for (int i = 0; i < 4; ++i) Initialized[i] = data[4 + i];
        size_t off = 8;
        SsHandle = speakeasy::read_le(data, off, ptr_size); off += ptr_size;

        size_t list_sz = InLoadOrderModuleList.sizeof_obj();
        std::vector<uint8_t> list_data(data.begin() + off, data.begin() + off + list_sz);
        InLoadOrderModuleList.from_bytes(list_data); off += list_sz;

        list_data.assign(data.begin() + off, data.begin() + off + list_sz);
        InMemoryOrderModuleList.from_bytes(list_data); off += list_sz;

        list_data.assign(data.begin() + off, data.begin() + off + list_sz);
        InInitializationOrderModuleList.from_bytes(list_data); off += list_sz;

        EntryInProgress = speakeasy::read_le(data, off, ptr_size); off += ptr_size;
        ShutdownInProgress = data[off]; off += 1;
        ShutdownThreadId = speakeasy::read_le(data, off, ptr_size);
    }
};

struct LDR_DATA_TABLE_ENTRY : speakeasy::EmuStruct {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    uint64_t DllBase = 0;
    uint64_t EntryPoint = 0;
    uint32_t SizeOfImage = 0;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    uint32_t Flags = 0;
    uint16_t LoadCount = 0;

    int ptr_size = 4;
    LDR_DATA_TABLE_ENTRY(int ptr_sz = 8)
        : ptr_size(ptr_sz),
          InLoadOrderLinks(ptr_sz),
          InMemoryOrderLinks(ptr_sz),
          InInitializationOrderLinks(ptr_sz),
          FullDllName(ptr_sz),
          BaseDllName(ptr_sz) {}

    size_t sizeof_obj() const override {
        return 3 * InLoadOrderLinks.sizeof_obj() + 2 * ptr_size + 4 + 2 * FullDllName.sizeof_obj() + 4 + 2;
    }

    std::vector<uint8_t> get_bytes() const override {
        std::vector<uint8_t> b(sizeof_obj(), 0);
        size_t off = 0;

        auto list_bytes = InLoadOrderLinks.get_bytes();
        size_t list_sz = list_bytes.size();
        std::copy(list_bytes.begin(), list_bytes.end(), b.begin() + off); off += list_sz;

        list_bytes = InMemoryOrderLinks.get_bytes();
        std::copy(list_bytes.begin(), list_bytes.end(), b.begin() + off); off += list_sz;

        list_bytes = InInitializationOrderLinks.get_bytes();
        std::copy(list_bytes.begin(), list_bytes.end(), b.begin() + off); off += list_sz;

        speakeasy::write_le(b, off, DllBase, ptr_size); off += ptr_size;
        speakeasy::write_le(b, off, EntryPoint, ptr_size); off += ptr_size;
        speakeasy::write_le(b, off, SizeOfImage, 4); off += 4;

        auto us_bytes = FullDllName.get_bytes();
        size_t us_sz = us_bytes.size();
        std::copy(us_bytes.begin(), us_bytes.end(), b.begin() + off); off += us_sz;

        us_bytes = BaseDllName.get_bytes();
        std::copy(us_bytes.begin(), us_bytes.end(), b.begin() + off); off += us_sz;

        speakeasy::write_le(b, off, Flags, 4); off += 4;
        speakeasy::write_le(b, off, LoadCount, 2);
        return b;
    }

    void from_bytes(const std::vector<uint8_t>& data) override {
        size_t off = 0;
        size_t list_sz = InLoadOrderLinks.sizeof_obj();

        std::vector<uint8_t> list_data(data.begin() + off, data.begin() + off + list_sz);
        InLoadOrderLinks.from_bytes(list_data); off += list_sz;

        list_data.assign(data.begin() + off, data.begin() + off + list_sz);
        InMemoryOrderLinks.from_bytes(list_data); off += list_sz;

        list_data.assign(data.begin() + off, data.begin() + off + list_sz);
        InInitializationOrderLinks.from_bytes(list_data); off += list_sz;

        DllBase = speakeasy::read_le(data, off, ptr_size); off += ptr_size;
        EntryPoint = speakeasy::read_le(data, off, ptr_size); off += ptr_size;
        SizeOfImage = static_cast<uint32_t>(speakeasy::read_le(data, off, 4)); off += 4;

        size_t us_sz = FullDllName.sizeof_obj();
        std::vector<uint8_t> us_data(data.begin() + off, data.begin() + off + us_sz);
        FullDllName.from_bytes(us_data); off += us_sz;

        us_data.assign(data.begin() + off, data.begin() + off + us_sz);
        BaseDllName.from_bytes(us_data); off += us_sz;

        Flags = static_cast<uint32_t>(speakeasy::read_le(data, off, 4)); off += 4;
        LoadCount = static_cast<uint16_t>(speakeasy::read_le(data, off, 2));
    }
};

//  Process Parameters 

struct CURDIR : speakeasy::EmuStruct {
    UNICODE_STRING DosPath;
    uint64_t Handle = 0;

    int ptr_size = 4;
    CURDIR(int ptr_sz = 8) : ptr_size(ptr_sz), DosPath(ptr_sz) {}

    size_t sizeof_obj() const override {
        return DosPath.sizeof_obj() + ptr_size;
    }
    std::vector<uint8_t> get_bytes() const override {
        std::vector<uint8_t> b(sizeof_obj(), 0);
        auto dp_bytes = DosPath.get_bytes();
        std::copy(dp_bytes.begin(), dp_bytes.end(), b.begin());
        speakeasy::write_le(b, dp_bytes.size(), Handle, ptr_size);
        return b;
    }
    void from_bytes(const std::vector<uint8_t>& data) override {
        size_t dp_sz = DosPath.sizeof_obj();
        std::vector<uint8_t> dp_data(data.begin(), data.begin() + dp_sz);
        DosPath.from_bytes(dp_data);
        Handle = speakeasy::read_le(data, dp_sz, ptr_size);
    }
};

struct RTL_USER_PROCESS_PARAMETERS : speakeasy::EmuStruct {
    uint32_t MaximumLength = 0;
    uint32_t Length = 0;
    uint32_t Flags = 0;
    uint32_t DebugFlags = 0;
    uint64_t ConsoleHandle = 0;
    uint32_t ConsoleFlags = 0;
    uint64_t StandardInput = 0;
    uint64_t StandardOutput = 0;
    uint64_t StandardError = 0;
    CURDIR CurrentDirectory;
    UNICODE_STRING DllPath;
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
    uint64_t Environment = 0;
    uint32_t StartingX = 0;
    uint32_t StartingY = 0;
    uint32_t CountX = 0;
    uint32_t CountY = 0;
    uint32_t CountCharsX = 0;
    uint32_t CountCharsY = 0;
    uint32_t FillAttribute = 0;
    uint32_t WindowFlags = 0;
    uint32_t ShowWindowFlags = 0;
    UNICODE_STRING WindowTitle;
    UNICODE_STRING DesktopInfo;
    UNICODE_STRING ShellInfo;
    UNICODE_STRING RuntimeData;

    int ptr_size = 4;
    RTL_USER_PROCESS_PARAMETERS(int ptr_sz = 8)
        : ptr_size(ptr_sz),
          CurrentDirectory(ptr_sz),
          DllPath(ptr_sz),
          ImagePathName(ptr_sz),
          CommandLine(ptr_sz),
          WindowTitle(ptr_sz),
          DesktopInfo(ptr_sz),
          ShellInfo(ptr_sz),
          RuntimeData(ptr_sz) {}

    size_t sizeof_obj() const override {
        return 4 * 4 + ptr_size + 4 + 3 * ptr_size +
               CurrentDirectory.sizeof_obj() +
               DllPath.sizeof_obj() +
               ImagePathName.sizeof_obj() +
               CommandLine.sizeof_obj() +
               ptr_size +
               9 * 4 +
               WindowTitle.sizeof_obj() +
               DesktopInfo.sizeof_obj() +
               ShellInfo.sizeof_obj() +
               RuntimeData.sizeof_obj();
    }

    std::vector<uint8_t> get_bytes() const override {
        std::vector<uint8_t> b(sizeof_obj(), 0);
        size_t off = 0;
        speakeasy::write_le(b, off, MaximumLength, 4); off += 4;
        speakeasy::write_le(b, off, Length, 4); off += 4;
        speakeasy::write_le(b, off, Flags, 4); off += 4;
        speakeasy::write_le(b, off, DebugFlags, 4); off += 4;
        speakeasy::write_le(b, off, ConsoleHandle, ptr_size); off += ptr_size;
        speakeasy::write_le(b, off, ConsoleFlags, 4); off += 4;
        speakeasy::write_le(b, off, StandardInput, ptr_size); off += ptr_size;
        speakeasy::write_le(b, off, StandardOutput, ptr_size); off += ptr_size;
        speakeasy::write_le(b, off, StandardError, ptr_size); off += ptr_size;

        auto bytes = CurrentDirectory.get_bytes();
        std::copy(bytes.begin(), bytes.end(), b.begin() + off); off += bytes.size();

        bytes = DllPath.get_bytes();
        std::copy(bytes.begin(), bytes.end(), b.begin() + off); off += bytes.size();

        bytes = ImagePathName.get_bytes();
        std::copy(bytes.begin(), bytes.end(), b.begin() + off); off += bytes.size();

        bytes = CommandLine.get_bytes();
        std::copy(bytes.begin(), bytes.end(), b.begin() + off); off += bytes.size();

        speakeasy::write_le(b, off, Environment, ptr_size); off += ptr_size;

        speakeasy::write_le(b, off, StartingX, 4); off += 4;
        speakeasy::write_le(b, off, StartingY, 4); off += 4;
        speakeasy::write_le(b, off, CountX, 4); off += 4;
        speakeasy::write_le(b, off, CountY, 4); off += 4;
        speakeasy::write_le(b, off, CountCharsX, 4); off += 4;
        speakeasy::write_le(b, off, CountCharsY, 4); off += 4;
        speakeasy::write_le(b, off, FillAttribute, 4); off += 4;
        speakeasy::write_le(b, off, WindowFlags, 4); off += 4;
        speakeasy::write_le(b, off, ShowWindowFlags, 4); off += 4;

        bytes = WindowTitle.get_bytes();
        std::copy(bytes.begin(), bytes.end(), b.begin() + off); off += bytes.size();

        bytes = DesktopInfo.get_bytes();
        std::copy(bytes.begin(), bytes.end(), b.begin() + off); off += bytes.size();

        bytes = ShellInfo.get_bytes();
        std::copy(bytes.begin(), bytes.end(), b.begin() + off); off += bytes.size();

        bytes = RuntimeData.get_bytes();
        std::copy(bytes.begin(), bytes.end(), b.begin() + off);
        return b;
    }

    void from_bytes(const std::vector<uint8_t>& data) override {
        size_t off = 0;
        MaximumLength = static_cast<uint32_t>(speakeasy::read_le(data, off, 4)); off += 4;
        Length = static_cast<uint32_t>(speakeasy::read_le(data, off, 4)); off += 4;
        Flags = static_cast<uint32_t>(speakeasy::read_le(data, off, 4)); off += 4;
        DebugFlags = static_cast<uint32_t>(speakeasy::read_le(data, off, 4)); off += 4;
        ConsoleHandle = speakeasy::read_le(data, off, ptr_size); off += ptr_size;
        ConsoleFlags = static_cast<uint32_t>(speakeasy::read_le(data, off, 4)); off += 4;
        StandardInput = speakeasy::read_le(data, off, ptr_size); off += ptr_size;
        StandardOutput = speakeasy::read_le(data, off, ptr_size); off += ptr_size;
        StandardError = speakeasy::read_le(data, off, ptr_size); off += ptr_size;

        size_t sz = CurrentDirectory.sizeof_obj();
        std::vector<uint8_t> sub_data(data.begin() + off, data.begin() + off + sz);
        CurrentDirectory.from_bytes(sub_data); off += sz;

        sz = DllPath.sizeof_obj();
        sub_data.assign(data.begin() + off, data.begin() + off + sz);
        DllPath.from_bytes(sub_data); off += sz;

        sz = ImagePathName.sizeof_obj();
        sub_data.assign(data.begin() + off, data.begin() + off + sz);
        ImagePathName.from_bytes(sub_data); off += sz;

        sz = CommandLine.sizeof_obj();
        sub_data.assign(data.begin() + off, data.begin() + off + sz);
        CommandLine.from_bytes(sub_data); off += sz;

        Environment = speakeasy::read_le(data, off, ptr_size); off += ptr_size;

        StartingX = static_cast<uint32_t>(speakeasy::read_le(data, off, 4)); off += 4;
        StartingY = static_cast<uint32_t>(speakeasy::read_le(data, off, 4)); off += 4;
        CountX = static_cast<uint32_t>(speakeasy::read_le(data, off, 4)); off += 4;
        CountY = static_cast<uint32_t>(speakeasy::read_le(data, off, 4)); off += 4;
        CountCharsX = static_cast<uint32_t>(speakeasy::read_le(data, off, 4)); off += 4;
        CountCharsY = static_cast<uint32_t>(speakeasy::read_le(data, off, 4)); off += 4;
        FillAttribute = static_cast<uint32_t>(speakeasy::read_le(data, off, 4)); off += 4;
        WindowFlags = static_cast<uint32_t>(speakeasy::read_le(data, off, 4)); off += 4;
        ShowWindowFlags = static_cast<uint32_t>(speakeasy::read_le(data, off, 4)); off += 4;

        sz = WindowTitle.sizeof_obj();
        sub_data.assign(data.begin() + off, data.begin() + off + sz);
        WindowTitle.from_bytes(sub_data); off += sz;

        sz = DesktopInfo.sizeof_obj();
        sub_data.assign(data.begin() + off, data.begin() + off + sz);
        DesktopInfo.from_bytes(sub_data); off += sz;

        sz = ShellInfo.sizeof_obj();
        sub_data.assign(data.begin() + off, data.begin() + off + sz);
        ShellInfo.from_bytes(sub_data); off += sz;

        sz = RuntimeData.sizeof_obj();
        sub_data.assign(data.begin() + off, data.begin() + off + sz);
        RuntimeData.from_bytes(sub_data);
    }
};

//  Process Environment Block (PEB) 

struct PEB : speakeasy::EmuStruct {
    uint8_t InheritedAddressSpace = 0;
    uint8_t ReadImageFileExecOptions = 0;
    uint8_t BeingDebugged = 0;
    uint8_t BitField = 0;
    uint64_t Mutant = 0;
    uint64_t ImageBaseAddress = 0;
    uint64_t Ldr = 0;
    uint64_t ProcessParameters = 0;
    uint64_t SubSystemData = 0;
    uint64_t ProcessHeap = 0;
    uint64_t FastPebLock = 0;
    uint64_t AtlThunkSListPtr = 0;
    uint64_t IFEOKey = 0;
    uint64_t CrossProcessFlags = 0;
    uint64_t UserSharedInfoPtr = 0;
    uint32_t SystemReserved = 0;
    uint32_t AtlThunkSListPtr32 = 0;
    uint64_t ApiSetMap = 0;
    uint64_t TlsExpansionCounter = 0;
    uint64_t TlsBitmap = 0;
    uint32_t TlsBitmapBits[2] = {};
    uint64_t ReadOnlySharedMemoryBase = 0;
    uint64_t SharedData = 0;
    uint64_t ReadOnlyStaticServerData = 0;
    uint64_t AnsiCodePageData = 0;
    uint64_t OemCodePageData = 0;
    uint64_t UnicodeCaseTableData = 0;
    uint32_t NumberOfProcessors = 0;
    uint32_t NtGlobalFlag = 0;
    int64_t CriticalSectionTimeout = 0;
    uint64_t HeapSegmentReserve = 0;
    uint64_t HeapSegmentCommit = 0;
    uint64_t HeapDeCommitTotalFreeThreshold = 0;
    uint64_t HeapDeCommitFreeBlockThreshold = 0;
    uint32_t NumberOfHeaps = 0;
    uint32_t MaximumNumberOfHeaps = 0;
    uint64_t ProcessHeaps = 0;
    uint64_t GdiSharedHandleTable = 0;
    uint64_t ProcessStarterHelper = 0;
    uint64_t GdiDCAttributeList = 0;
    uint64_t LoaderLock = 0;
    uint32_t OSMajorVersion = 0;
    uint32_t OSMinorVersion = 0;
    uint16_t OSBuildNumber = 0;
    uint16_t OSCSDVersion = 0;
    uint32_t OSPlatformId = 0;
    uint32_t ImageSubsystem = 0;
    uint32_t ImageSubsystemMajorVersion = 0;
    uint64_t ImageSubsystemMinorVersion = 0;
    uint64_t ActiveProcessAffinityMask = 0;
    uint32_t GdiHandleBuffer[60] = {};
    uint64_t PostProcessInitRoutine = 0;
    uint64_t TlsExpansionBitmap = 0;
    uint32_t TlsExpansionBitmapBits[32] = {};
    uint64_t SessionId = 0;

    int ptr_size = 4;
    PEB(int ptr_sz = 8) : ptr_size(ptr_sz) {}

    size_t sizeof_obj() const override {
        return (ptr_size == 8) ? 0x3d0 : 0x240;
    }

    std::vector<uint8_t> get_bytes() const override {
        std::vector<uint8_t> b(sizeof_obj(), 0);
        b[0] = InheritedAddressSpace;
        b[1] = ReadImageFileExecOptions;
        b[2] = BeingDebugged;
        b[3] = BitField;
        speakeasy::write_le(b, 4, Mutant, ptr_size);
        speakeasy::write_le(b, 4 + ptr_size, ImageBaseAddress, ptr_size);
        speakeasy::write_le(b, 4 + 2 * ptr_size, Ldr, ptr_size);
        speakeasy::write_le(b, 4 + 3 * ptr_size, ProcessParameters, ptr_size);
        speakeasy::write_le(b, 4 + 4 * ptr_size, SubSystemData, ptr_size);
        speakeasy::write_le(b, 4 + 5 * ptr_size, ProcessHeap, ptr_size);

        size_t nt_glob_offset = (ptr_size == 8) ? 0xBC : 0x68;
        speakeasy::write_le(b, nt_glob_offset, NtGlobalFlag, 4);

        size_t osver_offset = (ptr_size == 8) ? 0x110 : 0xA4;
        speakeasy::write_le(b, osver_offset, OSMajorVersion, 4);
        speakeasy::write_le(b, osver_offset + 4, OSMinorVersion, 4);
        speakeasy::write_le(b, osver_offset + 8, OSBuildNumber, 2);
        speakeasy::write_le(b, osver_offset + 10, OSCSDVersion, 2);
        speakeasy::write_le(b, osver_offset + 12, OSPlatformId, 4);

        return b;
    }

    void from_bytes(const std::vector<uint8_t>& data) override {
        InheritedAddressSpace = data[0];
        ReadImageFileExecOptions = data[1];
        BeingDebugged = data[2];
        BitField = data[3];
        Mutant = speakeasy::read_le(data, 4, ptr_size);
        ImageBaseAddress = speakeasy::read_le(data, 4 + ptr_size, ptr_size);
        Ldr = speakeasy::read_le(data, 4 + 2 * ptr_size, ptr_size);
        ProcessParameters = speakeasy::read_le(data, 4 + 3 * ptr_size, ptr_size);
        SubSystemData = speakeasy::read_le(data, 4 + 4 * ptr_size, ptr_size);
        ProcessHeap = speakeasy::read_le(data, 4 + 5 * ptr_size, ptr_size);

        size_t nt_glob_offset = (ptr_size == 8) ? 0xBC : 0x68;
        NtGlobalFlag = static_cast<uint32_t>(speakeasy::read_le(data, nt_glob_offset, 4));

        size_t osver_offset = (ptr_size == 8) ? 0x110 : 0xA4;
        OSMajorVersion = static_cast<uint32_t>(speakeasy::read_le(data, osver_offset, 4));
        OSMinorVersion = static_cast<uint32_t>(speakeasy::read_le(data, osver_offset + 4, 4));
        OSBuildNumber = static_cast<uint16_t>(speakeasy::read_le(data, osver_offset + 8, 2));
        OSCSDVersion = static_cast<uint16_t>(speakeasy::read_le(data, osver_offset + 10, 2));
        OSPlatformId = static_cast<uint32_t>(speakeasy::read_le(data, osver_offset + 12, 4));
    }
};

//  Thread Environment Block (TEB) 

struct NT_TIB : speakeasy::EmuStruct {
    uint64_t ExceptionList = 0;
    uint64_t StackBase = 0;
    uint64_t StackLimit = 0;
    uint64_t Reserved1 = 0;
    uint64_t Reserved2 = 0;
    uint64_t Reserved3 = 0;
    uint64_t Self = 0;

    int ptr_size = 4;
    NT_TIB(int ptr_sz = 8) : ptr_size(ptr_sz) {}

    size_t sizeof_obj() const override {
        return ptr_size * 7;
    }
    std::vector<uint8_t> get_bytes() const override {
        std::vector<uint8_t> b(sizeof_obj(), 0);
        speakeasy::write_le(b, 0, ExceptionList, ptr_size);
        speakeasy::write_le(b, ptr_size, StackBase, ptr_size);
        speakeasy::write_le(b, ptr_size * 2, StackLimit, ptr_size);
        speakeasy::write_le(b, ptr_size * 3, Reserved1, ptr_size);
        speakeasy::write_le(b, ptr_size * 4, Reserved2, ptr_size);
        speakeasy::write_le(b, ptr_size * 5, Reserved3, ptr_size);
        speakeasy::write_le(b, ptr_size * 6, Self, ptr_size);
        return b;
    }
    void from_bytes(const std::vector<uint8_t>& data) override {
        ExceptionList = speakeasy::read_le(data, 0, ptr_size);
        StackBase = speakeasy::read_le(data, ptr_size, ptr_size);
        StackLimit = speakeasy::read_le(data, ptr_size * 2, ptr_size);
        Reserved1 = speakeasy::read_le(data, ptr_size * 3, ptr_size);
        Reserved2 = speakeasy::read_le(data, ptr_size * 4, ptr_size);
        Reserved3 = speakeasy::read_le(data, ptr_size * 5, ptr_size);
        Self = speakeasy::read_le(data, ptr_size * 6, ptr_size);
    }
};

struct CLIENT_ID : speakeasy::EmuStruct {
    uint32_t UniqueProcess = 0;
    uint32_t UniqueThread = 0;

    size_t sizeof_obj() const override { return 8; }
    std::vector<uint8_t> get_bytes() const override {
        std::vector<uint8_t> b(8);
        speakeasy::write_le(b, 0, UniqueProcess, 4);
        speakeasy::write_le(b, 4, UniqueThread, 4);
        return b;
    }
    void from_bytes(const std::vector<uint8_t>& data) override {
        UniqueProcess = static_cast<uint32_t>(speakeasy::read_le(data, 0, 4));
        UniqueThread = static_cast<uint32_t>(speakeasy::read_le(data, 4, 4));
    }
};

struct TEB : speakeasy::EmuStruct {
    NT_TIB NtTib;
    uint64_t EnvironmentPointer = 0;
    CLIENT_ID ClientId;
    uint64_t ActiveRpcHandle = 0;
    uint64_t ThreadLocalStoragePointer = 0;
    uint64_t ProcessEnvironmentBlock = 0;
    uint32_t LastErrorValue = 0;

    int ptr_size = 4;
    TEB(int ptr_sz = 8) : ptr_size(ptr_sz), NtTib(ptr_sz) {}

    size_t sizeof_obj() const override {
        return (ptr_size == 8) ? 0x0f8 : 0x0f0;
    }

    std::vector<uint8_t> get_bytes() const override {
        std::vector<uint8_t> b(sizeof_obj(), 0);

        auto tib_bytes = NtTib.get_bytes();
        std::copy(tib_bytes.begin(), tib_bytes.end(), b.begin());

        size_t off = tib_bytes.size();
        speakeasy::write_le(b, off, EnvironmentPointer, ptr_size); off += ptr_size;

        auto cid_bytes = ClientId.get_bytes();
        std::copy(cid_bytes.begin(), cid_bytes.end(), b.begin() + off); off += cid_bytes.size();

        if (ptr_size == 8) {
            speakeasy::write_le(b, off, 0, 8); off += 8; // pad0
        }

        speakeasy::write_le(b, off, ActiveRpcHandle, ptr_size); off += ptr_size;
        speakeasy::write_le(b, off, ThreadLocalStoragePointer, ptr_size); off += ptr_size;
        speakeasy::write_le(b, off, ProcessEnvironmentBlock, ptr_size); off += ptr_size;
        speakeasy::write_le(b, off, LastErrorValue, 4);
        return b;
    }

    void from_bytes(const std::vector<uint8_t>& data) override {
        size_t tib_sz = NtTib.sizeof_obj();
        std::vector<uint8_t> tib_data(data.begin(), data.begin() + tib_sz);
        NtTib.from_bytes(tib_data);

        size_t off = tib_sz;
        EnvironmentPointer = speakeasy::read_le(data, off, ptr_size); off += ptr_size;

        std::vector<uint8_t> cid_data(data.begin() + off, data.begin() + off + 8);
        ClientId.from_bytes(cid_data); off += 8;

        if (ptr_size == 8) {
            off += 8; // pad0
        }

        ActiveRpcHandle = speakeasy::read_le(data, off, ptr_size); off += ptr_size;
        ThreadLocalStoragePointer = speakeasy::read_le(data, off, ptr_size); off += ptr_size;
        ProcessEnvironmentBlock = speakeasy::read_le(data, off, ptr_size); off += ptr_size;
        LastErrorValue = static_cast<uint32_t>(speakeasy::read_le(data, off, 4));
    }
};

//  Interrupt Descriptor Table (IDT) 

struct KIDTENTRY : speakeasy::EmuStruct {
    uint16_t OffsetLow = 0;
    uint16_t Selector = 0;
    uint32_t Base = 0;

    size_t sizeof_obj() const override { return 8; }
    std::vector<uint8_t> get_bytes() const override {
        std::vector<uint8_t> b(8, 0);
        speakeasy::write_le(b, 0, OffsetLow, 2);
        speakeasy::write_le(b, 2, Selector, 2);
        speakeasy::write_le(b, 4, Base, 4);
        return b;
    }
    void from_bytes(const std::vector<uint8_t>& data) override {
        OffsetLow = static_cast<uint16_t>(speakeasy::read_le(data, 0, 2));
        Selector = static_cast<uint16_t>(speakeasy::read_le(data, 2, 2));
        Base = static_cast<uint32_t>(speakeasy::read_le(data, 4, 4));
    }
};

struct KIDTENTRY64 : speakeasy::EmuStruct {
    uint16_t OffsetLow = 0;
    uint16_t Selector = 0;
    uint16_t Reserved0 = 0;
    uint16_t OffsetMiddle = 0;
    uint32_t OffsetHigh = 0;
    uint32_t Reserved1 = 0;

    size_t sizeof_obj() const override { return 16; }
    std::vector<uint8_t> get_bytes() const override {
        std::vector<uint8_t> b(16, 0);
        speakeasy::write_le(b, 0, OffsetLow, 2);
        speakeasy::write_le(b, 2, Selector, 2);
        speakeasy::write_le(b, 4, Reserved0, 2);
        speakeasy::write_le(b, 6, OffsetMiddle, 2);
        speakeasy::write_le(b, 8, OffsetHigh, 4);
        speakeasy::write_le(b, 12, Reserved1, 4);
        return b;
    }
    void from_bytes(const std::vector<uint8_t>& data) override {
        OffsetLow = static_cast<uint16_t>(speakeasy::read_le(data, 0, 2));
        Selector = static_cast<uint16_t>(speakeasy::read_le(data, 2, 2));
        Reserved0 = static_cast<uint16_t>(speakeasy::read_le(data, 4, 2));
        OffsetMiddle = static_cast<uint16_t>(speakeasy::read_le(data, 6, 2));
        OffsetHigh = static_cast<uint32_t>(speakeasy::read_le(data, 8, 4));
        Reserved1 = static_cast<uint32_t>(speakeasy::read_le(data, 12, 4));
    }
};

struct DESCRIPTOR_TABLE : speakeasy::EmuStruct {
    std::vector<KIDTENTRY> table_32;
    std::vector<KIDTENTRY64> table_64;
    int ptr_size = 4;

    DESCRIPTOR_TABLE(int ptr_sz = 8) : ptr_size(ptr_sz) {
        if (ptr_size == 4) {
            table_32.resize(256);
        } else {
            table_64.resize(256);
        }
    }

    size_t sizeof_obj() const override {
        return (ptr_size == 4) ? 8 * 256 : 16 * 256;
    }
    std::vector<uint8_t> get_bytes() const override {
        std::vector<uint8_t> b(sizeof_obj(), 0);
        size_t off = 0;
        if (ptr_size == 4) {
            for (const auto& entry : table_32) {
                auto entry_bytes = entry.get_bytes();
                std::copy(entry_bytes.begin(), entry_bytes.end(), b.begin() + off);
                off += 8;
            }
        } else {
            for (const auto& entry : table_64) {
                auto entry_bytes = entry.get_bytes();
                std::copy(entry_bytes.begin(), entry_bytes.end(), b.begin() + off);
                off += 16;
            }
        }
        return b;
    }
    void from_bytes(const std::vector<uint8_t>& data) override {
        size_t off = 0;
        if (ptr_size == 4) {
            for (auto& entry : table_32) {
                std::vector<uint8_t> entry_data(data.begin() + off, data.begin() + off + 8);
                entry.from_bytes(entry_data);
                off += 8;
            }
        } else {
            for (auto& entry : table_64) {
                std::vector<uint8_t> entry_data(data.begin() + off, data.begin() + off + 16);
                entry.from_bytes(entry_data);
                off += 16;
            }
        }
    }
};

struct IDT : speakeasy::EmuStruct {
    uint16_t Limit = 0;
    uint64_t Descriptors = 0;

    int ptr_size = 4;
    IDT(int ptr_sz = 8) : ptr_size(ptr_sz) {}

    size_t sizeof_obj() const override {
        return 2 + ptr_size;
    }
    std::vector<uint8_t> get_bytes() const override {
        std::vector<uint8_t> b(sizeof_obj(), 0);
        speakeasy::write_le(b, 0, Limit, 2);
        speakeasy::write_le(b, 2, Descriptors, ptr_size);
        return b;
    }
    void from_bytes(const std::vector<uint8_t>& data) override {
        Limit = static_cast<uint16_t>(speakeasy::read_le(data, 0, 2));
        Descriptors = speakeasy::read_le(data, 2, ptr_size);
    }
};

}}} // namespaces

#endif // SPEAKEASY_DEFS_NT_NTOSKRNL_H