// windef.h — Windows base type definitions
//
// Maps to: speakeasy/winenv/defs/windows/windef.py
//
// Fundamental Windows types: POINT, RECT, MONITORINFO, plus
// common helpers like GUID, LUID, PE header structures.

#ifndef SPEAKEASY_DEFS_WINDOWS_WINDEF_H
#define SPEAKEASY_DEFS_WINDOWS_WINDEF_H

#include <cstdint>
#include <cstring>
#include <vector>
#include "windows.h"
#include "../../../struct.h"

namespace speakeasy { namespace defs { namespace windows {

// ── Constants ──────────────────────────────────────────────────

#ifndef ANYSIZE_ARRAY
constexpr uint32_t ANYSIZE_ARRAY = 1;
#endif

// ── POINT ──────────────────────────────────────────────────────

struct POINT : speakeasy::EmuStruct {
    int32_t x = 0;
    int32_t y = 0;

    size_t sizeof_obj() const override { return 8; }
    std::vector<uint8_t> get_bytes() const override {
        std::vector<uint8_t> b(8);
        speakeasy::write_le(b, 0, static_cast<uint64_t>(x), 4);
        speakeasy::write_le(b, 4, static_cast<uint64_t>(y), 4);
        return b;
    }
};

// ── POINTS (short-coordinate variant) ───────────────────────────

struct POINTS : speakeasy::EmuStruct {
    int16_t x = 0;
    int16_t y = 0;

    size_t sizeof_obj() const override { return 4; }
    std::vector<uint8_t> get_bytes() const override {
        std::vector<uint8_t> b(4);
        speakeasy::write_le(b, 0, static_cast<uint64_t>(static_cast<int16_t>(x)), 2);
        speakeasy::write_le(b, 2, static_cast<uint64_t>(static_cast<int16_t>(y)), 2);
        return b;
    }
};

// ── RECT ───────────────────────────────────────────────────────

struct RECT : speakeasy::EmuStruct {
    int32_t left   = 0;
    int32_t top    = 0;
    int32_t right  = 0;
    int32_t bottom = 0;

    size_t sizeof_obj() const override { return 16; }
    std::vector<uint8_t> get_bytes() const override {
        std::vector<uint8_t> b(16);
        speakeasy::write_le(b, 0,  static_cast<uint64_t>(left), 4);
        speakeasy::write_le(b, 4,  static_cast<uint64_t>(top), 4);
        speakeasy::write_le(b, 8,  static_cast<uint64_t>(right), 4);
        speakeasy::write_le(b, 12, static_cast<uint64_t>(bottom), 4);
        return b;
    }
};

// ── RECTL (long-coordinate variant) ─────────────────────────────

struct RECTL : speakeasy::EmuStruct {
    int32_t left   = 0;
    int32_t top    = 0;
    int32_t right  = 0;
    int32_t bottom = 0;

    size_t sizeof_obj() const override { return 16; }
    std::vector<uint8_t> get_bytes() const override {
        std::vector<uint8_t> b(16);
        speakeasy::write_le(b, 0,  static_cast<uint64_t>(left), 4);
        speakeasy::write_le(b, 4,  static_cast<uint64_t>(top), 4);
        speakeasy::write_le(b, 8,  static_cast<uint64_t>(right), 4);
        speakeasy::write_le(b, 12, static_cast<uint64_t>(bottom), 4);
        return b;
    }
};

// ── SIZE ───────────────────────────────────────────────────────

struct SIZE : speakeasy::EmuStruct {
    int32_t cx = 0;
    int32_t cy = 0;

    size_t sizeof_obj() const override { return 8; }
    std::vector<uint8_t> get_bytes() const override {
        std::vector<uint8_t> b(8);
        speakeasy::write_le(b, 0, static_cast<uint64_t>(cx), 4);
        speakeasy::write_le(b, 4, static_cast<uint64_t>(cy), 4);
        return b;
    }
};

// ── MONITORINFO ────────────────────────────────────────────────

struct MONITORINFO : speakeasy::EmuStruct {
    uint32_t cbSize    = sizeof(MONITORINFO);
    RECT     rcMonitor;
    RECT     rcWork;
    uint32_t dwFlags   = 0;

    size_t sizeof_obj() const override { return 40; }
    std::vector<uint8_t> get_bytes() const override {
        std::vector<uint8_t> b(40, 0);
        speakeasy::write_le(b, 0, cbSize, 4);
        auto rcm = rcMonitor.get_bytes();
        std::copy(rcm.begin(), rcm.end(), b.begin() + 4);
        auto rcw = rcWork.get_bytes();
        std::copy(rcw.begin(), rcw.end(), b.begin() + 20);
        speakeasy::write_le(b, 36, dwFlags, 4);
        return b;
    }
};

// ── GUID ───────────────────────────────────────────────────────

struct GUID : speakeasy::EmuStruct {
    uint32_t Data1    = 0;
    uint16_t Data2    = 0;
    uint16_t Data3    = 0;
    uint8_t  Data4[8] = {};

    size_t sizeof_obj() const override { return 16; }
    std::vector<uint8_t> get_bytes() const override {
        std::vector<uint8_t> b(16);
        speakeasy::write_le(b, 0,  Data1, 4);
        speakeasy::write_le(b, 4,  Data2, 2);
        speakeasy::write_le(b, 6,  Data3, 2);
        for (size_t i = 0; i < 8; ++i)
            b[8 + i] = Data4[i];
        return b;
    }

    bool operator==(const GUID& o) const {
        if (Data1 != o.Data1 || Data2 != o.Data2 || Data3 != o.Data3)
            return false;
        for (size_t i = 0; i < 8; ++i)
            if (Data4[i] != o.Data4[i])
                return false;
        return true;
    }
    bool operator!=(const GUID& o) const { return !(*this == o); }
};

// ── LUID ───────────────────────────────────────────────────────

struct LUID : speakeasy::EmuStruct {
    uint32_t LowPart  = 0;
    int32_t  HighPart = 0;

    size_t sizeof_obj() const override { return 8; }
    std::vector<uint8_t> get_bytes() const override {
        std::vector<uint8_t> b(8);
        speakeasy::write_le(b, 0, LowPart, 4);
        speakeasy::write_le(b, 4, static_cast<uint64_t>(HighPart), 4);
        return b;
    }
};

// ── LARGE_INTEGER / ULARGE_INTEGER ────────────────────────────

struct LARGE_INTEGER : speakeasy::EmuStruct {
    int64_t QuadPart = 0;

    size_t sizeof_obj() const override { return 8; }
    std::vector<uint8_t> get_bytes() const override {
        std::vector<uint8_t> b(8);
        speakeasy::write_le(b, 0, static_cast<uint64_t>(QuadPart), 8);
        return b;
    }
};

struct ULARGE_INTEGER : speakeasy::EmuStruct {
    uint64_t QuadPart = 0;

    size_t sizeof_obj() const override { return 8; }
    std::vector<uint8_t> get_bytes() const override {
        std::vector<uint8_t> b(8);
        speakeasy::write_le(b, 0, QuadPart, 8);
        return b;
    }
};

// ── PE header structures ───────────────────────────────────────

// IMAGE_DOS_HEADER
struct IMAGE_DOS_HEADER : speakeasy::EmuStruct {
    uint16_t e_magic    = 0x5A4D;  // "MZ"
    uint16_t e_cblp     = 0;
    uint16_t e_cp       = 0;
    uint16_t e_crlc     = 0;
    uint16_t e_cparhdr  = 0;
    uint16_t e_minalloc = 0;
    uint16_t e_maxalloc = 0;
    uint16_t e_ss       = 0;
    uint16_t e_sp       = 0;
    uint16_t e_csum     = 0;
    uint16_t e_ip       = 0;
    uint16_t e_cs       = 0;
    uint16_t e_lfarlc   = 0;
    uint16_t e_ovno     = 0;
    uint16_t e_res[4]   = {};
    uint16_t e_oemid    = 0;
    uint16_t e_oeminfo  = 0;
    uint16_t e_res2[10] = {};
    int32_t  e_lfanew   = 0;  // offset to PE signature

    size_t sizeof_obj() const override { return 64; }
    std::vector<uint8_t> get_bytes() const override {
        std::vector<uint8_t> b(64, 0);
        speakeasy::write_le(b, 0,  e_magic, 2);
        speakeasy::write_le(b, 2,  e_cblp, 2);
        speakeasy::write_le(b, 4,  e_cp, 2);
        speakeasy::write_le(b, 6,  e_crlc, 2);
        speakeasy::write_le(b, 8,  e_cparhdr, 2);
        speakeasy::write_le(b, 10, e_minalloc, 2);
        speakeasy::write_le(b, 12, e_maxalloc, 2);
        speakeasy::write_le(b, 14, e_ss, 2);
        speakeasy::write_le(b, 16, e_sp, 2);
        speakeasy::write_le(b, 18, e_csum, 2);
        speakeasy::write_le(b, 20, e_ip, 2);
        speakeasy::write_le(b, 22, e_cs, 2);
        speakeasy::write_le(b, 24, e_lfarlc, 2);
        speakeasy::write_le(b, 26, e_ovno, 2);
        for (size_t i = 0; i < 4; ++i)
            speakeasy::write_le(b, 28 + i * 2, e_res[i], 2);
        speakeasy::write_le(b, 36, e_oemid, 2);
        speakeasy::write_le(b, 38, e_oeminfo, 2);
        for (size_t i = 0; i < 10; ++i)
            speakeasy::write_le(b, 40 + i * 2, e_res2[i], 2);
        speakeasy::write_le(b, 60, static_cast<uint64_t>(e_lfanew), 4);
        return b;
    }
};

// IMAGE_FILE_HEADER
struct IMAGE_FILE_HEADER : speakeasy::EmuStruct {
    uint16_t Machine              = 0;
    uint16_t NumberOfSections     = 0;
    uint32_t TimeDateStamp        = 0;
    uint32_t PointerToSymbolTable = 0;
    uint32_t NumberOfSymbols      = 0;
    uint16_t SizeOfOptionalHeader = 0;
    uint16_t Characteristics      = 0;

    size_t sizeof_obj() const override { return 20; }
    std::vector<uint8_t> get_bytes() const override {
        std::vector<uint8_t> b(20);
        speakeasy::write_le(b, 0,  Machine, 2);
        speakeasy::write_le(b, 2,  NumberOfSections, 2);
        speakeasy::write_le(b, 4,  TimeDateStamp, 4);
        speakeasy::write_le(b, 8,  PointerToSymbolTable, 4);
        speakeasy::write_le(b, 12, NumberOfSymbols, 4);
        speakeasy::write_le(b, 16, SizeOfOptionalHeader, 2);
        speakeasy::write_le(b, 18, Characteristics, 2);
        return b;
    }
};

// IMAGE_DATA_DIRECTORY
struct IMAGE_DATA_DIRECTORY : speakeasy::EmuStruct {
    uint32_t VirtualAddress = 0;
    uint32_t Size           = 0;

    size_t sizeof_obj() const override { return 8; }
    std::vector<uint8_t> get_bytes() const override {
        std::vector<uint8_t> b(8);
        speakeasy::write_le(b, 0, VirtualAddress, 4);
        speakeasy::write_le(b, 4, Size, 4);
        return b;
    }
};

// IMAGE_OPTIONAL_HEADER32
struct IMAGE_OPTIONAL_HEADER32 : speakeasy::EmuStruct {
    uint16_t Magic                       = 0x10B;
    uint8_t  MajorLinkerVersion          = 0;
    uint8_t  MinorLinkerVersion          = 0;
    uint32_t SizeOfCode                  = 0;
    uint32_t SizeOfInitializedData       = 0;
    uint32_t SizeOfUninitializedData     = 0;
    uint32_t AddressOfEntryPoint         = 0;
    uint32_t BaseOfCode                  = 0;
    uint32_t BaseOfData                  = 0;
    uint32_t ImageBase                   = 0x400000;
    uint32_t SectionAlignment            = 0x1000;
    uint32_t FileAlignment               = 0x200;
    uint16_t MajorOperatingSystemVersion = 0;
    uint16_t MinorOperatingSystemVersion = 0;
    uint16_t MajorImageVersion           = 0;
    uint16_t MinorImageVersion           = 0;
    uint16_t MajorSubsystemVersion       = 0;
    uint16_t MinorSubsystemVersion       = 0;
    uint32_t Win32VersionValue           = 0;
    uint32_t SizeOfImage                 = 0;
    uint32_t SizeOfHeaders               = 0;
    uint32_t CheckSum                    = 0;
    uint16_t Subsystem                   = 0;
    uint16_t DllCharacteristics          = 0;
    uint32_t SizeOfStackReserve          = 0x100000;
    uint32_t SizeOfStackCommit           = 0x1000;
    uint32_t SizeOfHeapReserve           = 0x100000;
    uint32_t SizeOfHeapCommit            = 0x1000;
    uint32_t LoaderFlags                 = 0;
    uint32_t NumberOfRvaAndSizes         = 16;
    IMAGE_DATA_DIRECTORY DataDirectory[16];

    size_t sizeof_obj() const override { return 224; }
    std::vector<uint8_t> get_bytes() const override {
        constexpr size_t SZ = 224;
        std::vector<uint8_t> b(SZ, 0);
        speakeasy::write_le(b, 0,  Magic, 2);
        b[2] = MajorLinkerVersion;
        b[3] = MinorLinkerVersion;
        speakeasy::write_le(b, 4,  SizeOfCode, 4);
        speakeasy::write_le(b, 8,  SizeOfInitializedData, 4);
        speakeasy::write_le(b, 12, SizeOfUninitializedData, 4);
        speakeasy::write_le(b, 16, AddressOfEntryPoint, 4);
        speakeasy::write_le(b, 20, BaseOfCode, 4);
        speakeasy::write_le(b, 24, BaseOfData, 4);
        speakeasy::write_le(b, 28, ImageBase, 4);
        speakeasy::write_le(b, 32, SectionAlignment, 4);
        speakeasy::write_le(b, 36, FileAlignment, 4);
        speakeasy::write_le(b, 40, MajorOperatingSystemVersion, 2);
        speakeasy::write_le(b, 42, MinorOperatingSystemVersion, 2);
        speakeasy::write_le(b, 44, MajorImageVersion, 2);
        speakeasy::write_le(b, 46, MinorImageVersion, 2);
        speakeasy::write_le(b, 48, MajorSubsystemVersion, 2);
        speakeasy::write_le(b, 50, MinorSubsystemVersion, 2);
        speakeasy::write_le(b, 52, Win32VersionValue, 4);
        speakeasy::write_le(b, 56, SizeOfImage, 4);
        speakeasy::write_le(b, 60, SizeOfHeaders, 4);
        speakeasy::write_le(b, 64, CheckSum, 4);
        speakeasy::write_le(b, 68, Subsystem, 2);
        speakeasy::write_le(b, 70, DllCharacteristics, 2);
        speakeasy::write_le(b, 72, SizeOfStackReserve, 4);
        speakeasy::write_le(b, 76, SizeOfStackCommit, 4);
        speakeasy::write_le(b, 80, SizeOfHeapReserve, 4);
        speakeasy::write_le(b, 84, SizeOfHeapCommit, 4);
        speakeasy::write_le(b, 88, LoaderFlags, 4);
        speakeasy::write_le(b, 92, NumberOfRvaAndSizes, 4);
        for (size_t i = 0; i < 16; ++i) {
            auto dd = DataDirectory[i].get_bytes();
            std::copy(dd.begin(), dd.end(), b.begin() + 96 + i * 8);
        }
        return b;
    }
};

// IMAGE_OPTIONAL_HEADER64
struct IMAGE_OPTIONAL_HEADER64 : speakeasy::EmuStruct {
    uint16_t Magic                       = 0x20B;
    uint8_t  MajorLinkerVersion          = 0;
    uint8_t  MinorLinkerVersion          = 0;
    uint32_t SizeOfCode                  = 0;
    uint32_t SizeOfInitializedData       = 0;
    uint32_t SizeOfUninitializedData     = 0;
    uint32_t AddressOfEntryPoint         = 0;
    uint32_t BaseOfCode                  = 0;
    uint64_t ImageBase                   = 0x140000000;
    uint32_t SectionAlignment            = 0x1000;
    uint32_t FileAlignment               = 0x200;
    uint16_t MajorOperatingSystemVersion = 0;
    uint16_t MinorOperatingSystemVersion = 0;
    uint16_t MajorImageVersion           = 0;
    uint16_t MinorImageVersion           = 0;
    uint16_t MajorSubsystemVersion       = 0;
    uint16_t MinorSubsystemVersion       = 0;
    uint32_t Win32VersionValue           = 0;
    uint32_t SizeOfImage                 = 0;
    uint32_t SizeOfHeaders               = 0;
    uint32_t CheckSum                    = 0;
    uint16_t Subsystem                   = 0;
    uint16_t DllCharacteristics          = 0;
    uint64_t SizeOfStackReserve          = 0x100000;
    uint64_t SizeOfStackCommit           = 0x1000;
    uint64_t SizeOfHeapReserve           = 0x100000;
    uint64_t SizeOfHeapCommit            = 0x1000;
    uint32_t LoaderFlags                 = 0;
    uint32_t NumberOfRvaAndSizes         = 16;
    IMAGE_DATA_DIRECTORY DataDirectory[16];

    size_t sizeof_obj() const override { return 240; }
    std::vector<uint8_t> get_bytes() const override {
        constexpr size_t SZ = 240;
        std::vector<uint8_t> b(SZ, 0);
        speakeasy::write_le(b, 0,  Magic, 2);
        b[2] = MajorLinkerVersion;
        b[3] = MinorLinkerVersion;
        speakeasy::write_le(b, 4,  SizeOfCode, 4);
        speakeasy::write_le(b, 8,  SizeOfInitializedData, 4);
        speakeasy::write_le(b, 12, SizeOfUninitializedData, 4);
        speakeasy::write_le(b, 16, AddressOfEntryPoint, 4);
        speakeasy::write_le(b, 20, BaseOfCode, 4);
        speakeasy::write_le(b, 24, ImageBase, 8);
        speakeasy::write_le(b, 32, SectionAlignment, 4);
        speakeasy::write_le(b, 36, FileAlignment, 4);
        speakeasy::write_le(b, 40, MajorOperatingSystemVersion, 2);
        speakeasy::write_le(b, 42, MinorOperatingSystemVersion, 2);
        speakeasy::write_le(b, 44, MajorImageVersion, 2);
        speakeasy::write_le(b, 46, MinorImageVersion, 2);
        speakeasy::write_le(b, 48, MajorSubsystemVersion, 2);
        speakeasy::write_le(b, 50, MinorSubsystemVersion, 2);
        speakeasy::write_le(b, 52, Win32VersionValue, 4);
        speakeasy::write_le(b, 56, SizeOfImage, 4);
        speakeasy::write_le(b, 60, SizeOfHeaders, 4);
        speakeasy::write_le(b, 64, CheckSum, 4);
        speakeasy::write_le(b, 68, Subsystem, 2);
        speakeasy::write_le(b, 70, DllCharacteristics, 2);
        speakeasy::write_le(b, 72, SizeOfStackReserve, 8);
        speakeasy::write_le(b, 80, SizeOfStackCommit, 8);
        speakeasy::write_le(b, 88, SizeOfHeapReserve, 8);
        speakeasy::write_le(b, 96, SizeOfHeapCommit, 8);
        speakeasy::write_le(b, 104, LoaderFlags, 4);
        speakeasy::write_le(b, 108, NumberOfRvaAndSizes, 4);
        for (size_t i = 0; i < 16; ++i) {
            auto dd = DataDirectory[i].get_bytes();
            std::copy(dd.begin(), dd.end(), b.begin() + 112 + i * 8);
        }
        return b;
    }
};

// IMAGE_NT_HEADERS32
struct IMAGE_NT_HEADERS32 : speakeasy::EmuStruct {
    uint32_t Signature = 0x4550;  // "PE\0\0"
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER32 OptionalHeader;

    size_t sizeof_obj() const override { return 248; }
    std::vector<uint8_t> get_bytes() const override {
        constexpr size_t SZ = 248;
        std::vector<uint8_t> b(SZ, 0);
        speakeasy::write_le(b, 0, Signature, 4);
        auto fh = FileHeader.get_bytes();
        std::copy(fh.begin(), fh.end(), b.begin() + 4);
        auto oh = OptionalHeader.get_bytes();
        std::copy(oh.begin(), oh.end(), b.begin() + 24);
        return b;
    }
};

// IMAGE_NT_HEADERS64
struct IMAGE_NT_HEADERS64 : speakeasy::EmuStruct {
    uint32_t Signature = 0x4550;  // "PE\0\0"
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;

    size_t sizeof_obj() const override { return 264; }
    std::vector<uint8_t> get_bytes() const override {
        constexpr size_t SZ = 264;
        std::vector<uint8_t> b(SZ, 0);
        speakeasy::write_le(b, 0, Signature, 4);
        auto fh = FileHeader.get_bytes();
        std::copy(fh.begin(), fh.end(), b.begin() + 4);
        auto oh = OptionalHeader.get_bytes();
        std::copy(oh.begin(), oh.end(), b.begin() + 24);
        return b;
    }
};

// IMAGE_SECTION_HEADER
struct IMAGE_SECTION_HEADER : speakeasy::EmuStruct {
    uint8_t  Name[8]                = {};
    uint32_t VirtualSize            = 0;
    uint32_t VirtualAddress         = 0;
    uint32_t SizeOfRawData          = 0;
    uint32_t PointerToRawData       = 0;
    uint32_t PointerToRelocations   = 0;
    uint32_t PointerToLinenumbers   = 0;
    uint16_t NumberOfRelocations    = 0;
    uint16_t NumberOfLinenumbers    = 0;
    uint32_t Characteristics        = 0;

    size_t sizeof_obj() const override { return 40; }
    std::vector<uint8_t> get_bytes() const override {
        std::vector<uint8_t> b(40, 0);
        for (size_t i = 0; i < 8; ++i)
            b[i] = Name[i];
        speakeasy::write_le(b, 8,  VirtualSize, 4);
        speakeasy::write_le(b, 12, VirtualAddress, 4);
        speakeasy::write_le(b, 16, SizeOfRawData, 4);
        speakeasy::write_le(b, 20, PointerToRawData, 4);
        speakeasy::write_le(b, 24, PointerToRelocations, 4);
        speakeasy::write_le(b, 28, PointerToLinenumbers, 4);
        speakeasy::write_le(b, 32, NumberOfRelocations, 2);
        speakeasy::write_le(b, 34, NumberOfLinenumbers, 2);
        speakeasy::write_le(b, 36, Characteristics, 4);
        return b;
    }
};

// ── PE Constants ───────────────────────────────────────────────

// Machine types
#ifndef IMAGE_FILE_MACHINE_I386
constexpr uint16_t IMAGE_FILE_MACHINE_I386   = 0x014C;
constexpr uint16_t IMAGE_FILE_MACHINE_AMD64  = 0x8664;
constexpr uint16_t IMAGE_FILE_MACHINE_IA64   = 0x0200;
constexpr uint16_t IMAGE_FILE_MACHINE_THUMB  = 0x01C2;
constexpr uint16_t IMAGE_FILE_MACHINE_ARM64  = 0xAA64;
#endif

// Section characteristics
#ifndef IMAGE_SCN_CNT_CODE
constexpr uint32_t IMAGE_SCN_CNT_CODE               = 0x00000020;
constexpr uint32_t IMAGE_SCN_CNT_INITIALIZED_DATA    = 0x00000040;
constexpr uint32_t IMAGE_SCN_CNT_UNINITIALIZED_DATA  = 0x00000080;
constexpr uint32_t IMAGE_SCN_MEM_EXECUTE             = 0x20000000;
constexpr uint32_t IMAGE_SCN_MEM_READ                = 0x40000000;
constexpr uint32_t IMAGE_SCN_MEM_WRITE               = 0x80000000;
#endif

// Subsystem
#ifndef IMAGE_SUBSYSTEM_NATIVE
constexpr uint16_t IMAGE_SUBSYSTEM_NATIVE          = 1;
constexpr uint16_t IMAGE_SUBSYSTEM_WINDOWS_GUI     = 2;
constexpr uint16_t IMAGE_SUBSYSTEM_WINDOWS_CUI     = 3;
#endif

// File header characteristics
#ifndef IMAGE_FILE_RELOCS_STRIPPED
constexpr uint16_t IMAGE_FILE_RELOCS_STRIPPED       = 0x0001;
constexpr uint16_t IMAGE_FILE_EXECUTABLE_IMAGE      = 0x0002;
constexpr uint16_t IMAGE_FILE_LINE_NUMS_STRIPPED    = 0x0004;
constexpr uint16_t IMAGE_FILE_LOCAL_SYMS_STRIPPED   = 0x0008;
constexpr uint16_t IMAGE_FILE_AGGRESSIVE_WS_TRIM    = 0x0010;
constexpr uint16_t IMAGE_FILE_LARGE_ADDRESS_AWARE   = 0x0020;
constexpr uint16_t IMAGE_FILE_BYTES_REVERSED_LO     = 0x0080;
constexpr uint16_t IMAGE_FILE_32BIT_MACHINE         = 0x0100;
constexpr uint16_t IMAGE_FILE_DEBUG_STRIPPED        = 0x0200;
constexpr uint16_t IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP = 0x0400;
constexpr uint16_t IMAGE_FILE_NET_RUN_FROM_SWAP     = 0x0800;
constexpr uint16_t IMAGE_FILE_SYSTEM                = 0x1000;
constexpr uint16_t IMAGE_FILE_DLL                   = 0x2000;
constexpr uint16_t IMAGE_FILE_UP_SYSTEM_ONLY        = 0x4000;
#endif

// DllCharacteristics
#ifndef IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
constexpr uint16_t IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040;
constexpr uint16_t IMAGE_DLLCHARACTERISTICS_NX_COMPAT    = 0x0100;
#endif

}}} // namespaces

#endif // SPEAKEASY_DEFS_WINDOWS_WINDEF_H
