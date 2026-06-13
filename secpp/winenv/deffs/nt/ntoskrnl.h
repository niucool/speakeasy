// ntoskrnl.h  Windows NT kernel type definitions (new EmuStructHelper CRTP)
//
// Maps to: speakeasy/winenv/defs/nt/ntoskrnl.py
//
// Uses the new EmuStructHelper CRTP approach for auto serialize/deserialize.
// All structs use #pragma pack(push, 1) with explicit padding fields to match
// the sizeof() that Python ctypes (natural C ABI alignment) would produce.
//
// Namespace speakeasy::deffs::nt to avoid conflicts with existing defs.
//
// NOTE: Core structs (LIST_ENTRY, UNICODE_STRING, STRING, OBJECT_ATTRIBUTES,
// IO_STATUS_BLOCK, LARGE_INTEGER, KSYSTEM_TIME, SYSTEM_TIMEOFDAY_INFORMATION,
// DISK_EXTENT, VOLUME_DISK_EXTENTS) are defined below.

#ifndef SPEAKEASY_DEFS_NEW_NT_NTOSKRNL_H
#define SPEAKEASY_DEFS_NEW_NT_NTOSKRNL_H

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include "struct.h"

namespace speakeasy { namespace deffs { namespace nt {

#pragma pack(push, 1)

// 
// Core POD types defined FIRST (needed as nested members)
// 

//  LIST_ENTRY_POD 
template <int PtrSize>
struct LIST_ENTRY_POD;
template <>
struct LIST_ENTRY_POD<4> {
    uint32_t Flink = 0;
    uint32_t Blink = 0;
};
template <>
struct LIST_ENTRY_POD<8> {
    uint64_t Flink = 0;
    uint64_t Blink = 0;
};

//  UNICODE_STRING_POD 
template <int PtrSize>
struct UNICODE_STRING_POD;
template <>
struct UNICODE_STRING_POD<4> {
    uint16_t Length = 0;
    uint16_t MaximumLength = 0;
    uint32_t Buffer = 0;
};
template <>
struct UNICODE_STRING_POD<8> {
    uint16_t Length = 0;
    uint16_t MaximumLength = 0;
    uint32_t padding = 0;
    uint64_t Buffer = 0;
};

//  IO_STATUS_BLOCK_POD 
template <int PtrSize>
struct IO_STATUS_BLOCK_POD;
template <>
struct IO_STATUS_BLOCK_POD<4> {
    uint32_t Status = 0;
    uint32_t Information = 0;
};
template <>
struct IO_STATUS_BLOCK_POD<8> {
    uint64_t Status = 0;
    uint64_t Information = 0;
};

//  KEVENT_POD (4096-byte opaque event object) 
struct KEVENT_POD { uint8_t Data[4096] = {}; };

// ==========================================================================================================
// Helper: embed UNICODE_STRING<PtrSize> fields in a struct.
// UNICODE_STRING<4> layout: uint16 + uint16 + uint32 = 8 bytes (N must be 4-aligned)
// UNICODE_STRING<8> layout: uint16 + uint16 + uint32 pad + uint64 = 16 bytes (N must be 8-aligned)
// ==========================================================================================================
template <int PtrSize>
struct US_ALIGNMENT {};
template <> struct US_ALIGNMENT<4> { static constexpr int value = 4; };
template <> struct US_ALIGNMENT<8> { static constexpr int value = 8; };

// Compute padding needed to reach alignment
inline constexpr uint32_t align_up(uint32_t offset, uint32_t alignment) {
    return (offset + alignment - 1) & ~(alignment - 1);
}

// ==========================================================================================================
// ------ SSDT (KeServiceDescriptorTable) ------------------------------------------------------------------
// ==========================================================================================================
template <int PtrSize>
struct SSDT_POD;

template <>
struct SSDT_POD<4> {
    uint32_t pServiceTable   = 0;  // offset  0
    uint32_t pCounterTable   = 0;  // offset  4
    uint32_t NumberOfServices = 0; // offset  8
    uint32_t pArgumentTable  = 0;  // offset 12
    // total = 16
};
// x64: Ptr(8)+Ptr(8)+uint32(4)+pad(4)+Ptr(8) = 32
template <>
struct SSDT_POD<8> {
    uint64_t pServiceTable    = 0; // offset  0
    uint64_t pCounterTable    = 0; // offset  8
    uint32_t NumberOfServices = 0; // offset 16
    uint32_t pad              = 0; // offset 20  align next Ptr to 8
    uint64_t pArgumentTable   = 0; // offset 24
    // total = 32
};
template <int PtrSize>
struct SSDT : public EmuStructHelper<SSDT<PtrSize>>, public SSDT_POD<PtrSize> {
    std::string get_mem_tag() const override { return "ssdt"; }
};

// ==========================================================================================================
// ------ DeviceIoControl ----------------------------------------------------------------------------------
// ==========================================================================================================
template <int PtrSize>
struct DeviceIoControl_POD;

// x86: 3*uint32(12) + Ptr(4) = 16
template <>
struct DeviceIoControl_POD<4> {
    uint32_t OutputBufferLength = 0; // offset  0
    uint32_t InputBufferLength  = 0; // offset  4
    uint32_t IoControlCode      = 0; // offset  8
    uint32_t Type3InputBuffer   = 0; // offset 12
    // total = 16
};
// x64: 3*uint32(12) + pad(4) + Ptr(8) = 24
template <>
struct DeviceIoControl_POD<8> {
    uint32_t OutputBufferLength = 0; // offset  0
    uint32_t InputBufferLength  = 0; // offset  4
    uint32_t IoControlCode      = 0; // offset  8
    uint32_t pad                = 0; // offset 12  align Type3InputBuffer
    uint64_t Type3InputBuffer   = 0; // offset 16
    // total = 24
};
template <int PtrSize>
struct DeviceIoControl : public EmuStructHelper<DeviceIoControl<PtrSize>>, public DeviceIoControl_POD<PtrSize> {
    std::string get_mem_tag() const override { return "device_io_control"; }
};

// ==========================================================================================================
// ------ SYSTEM_MODULE -------------------------------------------------------------------------------------
// ==========================================================================================================
// x86: 2*Ptr(8) + Ptr(4) + 4*uint32(16) + 4*uint16(8) + uint8[256] = 296... wait let me recalculate
// Reserved = 2 * Ptr on x86 = 8 bytes
// Base = Ptr = 4 bytes
// Size = u32 = 4, Flags = u32 = 4, Index = u16 = 2, Unknown = u16 = 2, LoadCount = u16 = 2, ModuleNameOffset = u16 = 2
// ImageName = u8[256]
// Total x86: 8 + 4 + 4 + 4 + 2 + 2 + 2 + 2 + 256 = 284
template <int PtrSize>
struct SYSTEM_MODULE_POD;

template <>
struct SYSTEM_MODULE_POD<4> {
    uint32_t Reserved[2]      = {};  // offset  0  (2*4 = 8)
    uint32_t Base             = 0;   // offset  8
    uint32_t Size             = 0;   // offset 12
    uint32_t Flags            = 0;   // offset 16
    uint16_t Index            = 0;   // offset 20
    uint16_t Unknown          = 0;   // offset 22
    uint16_t LoadCount        = 0;   // offset 24
    uint16_t ModuleNameOffset = 0;   // offset 26
    uint8_t  ImageName[256]   = {};  // offset 28
    // total = 284
};
// x64: 2*Ptr(16) + Ptr(8) + 4*uint32(16) + 4*uint16(8) + uint8[256] = 304
// Reserved = 2 * Ptr on x64 = 16 bytes
// Base = Ptr = 8 bytes
// Size = u32 = 4, Flags = u32 = 4, Index = u16=2, Unknown=u16=2, LoadCount=u16=2, ModuleNameOffset=u16=2
// ImageName = u8[256]
// Total x64: 16 + 8 + 4 + 4 + 2 + 2 + 2 + 2 + 256 = 296
// Wait, after Flags (u32) at offset 28, Index (u16) at 32 is 2-aligned 
template <>
struct SYSTEM_MODULE_POD<8> {
    uint64_t Reserved[2]      = {};  // offset  0 (2*8 = 16)
    uint64_t Base             = 0;   // offset 16
    uint32_t Size             = 0;   // offset 24
    uint32_t Flags            = 0;   // offset 28
    uint16_t Index            = 0;   // offset 32
    uint16_t Unknown          = 0;   // offset 34
    uint16_t LoadCount        = 0;   // offset 36
    uint16_t ModuleNameOffset = 0;   // offset 38
    uint8_t  ImageName[256]   = {};  // offset 40
    // total = 296
};
template <int PtrSize>
struct SYSTEM_MODULE : public EmuStructHelper<SYSTEM_MODULE<PtrSize>>, public SYSTEM_MODULE_POD<PtrSize> {
    std::string get_mem_tag() const override { return "system_module"; }
};

// ==========================================================================================================
// ------ CLIENT_ID (ptr-size polymorphic: HANDLE is pointer-sized) -----------------------------------------
// x86: UniqueProcess(4) + UniqueThread(4) = 8
// x64: UniqueProcess(8) + UniqueThread(8) = 16
// ==========================================================================================================
template <int PtrSize = sizeof(void*)>
struct CLIENT_ID_POD;

template <>
struct CLIENT_ID_POD<4> {
    uint32_t UniqueProcess = 0; // offset 0
    uint32_t UniqueThread  = 0; // offset 4
    // total = 8
};

template <>
struct CLIENT_ID_POD<8> {
    uint64_t UniqueProcess = 0; // offset 0
    uint64_t UniqueThread  = 0; // offset 8
    // total = 16
};

template <int PtrSize = sizeof(void*)>
struct CLIENT_ID : public EmuStructHelper<CLIENT_ID<PtrSize>>, public CLIENT_ID_POD<PtrSize> {
    std::string get_mem_tag() const override { return "client_id"; }
};

// ==========================================================================================================
// ------ SYSTEM_PROCESS_INFORMATION ------------------------------------------------------------------------
// ==========================================================================================================
// x86 layout:
//   0: NextEntryOffset (u32) = 4
//   4: NumberOfThreads (u32) = 4
//   8: Reserved1[48] = 48 bytes
//  56: UNICODE_STRING<4> ImageName = 8 bytes (uint16+uint16+uint32) - starts at 56, which is 4-aligned 
//  64: BasePriority (u32) = 4
//  68: UniqueProcessId (u32) = 4
//  72: InheritedFromUniqueProcessId (u32) = 4
//  76: HandleCount (u32) = 4
//  80: SessionId (u32) = 4
//  84: UniqueProcessKey (u32) = 4
//  88: PeakVirtualSize (u32) = 4
//  92: VirtualSize (u32) = 4
//  96: PageFaultCount (u32) = 4
// 100: PeakWorkingSetSize (u32) = 4
// 104: WorkingSetSize (u32) = 4
// 108: QuotaPeakPagedPoolUsage (u32) = 4
// 112: QuotaPagedPoolUsage (u32) = 4
// 116: QuotaPeakNonPagedPoolUsage (u32) = 4
// 120: QuotaNonPagedPoolUsage (u32) = 4
// 124: PagefileUsage (u32) = 4
// 128: PeakPagefileUsage (u32) = 4
// 132: PrivatePageCount (u32) = 4
// 136: Reserved7[6] = 6*u64 = 48
// total = 184
//
// x64 layout:
//   0: NextEntryOffset (u32) = 4
//   4: NumberOfThreads (u32) = 4
//   8: Reserved1[48] = 48 bytes
//  56: UNICODE_STRING<8> ImageName = 16 bytes - starts at 56. 56%8=0 
//  72: BasePriority (u32) = 4
//  76: pad (4)  align next Ptr to 8
//  80: UniqueProcessId (u64) = 8
//  88: InheritedFromUniqueProcessId (u64) = 8
//  96: HandleCount (u32) = 4
// 100: SessionId (u32) = 4
// 104: UniqueProcessKey (u64) = 8
// 112: PeakVirtualSize (u64) = 8
// 120: VirtualSize (u64) = 8
// 128: PageFaultCount (u32) = 4
// 132: pad (4)  align PeakWorkingSetSize to 8
// 136: PeakWorkingSetSize (u64) = 8
// 144: WorkingSetSize (u64) = 8
// 152: QuotaPeakPagedPoolUsage (u64) = 8
// 160: QuotaPagedPoolUsage (u64) = 8
// 168: QuotaPeakNonPagedPoolUsage (u64) = 8
// 176: QuotaNonPagedPoolUsage (u64) = 8
// 184: PagefileUsage (u64) = 8
// 192: PeakPagefileUsage (u64) = 8
// 200: PrivatePageCount (u64) = 8
// 208: Reserved7[6] = 48 bytes
// total = 256

template <int PtrSize>
struct SYSTEM_PROCESS_INFORMATION_POD;

template <>
struct SYSTEM_PROCESS_INFORMATION_POD<4> {
    uint32_t NextEntryOffset                 = 0; // offset   0
    uint32_t NumberOfThreads                 = 0; // offset   4
    uint8_t  Reserved1[48]                   = {};// offset   8 (56)
    // UNICODE_STRING<4> ImageName (8 bytes) @ offset 56 (4-aligned )
    uint16_t ImageName_Length                = 0; // offset  56
    uint16_t ImageName_MaximumLength         = 0; // offset  58
    uint32_t ImageName_Buffer                = 0; // offset  60
    uint32_t BasePriority                    = 0; // offset  64
    uint32_t UniqueProcessId                 = 0; // offset  68
    uint32_t InheritedFromUniqueProcessId    = 0; // offset  72
    uint32_t HandleCount                     = 0; // offset  76
    uint32_t SessionId                       = 0; // offset  80
    uint32_t UniqueProcessKey                = 0; // offset  84
    uint32_t PeakVirtualSize                 = 0; // offset  88
    uint32_t VirtualSize                     = 0; // offset  92
    uint32_t PageFaultCount                  = 0; // offset  96
    uint32_t PeakWorkingSetSize              = 0; // offset 100
    uint32_t WorkingSetSize                  = 0; // offset 104
    uint32_t QuotaPeakPagedPoolUsage        = 0; // offset 108
    uint32_t QuotaPagedPoolUsage            = 0; // offset 112
    uint32_t QuotaPeakNonPagedPoolUsage     = 0; // offset 116
    uint32_t QuotaNonPagedPoolUsage         = 0; // offset 120
    uint32_t PagefileUsage                   = 0; // offset 124
    uint32_t PeakPagefileUsage               = 0; // offset 128
    uint32_t PrivatePageCount                = 0; // offset 132
    uint64_t Reserved7[6]                    = {};// offset 136 (48 bytes)
    // total = 184
};

template <>
struct SYSTEM_PROCESS_INFORMATION_POD<8> {
    uint32_t NextEntryOffset                 = 0; // offset   0
    uint32_t NumberOfThreads                 = 0; // offset   4
    uint8_t  Reserved1[48]                   = {};// offset   8 (56)
    // UNICODE_STRING<8> ImageName (16 bytes) @ offset 56 (8-aligned )
    uint16_t ImageName_Length                = 0; // offset  56
    uint16_t ImageName_MaximumLength         = 0; // offset  58
    uint32_t ImageName_pad                   = 0; // offset  60  align Buffer to 8
    uint64_t ImageName_Buffer                = 0; // offset  64
    uint32_t BasePriority                    = 0; // offset  72
    uint32_t pad1                            = 0; // offset  76  align UniqueProcessId to 8
    uint64_t UniqueProcessId                 = 0; // offset  80
    uint64_t InheritedFromUniqueProcessId    = 0; // offset  88
    uint32_t HandleCount                     = 0; // offset  96
    uint32_t SessionId                       = 0; // offset 100
    uint64_t UniqueProcessKey                = 0; // offset 104
    uint64_t PeakVirtualSize                 = 0; // offset 112
    uint64_t VirtualSize                     = 0; // offset 120
    uint32_t PageFaultCount                  = 0; // offset 128
    uint32_t pad2                            = 0; // offset 132  align PeakWorkingSetSize
    uint64_t PeakWorkingSetSize              = 0; // offset 136
    uint64_t WorkingSetSize                  = 0; // offset 144
    uint64_t QuotaPeakPagedPoolUsage        = 0; // offset 152
    uint64_t QuotaPagedPoolUsage            = 0; // offset 160
    uint64_t QuotaPeakNonPagedPoolUsage     = 0; // offset 168
    uint64_t QuotaNonPagedPoolUsage         = 0; // offset 176
    uint64_t PagefileUsage                   = 0; // offset 184
    uint64_t PeakPagefileUsage               = 0; // offset 192
    uint64_t PrivatePageCount                = 0; // offset 200
    uint64_t Reserved7[6]                    = {};// offset 208 (48 bytes)
    // total = 256
};

template <int PtrSize>
struct SYSTEM_PROCESS_INFORMATION : public EmuStructHelper<SYSTEM_PROCESS_INFORMATION<PtrSize>>, public SYSTEM_PROCESS_INFORMATION_POD<PtrSize> {
    std::string get_mem_tag() const override { return "system_process_information"; }
};

// ==========================================================================================================
// ------ SYSTEM_THREAD_INFORMATION -------------------------------------------------------------------------
// ==========================================================================================================
// x86: 3*u64(24) + u32(4) + Ptr(4) + CLIENT_ID(8) + 5*u32(20) = 60
// x64: 3*u64(24) + u32(4) + pad(4) + Ptr(8) + CLIENT_ID(8) + 5*u32(20) = 68
template <int PtrSize>
struct SYSTEM_THREAD_INFORMATION_POD;

template <>
struct SYSTEM_THREAD_INFORMATION_POD<4> {
    uint64_t Reserved1[3]   = {}; // offset  0 (24)
    uint32_t Reserved2      = 0;  // offset 24
    uint32_t StartAddress   = 0;  // offset 28
    CLIENT_ID_POD<4> ClientId;       // offset 32 (nested, size=8)
    uint32_t Priority        = 0;  // offset 40
    uint32_t BasePriority    = 0;  // offset 44
    uint32_t ContextSwitches = 0;  // offset 48
    uint32_t ThreadState      = 0;  // offset 52
    uint32_t WaitReason      = 0;  // offset 56
    // total = 60
};

template <>
struct SYSTEM_THREAD_INFORMATION_POD<8> {
    uint64_t Reserved1[3]   = {}; // offset  0 (24)
    uint32_t Reserved2      = 0;  // offset 24
    uint32_t pad            = 0;  // offset 28  align StartAddress to 8
    uint64_t StartAddress   = 0;  // offset 32
    CLIENT_ID_POD<8> ClientId;       // offset 40 (nested, size=16)
    uint32_t Priority        = 0;  // offset 48
    uint32_t BasePriority    = 0;  // offset 52
    uint32_t ContextSwitches = 0;  // offset 56
    uint32_t ThreadState      = 0;  // offset 60
    uint32_t WaitReason      = 0;  // offset 64
    // total = 68
};

template <int PtrSize>
struct SYSTEM_THREAD_INFORMATION : public EmuStructHelper<SYSTEM_THREAD_INFORMATION<PtrSize>>, public SYSTEM_THREAD_INFORMATION_POD<PtrSize> {
    std::string get_mem_tag() const override { return "system_thread_information"; }
};

// ==========================================================================================================
// ------ MDL (Memory Descriptor List) ----------------------------------------------------------------------
// ==========================================================================================================
// x86: Ptr(4)+u16(2)+u16(2)+Ptr(4)+Ptr(4)+Ptr(4)+u32(4)+u32(4) = 28
// x64: Ptr(8)+u16(2)+u16(2)+pad(4)+Ptr(8)+Ptr(8)+Ptr(8)+u32(4)+u32(4) = 48
template <int PtrSize>
struct MDL_POD;

template <>
struct MDL_POD<4> {
    uint32_t Next           = 0;  // offset  0
    uint16_t Size           = 0;  // offset  4
    uint16_t MdlFlags       = 0;  // offset  6
    uint32_t Process        = 0;  // offset  8
    uint32_t MappedSystemVa = 0;  // offset 12
    uint32_t StartVa        = 0;  // offset 16
    uint32_t ByteCount      = 0;  // offset 20
    uint32_t ByteOffset     = 0;  // offset 24
    // total = 28
};

template <>
struct MDL_POD<8> {
    uint64_t Next           = 0;  // offset  0
    uint16_t Size           = 0;  // offset  8
    uint16_t MdlFlags       = 0;  // offset 10
    uint32_t pad            = 0;  // offset 12  align Process to 8
    uint64_t Process        = 0;  // offset 16
    uint64_t MappedSystemVa = 0;  // offset 24
    uint64_t StartVa        = 0;  // offset 32
    uint32_t ByteCount      = 0;  // offset 40
    uint32_t ByteOffset     = 0;  // offset 44
    // total = 48
};

template <int PtrSize>
struct MDL : public EmuStructHelper<MDL<PtrSize>>, public MDL_POD<PtrSize> {
    std::string get_mem_tag() const override { return "mdl"; }
};

// ==========================================================================================================
// ------ KIDTENTRY (x86 IDT entry, 8 bytes) ----------------------------------------------------------------
// ==========================================================================================================
struct KIDTENTRY_POD {
    uint16_t OffsetLow  = 0; // offset 0
    uint16_t Selector   = 0; // offset 2
    uint32_t Base       = 0; // offset 4
};
struct KIDTENTRY : public EmuStructHelper<KIDTENTRY>, public KIDTENTRY_POD {
    std::string get_mem_tag() const override { return "kidtentry"; }
};

// ==========================================================================================================
// ------ KIDTENTRY64 (x64 IDT entry, 16 bytes) -------------------------------------------------------------
// ==========================================================================================================
struct KIDTENTRY64_POD {
    uint16_t OffsetLow    = 0; // offset  0
    uint16_t Selector     = 0; // offset  2
    uint16_t Reserved0    = 0; // offset  4
    uint16_t OffsetMiddle = 0; // offset  6
    uint32_t OffsetHigh   = 0; // offset  8 (4-aligned )
    uint32_t Reserved1    = 0; // offset 12
};
struct KIDTENTRY64 : public EmuStructHelper<KIDTENTRY64>, public KIDTENTRY64_POD {
    std::string get_mem_tag() const override { return "kidtentry64"; }
};

// ==========================================================================================================
// ------ ETHREAD / EPROCESS / KEVENT / MUTANT (4096-byte opaque objects) ----------------------------------
// ==========================================================================================================
struct ETHREAD_POD { uint8_t Data[4096] = {}; };
struct ETHREAD : public EmuStructHelper<ETHREAD>, public ETHREAD_POD {
    std::string get_mem_tag() const override { return "ethread"; }
};

struct EPROCESS_POD { uint8_t Data[4096] = {}; };
struct EPROCESS : public EmuStructHelper<EPROCESS>, public EPROCESS_POD {
    std::string get_mem_tag() const override { return "eprocess"; }
};

// KEVENT_POD defined at top of file
struct KEVENT : public EmuStructHelper<KEVENT>, public KEVENT_POD {
    std::string get_mem_tag() const override { return "kevent"; }
};

struct MUTANT_POD { uint8_t Data[4096] = {}; };
struct MUTANT : public EmuStructHelper<MUTANT>, public MUTANT_POD {
    std::string get_mem_tag() const override { return "mutant"; }
};

// ==========================================================================================================
// ------ RTL_OSVERSIONINFOW (5*uint32 + uint8[256] = 276 bytes) -------------------------------------------
// ==========================================================================================================
struct RTL_OSVERSIONINFOW_POD {
    uint32_t dwOSVersionInfoSize = 0; // offset   0
    uint32_t dwMajorVersion     = 0; // offset   4
    uint32_t dwMinorVersion     = 0; // offset   8
    uint32_t dwBuildNumber      = 0; // offset  12
    uint32_t dwPlatformId       = 0; // offset  16
    uint8_t  szCSDVersion[256]  = {}; // offset  20
    // total = 276
};
struct RTL_OSVERSIONINFOW : public EmuStructHelper<RTL_OSVERSIONINFOW>, public RTL_OSVERSIONINFOW_POD {
    std::string get_mem_tag() const override { return "rtl_osversioninfow"; }
};

// ==========================================================================================================
// ------ RTL_OSVERSIONINFOEXW (276 + 8 = 284 bytes) -------------------------------------------------------
// ==========================================================================================================
struct RTL_OSVERSIONINFOEXW_POD {
    uint32_t dwOSVersionInfoSize = 0; // offset   0
    uint32_t dwMajorVersion     = 0; // offset   4
    uint32_t dwMinorVersion     = 0; // offset   8
    uint32_t dwBuildNumber      = 0; // offset  12
    uint32_t dwPlatformId       = 0; // offset  16
    uint8_t  szCSDVersion[256]  = {}; // offset  20 (276)
    uint16_t wServicePackMajor = 0;  // offset 276
    uint16_t wServicePackMinor = 0;  // offset 278
    uint16_t wSuiteMask        = 0;  // offset 280
    uint8_t  wProductType      = 0;  // offset 282
    uint8_t  wReserved         = 0;  // offset 283
    // total = 284
};
struct RTL_OSVERSIONINFOEXW : public EmuStructHelper<RTL_OSVERSIONINFOEXW>, public RTL_OSVERSIONINFOEXW_POD {
    std::string get_mem_tag() const override { return "rtl_osversioninfoexw"; }
};

// ==========================================================================================================
// ------ IDT (Interrupt Descriptor Table) ------------------------------------------------------------------
// ==========================================================================================================
// x86: u16(2) + Ptr(4) = 6
// x64: u16(2) + pad(6) + Ptr(8) = 16
template <int PtrSize>
struct IDT_POD;

template <>
struct IDT_POD<4> {
    uint16_t Limit       = 0; // offset 0
    uint32_t Descriptors = 0; // offset 2 (2 bytes after uint16, 4-aligned )
    // total = 6
};

template <>
struct IDT_POD<8> {
    uint16_t Limit       = 0; // offset 0
    uint8_t  pad[6]      = {}; // offset 2  align Descriptors to 8
    uint64_t Descriptors = 0; // offset 8
    // total = 16
};

template <int PtrSize>
struct IDT : public EmuStructHelper<IDT<PtrSize>>, public IDT_POD<PtrSize> {
    std::string get_mem_tag() const override { return "idt"; }
};

// ==========================================================================================================
// ------ KAPC (Kernel Asynchronous Procedure Call) ---------------------------------------------------------
// ==========================================================================================================
// x86: 4*u8(4) + u32(4) + Ptr(4) + LIST_ENTRY(8) + 6*Ptr(24) + 3*u8(3) = 47  round to 48
// x64: 4*u8(4) + u32(4) + Ptr(8) + LIST_ENTRY(16) + 6*Ptr(48) + 3*u8(3) = 83  round to 88
// NOTE: LIST_ENTRY starts immediately after Thread; the LIST_ENTRY fields are:
//   Flink (pointer), Blink (pointer)
template <int PtrSize>
struct KAPC_POD;

template <>
struct KAPC_POD<4> {
    uint8_t  Type         = 0;   // offset  0
    uint8_t  SpareByte0   = 0;   // offset  1
    uint8_t  Size         = 0;   // offset  2
    uint8_t  SpareByte1   = 0;   // offset  3
    uint32_t SpareLong0   = 0;   // offset  4
    uint32_t Thread       = 0;   // offset  8  (4-aligned )
    LIST_ENTRY_POD<4> ApcListEntry;     // offset 12 (nested, size=8)
    uint32_t KernelRoutine  = 0;     // offset 20
    uint32_t RundownRoutine = 0;     // offset 24
    uint32_t NormalRoutine  = 0;     // offset 28
    uint32_t NormalContext  = 0;     // offset 32
    uint32_t SystemArgument1 = 0;    // offset 36
    uint32_t SystemArgument2 = 0;    // offset 40
    uint8_t  ApcStateIndex  = 0;     // offset 44
    uint8_t  ApcMode        = 0;     // offset 45
    uint8_t  Inserted       = 0;     // offset 46
    // total = 47
};

template <>
struct KAPC_POD<8> {
    uint8_t  Type         = 0;   // offset  0
    uint8_t  SpareByte0   = 0;   // offset  1
    uint8_t  Size         = 0;   // offset  2
    uint8_t  SpareByte1   = 0;   // offset  3
    uint32_t SpareLong0   = 0;   // offset  4
    // NOTE: offset 8 is 8-aligned, so Thread goes at offset 8 
    uint64_t Thread       = 0;   // offset  8
    LIST_ENTRY_POD<8> ApcListEntry;     // offset 16 (nested, size=16)
    uint64_t KernelRoutine  = 0;     // offset 32
    uint64_t RundownRoutine = 0;     // offset 40
    uint64_t NormalRoutine  = 0;     // offset 48
    uint64_t NormalContext  = 0;     // offset 56
    uint64_t SystemArgument1 = 0;    // offset 64
    uint64_t SystemArgument2 = 0;    // offset 72
    uint8_t  ApcStateIndex  = 0;     // offset 80
    uint8_t  ApcMode        = 0;     // offset 81
    uint8_t  Inserted       = 0;     // offset 82
    // total = 83 (natural C alignment would round up to 88)
};

template <int PtrSize>
struct KAPC : public EmuStructHelper<KAPC<PtrSize>>, public KAPC_POD<PtrSize> {
    std::string get_mem_tag() const override { return "kapc"; }
};

// ==========================================================================================================
// ------ FILE_STANDARD_INFORMATION (24 bytes) --------------------------------------------------------------
// ==========================================================================================================
// LARGE_INTEGER_POD defined here (used by FILE_STANDARD_INFORMATION and FILE_OBJECT)
// Full definition at end of file alongside LARGE_INTEGER wrapper
struct LARGE_INTEGER_POD {
    uint64_t QuadPart = 0;  // offset 0, total 8
};
struct FILE_STANDARD_INFORMATION_POD {
    LARGE_INTEGER_POD AllocationSize;   // offset  0
    LARGE_INTEGER_POD EndOfFile;        // offset  8
    uint32_t NumberOfLinks   = 0; // offset 16
    uint8_t  DeletePending   = 0; // offset 20
    uint8_t  Directory       = 0; // offset 21
    // total = 22 (natural alignment would pad to 24)
};
struct FILE_STANDARD_INFORMATION : public EmuStructHelper<FILE_STANDARD_INFORMATION>, public FILE_STANDARD_INFORMATION_POD {
    std::string get_mem_tag() const override { return "file_standard_information"; }
};

// ==========================================================================================================
// ------ DESCRIPTOR_TABLE (x86: 256*KIDTENTRY, x64: 256*KIDTENTRY64) -------------------------------------
// ==========================================================================================================
template <int PtrSize>
struct DESCRIPTOR_TABLE_POD;

template <>
struct DESCRIPTOR_TABLE_POD<4> {
    KIDTENTRY_POD Table[256] = {};
};
template <>
struct DESCRIPTOR_TABLE_POD<8> {
    KIDTENTRY64_POD Table[256] = {};
};
template <int PtrSize>
struct DESCRIPTOR_TABLE : public EmuStructHelper<DESCRIPTOR_TABLE<PtrSize>>, public DESCRIPTOR_TABLE_POD<PtrSize> {
    std::string get_mem_tag() const override { return "descriptor_table"; }
};

// ==========================================================================================================
// ------ DRIVER_OBJECT -------------------------------------------------------------------------------------
// ==========================================================================================================
// x86: u16+u16+Ptr(4)+u32+Ptr(4)+u32+Ptr(4)+Ptr(4)+UNICODE_STRING(8)+Ptr(4)+Ptr(4)+Ptr(4)+Ptr(4)+Ptr(4)+28*Ptr(112)
// Let me compute precisely:
//   0: Type(u16)=2, Size(u16)=2 [4]
//   4: DeviceObject(Ptr=4) [8]
//   8: Flags(u32)=4 [12]
//  12: DriverStart(Ptr=4) [16]
//  16: DriverSize(u32)=4 [20]
//  20: DriverSection(Ptr=4) [24]
//  24: DriverExtension(Ptr=4) [28]
//  28: UNICODE_STRING(8) [36]
//  36: HardwareDatabase(Ptr=4) [40]
//  40: FastIoDispatch(Ptr=4) [44]
//  44: DriverInit(Ptr=4) [48]
//  48: DriverStartIo(Ptr=4) [52]
//  52: DriverUnload(Ptr=4) [56]
//  56: MajorFunction[28] (28*4=112) [168]
// total = 168
//
// x64:
//   0: Type(u16)=2, Size(u16)=2 [4]
//   4: pad1(4) align DeviceObject to 8 [8]
//   8: DeviceObject(Ptr=8) [16]
//  16: Flags(u32)=4 [20]
//  20: pad2(4) align DriverStart to 8 [24]
//  24: DriverStart(Ptr=8) [32]
//  32: DriverSize(u32)=4 [36]
//  36: pad3(4) align DriverSection to 8 [40]
//  40: DriverSection(Ptr=8) [48]
//  48: DriverExtension(Ptr=8) [56]
//  56: UNICODE_STRING(16) [72]
//  72: HardwareDatabase(Ptr=8) [80]
//  80: FastIoDispatch(Ptr=8) [88]
//  88: DriverInit(Ptr=8) [96]
//  96: DriverStartIo(Ptr=8) [104]
// 104: DriverUnload(Ptr=8) [112]
// 112: MajorFunction[28] (28*8=224) [336]
// total = 336
template <int PtrSize>
struct DRIVER_OBJECT_POD;

template <>
struct DRIVER_OBJECT_POD<4> {
    uint16_t Type              = 0;  // offset   0
    uint16_t Size              = 0;  // offset   2
    uint32_t DeviceObject      = 0;  // offset   4
    uint32_t Flags             = 0;  // offset   8
    uint32_t DriverStart       = 0;  // offset  12
    uint32_t DriverSize        = 0;  // offset  16
    uint32_t DriverSection     = 0;  // offset  20
    uint32_t DriverExtension   = 0;  // offset  24
    UNICODE_STRING_POD<4> DriverName;    // offset  28 (nested, size=8)
    uint32_t HardwareDatabase   = 0;  // offset  36
    uint32_t FastIoDispatch     = 0;  // offset  40
    uint32_t DriverInit         = 0;  // offset  44
    uint32_t DriverStartIo      = 0;  // offset  48
    uint32_t DriverUnload       = 0;  // offset  52
    uint32_t MajorFunction[28]  = {}; // offset  56 (112 bytes)
    // total = 168
};

template <>
struct DRIVER_OBJECT_POD<8> {
    uint16_t Type              = 0;  // offset   0
    uint16_t Size              = 0;  // offset   2
    uint32_t pad1              = 0;  // offset   4  align DeviceObject to 8
    uint64_t DeviceObject      = 0;  // offset   8
    uint32_t Flags             = 0;  // offset  16
    uint32_t pad2              = 0;  // offset  20  align DriverStart to 8
    uint64_t DriverStart       = 0;  // offset  24
    uint32_t DriverSize        = 0;  // offset  32
    uint32_t pad3              = 0;  // offset  36  align DriverSection to 8
    uint64_t DriverSection     = 0;  // offset  40
    uint64_t DriverExtension   = 0;  // offset  48
    UNICODE_STRING_POD<8> DriverName;    // offset  56 (nested, size=16)
    uint64_t HardwareDatabase   = 0;  // offset  72
    uint64_t FastIoDispatch     = 0;  // offset  80
    uint64_t DriverInit         = 0;  // offset  88
    uint64_t DriverStartIo      = 0;  // offset  96
    uint64_t DriverUnload       = 0;  // offset 104
    uint64_t MajorFunction[28]  = {}; // offset 112 (224 bytes)
    // total = 336
};

template <int PtrSize>
struct DRIVER_OBJECT : public EmuStructHelper<DRIVER_OBJECT<PtrSize>>, public DRIVER_OBJECT_POD<PtrSize> {
    std::string get_mem_tag() const override { return "driver_object"; }
};

// ==========================================================================================================
// ------ KDEVICE_QUEUE -------------------------------------------------------------------------------------
// ==========================================================================================================
// x86: u16(2)+u16(2)+LIST_ENTRY(8)+u64(8)+u8(1) = 21  round to 24
// x64: u16(2)+u16(2)+pad(4)+LIST_ENTRY(16)+u64(8)+u8(1) = 33  round to 40
template <int PtrSize>
struct KDEVICE_QUEUE_POD;

template <>
struct KDEVICE_QUEUE_POD<4> {
    uint16_t Type = 0;   // offset  0
    uint16_t Size = 0;   // offset  2
    LIST_ENTRY_POD<4> DeviceListHead;   // offset  4 (nested, size=8)
    uint64_t Lock                = 0;  // offset 12
    uint8_t  Busy                = 0;  // offset 20
    // total = 21
};

template <>
struct KDEVICE_QUEUE_POD<8> {
    uint16_t Type = 0;   // offset  0
    uint16_t Size = 0;   // offset  2
    uint32_t pad1 = 0;   // offset  4  align LIST_ENTRY to 8
    LIST_ENTRY_POD<8> DeviceListHead;   // offset  8 (nested, size=16)
    uint64_t Lock                = 0;  // offset 24
    uint8_t  Busy                = 0;  // offset 32
    // total = 33
};

template <int PtrSize>
struct KDEVICE_QUEUE : public EmuStructHelper<KDEVICE_QUEUE<PtrSize>>, public KDEVICE_QUEUE_POD<PtrSize> {
    std::string get_mem_tag() const override { return "kdevice_queue"; }
};

// ==========================================================================================================
// ------ KDPC (Deferred Procedure Call) --------------------------------------------------------------------
// ==========================================================================================================
// x86: u8+u8+u16(4)+LIST_ENTRY(8)+5*Ptr(20)+Ptr(4) = 36
// x64: u8+u8+u16(4)+pad(4)+LIST_ENTRY(16)+5*Ptr(40)+Ptr(8) = 72
template <int PtrSize>
struct KDPC_POD;

template <>
struct KDPC_POD<4> {
    uint8_t  Type          = 0;  // offset  0
    uint8_t  Importance    = 0;  // offset  1
    uint16_t Number        = 0;  // offset  2
    LIST_ENTRY_POD<4> DpcListEntry;     // offset  4 (nested, size=8)
    uint32_t DeferredRoutine   = 0;      // offset 12
    uint32_t DeferredContext   = 0;      // offset 16
    uint32_t SystemArgument1   = 0;      // offset 20
    uint32_t SystemArgument2   = 0;      // offset 24
    uint32_t DpcData           = 0;      // offset 28
    // total = 32
};

template <>
struct KDPC_POD<8> {
    uint8_t  Type          = 0;  // offset  0
    uint8_t  Importance    = 0;  // offset  1
    uint16_t Number        = 0;  // offset  2
    uint32_t pad1          = 0;  // offset  4  align LIST_ENTRY to 8
    LIST_ENTRY_POD<8> DpcListEntry;     // offset  8 (nested, size=16)
    uint64_t DeferredRoutine   = 0;      // offset 24
    uint64_t DeferredContext   = 0;      // offset 32
    uint64_t SystemArgument1   = 0;      // offset 40
    uint64_t SystemArgument2   = 0;      // offset 48
    uint64_t DpcData           = 0;      // offset 56
    // total = 64
};

template <int PtrSize>
struct KDPC : public EmuStructHelper<KDPC<PtrSize>>, public KDPC_POD<PtrSize> {
    std::string get_mem_tag() const override { return "kdpc"; }
};

// ==========================================================================================================
// ------ KDEVICE_QUEUE_ENTRY -------------------------------------------------------------------------------
// ==========================================================================================================
// x86: LIST_ENTRY(8)+u32(4)+u8(1) = 13
// x64: LIST_ENTRY(16)+u32(4)+u8(1) = 21
template <int PtrSize>
struct KDEVICE_QUEUE_ENTRY_POD;

template <>
struct KDEVICE_QUEUE_ENTRY_POD<4> {
    LIST_ENTRY_POD<4> DeviceListEntry;  // offset 0 (nested, size=8)
    uint32_t SortKey     = 0;   // offset  8
    uint8_t  Inserted    = 0;   // offset 12
    // total = 13
};

template <>
struct KDEVICE_QUEUE_ENTRY_POD<8> {
    LIST_ENTRY_POD<8> DeviceListEntry;  // offset 0 (nested, size=16)
    uint32_t SortKey     = 0;   // offset 16
    uint8_t  Inserted    = 0;   // offset 20
    // total = 21
};

template <int PtrSize>
struct KDEVICE_QUEUE_ENTRY : public EmuStructHelper<KDEVICE_QUEUE_ENTRY<PtrSize>>, public KDEVICE_QUEUE_ENTRY_POD<PtrSize> {
    std::string get_mem_tag() const override { return "kdevice_queue_entry"; }
};

// ==========================================================================================================
// ------ NT_TIB (Thread Information Block) ----------------------------------------------------------------
// ==========================================================================================================
// 7 pointer-sized fields
// x86: 7*4 = 28
// x64: 7*8 = 56
template <int PtrSize>
struct NT_TIB_POD;

template <>
struct NT_TIB_POD<4> {
    uint32_t ExceptionList = 0; // offset  0
    uint32_t StackBase     = 0; // offset  4
    uint32_t StackLimit    = 0; // offset  8
    uint32_t Reserved1     = 0; // offset 12
    uint32_t Reserved2     = 0; // offset 16
    uint32_t Reserved3     = 0; // offset 20
    uint32_t Self          = 0; // offset 24
    // total = 28
};

template <>
struct NT_TIB_POD<8> {
    uint64_t ExceptionList = 0; // offset  0
    uint64_t StackBase     = 0; // offset  8
    uint64_t StackLimit    = 0; // offset 16
    uint64_t Reserved1     = 0; // offset 24
    uint64_t Reserved2     = 0; // offset 32
    uint64_t Reserved3     = 0; // offset 40
    uint64_t Self          = 0; // offset 48
    // total = 56
};

template <int PtrSize>
struct NT_TIB : public EmuStructHelper<NT_TIB<PtrSize>>, public NT_TIB_POD<PtrSize> {
    std::string get_mem_tag() const override { return "nt_tib"; }
};

// ==========================================================================================================
// ------ TEB (Thread Environment Block) --------------------------------------------------------------------
// ==========================================================================================================
// x86: NT_TIB(28) + Ptr(4) + CLIENT_ID(8) + 6*Ptr(24) + 2*u32(8) + Ptr(4) + Ptr(4) + u32[26](104) + u32[5](20) + Ptr(4) + u32(4) = 212
// x64: NT_TIB(56) + Ptr(8) + CLIENT_ID(8) + pad0(8) + 6*Ptr(48) + 2*u32(8) + Ptr(8) + Ptr(8) + u32[26](104) + u32[5](20) + Ptr(8) + u32(4) = ??? 
// Let me be more careful...
//
// x86:
//   0: NT_TIB<4> = 7*4 = 28 bytes
//  28: EnvironmentPointer(Ptr=4) [32]
//  32: CLIENT_ID(8) [40]
//  40: ActiveRpcHandle(Ptr=4) [44]
//  44: ThreadLocalStoragePointer(Ptr=4) [48]
//  48: ProcessEnvironmentBlock(Ptr=4) [52]
//  52: LastErrorValue(u32=4)+CountOfOwnedCriticalSections(u32=4) [60]
//  60: CsrClientThread(Ptr=4) [64]
//  64: Win32ThreadInfo(Ptr=4) [68]
//  68: User32Reserved[26] (26*4=104) [172]
// 172: UserReserved[5] (5*4=20) [192]
// 192: WOW32Reserved(Ptr=4) [196]
// 196: CurrentLocale(u32=4) [200]
// total = 200
//
// x64:
//   0: NT_TIB<8> = 7*8 = 56 bytes
//  56: EnvironmentPointer(Ptr=8) [64]
//  64: CLIENT_ID(8: 2*u32) [72]
//  72: pad0(8) - In Python, x64 TEB has `self.pad0 = Ptr` after ClientId [80]
//  80: ActiveRpcHandle(Ptr=8) [88]
//  88: ThreadLocalStoragePointer(Ptr=8) [96]
//  96: ProcessEnvironmentBlock(Ptr=8) [104]
// 104: LastErrorValue(u32=4)+CountOfOwnedCriticalSections(u32=4) [112]
// 112: CsrClientThread(Ptr=8) [120]
// 120: Win32ThreadInfo(Ptr=8) [128]
// 128: User32Reserved[26] (26*4=104) [232]
// 232: UserReserved[5] (5*4=20) [252]
// 252: WOW32Reserved(Ptr=8) [260]
// 260: CurrentLocale(u32=4) [264]
// total = 264
template <int PtrSize>
struct TEB_POD;

template <>
struct TEB_POD<4> {
    NT_TIB_POD<4> NtTib;                    // offset   0 (nested, size=28)
    uint32_t EnvironmentPointer    = 0; // offset  28
    CLIENT_ID_POD<4> ClientId;               // offset  32 (nested, size=8)
    uint32_t ActiveRpcHandle                  = 0; // offset  40
    uint32_t ThreadLocalStoragePointer        = 0; // offset  44
    uint32_t ProcessEnvironmentBlock           = 0; // offset  48
    uint32_t LastErrorValue                   = 0; // offset  52
    uint32_t CountOfOwnedCriticalSections     = 0; // offset  56
    uint32_t CsrClientThread                  = 0; // offset  60
    uint32_t Win32ThreadInfo                  = 0; // offset  64
    uint32_t User32Reserved[26]              = {}; // offset  68 (104 bytes)
    uint32_t UserReserved[5]                 = {}; // offset 172 (20 bytes)
    uint32_t WOW32Reserved                    = 0; // offset 192
    uint32_t CurrentLocale                    = 0; // offset 196
    // total = 200
};

template <>
struct TEB_POD<8> {
    NT_TIB_POD<8> NtTib;                    // offset   0 (nested, size=56)
    uint64_t EnvironmentPointer    = 0; // offset  56
    CLIENT_ID_POD<8> ClientId;               // offset  64 (nested, size=16)
    uint64_t ActiveRpcHandle                  = 0; // offset  80
    uint64_t ThreadLocalStoragePointer        = 0; // offset  88
    uint64_t ProcessEnvironmentBlock           = 0; // offset  96
    uint32_t LastErrorValue                   = 0; // offset 104
    uint32_t CountOfOwnedCriticalSections     = 0; // offset 108
    uint64_t CsrClientThread                  = 0; // offset 112
    uint64_t Win32ThreadInfo                  = 0; // offset 120
    uint32_t User32Reserved[26]              = {}; // offset 128 (104 bytes)
    uint32_t UserReserved[5]                 = {}; // offset 232 (20 bytes)
    uint64_t WOW32Reserved                    = 0; // offset 252
    uint32_t CurrentLocale                    = 0; // offset 260
    // total = 264
};

template <int PtrSize>
struct TEB : public EmuStructHelper<TEB<PtrSize>>, public TEB_POD<PtrSize> {
    std::string get_mem_tag() const override { return "teb"; }
};

// ==========================================================================================================
// ------ PEB (Process Environment Block) -------------------------------------------------------------------
// NOTE: PEB is a very large struct (500+ bytes). Many fields are pointers.
// We inline everything to avoid dependency issues.
// ==========================================================================================================
template <int PtrSize>
struct PEB_POD;

template <>
struct PEB_POD<4> {
    // offset   0:  4*u8
    uint8_t  InheritedAddressSpace       = 0;
    uint8_t  ReadImageFileExecOptions    = 0;
    uint8_t  BeingDebugged               = 0;
    uint8_t  BitField                    = 0;
    // offset   4:  Mutant Ptr
    uint32_t Mutant                      = 0;
    // offset   8:  ImageBaseAddress Ptr
    uint32_t ImageBaseAddress            = 0;
    // offset  12:  Ldr Ptr
    uint32_t Ldr                         = 0;
    // offset  16:  ProcessParameters Ptr
    uint32_t ProcessParameters           = 0;
    // offset  20:  SubSystemData Ptr
    uint32_t SubSystemData               = 0;
    // offset  24:  ProcessHeap Ptr
    uint32_t ProcessHeap                 = 0;
    // offset  28:  FastPebLock Ptr
    uint32_t FastPebLock                 = 0;
    // offset  32:  AtlThunkSListPtr Ptr
    uint32_t AtlThunkSListPtr            = 0;
    // offset  36:  IFEOKey Ptr
    uint32_t IFEOKey                     = 0;
    // offset  40:  CrossProcessFlags Ptr
    uint32_t CrossProcessFlags           = 0;
    // offset  44:  UserSharedInfoPtr Ptr
    uint32_t UserSharedInfoPtr           = 0;
    // offset  48:  SystemReserved u32
    uint32_t SystemReserved              = 0;
    // offset  52:  AtlThunkSListPtr32 u32
    uint32_t AtlThunkSListPtr32          = 0;
    // offset  56:  ApiSetMap Ptr
    uint32_t ApiSetMap                   = 0;
    // offset  60:  TlsExpansionCounter Ptr
    uint32_t TlsExpansionCounter         = 0;
    // offset  64:  TlsBitmap Ptr
    uint32_t TlsBitmap                   = 0;
    // offset  68:  TlsBitmapBits[2] (2*u32=8)
    uint32_t TlsBitmapBits[2]            = {};
    // offset  76:  ReadOnlySharedMemoryBase Ptr
    uint32_t ReadOnlySharedMemoryBase    = 0;
    // offset  80:  SharedData Ptr
    uint32_t SharedData                  = 0;
    // offset  84:  ReadOnlyStaticServerData Ptr
    uint32_t ReadOnlyStaticServerData    = 0;
    // offset  88:  AnsiCodePageData Ptr
    uint32_t AnsiCodePageData            = 0;
    // offset  92:  OemCodePageData Ptr
    uint32_t OemCodePageData             = 0;
    // offset  96:  UnicodeCaseTableData Ptr
    uint32_t UnicodeCaseTableData        = 0;
    // offset 100:  NumberOfProcessors u32
    uint32_t NumberOfProcessors          = 0;
    // offset 104:  NtGlobalFlag u32
    uint32_t NtGlobalFlag                = 0;
    // offset 108:  CriticalSectionTimeout LARGE_INTEGER (u64)
    uint64_t CriticalSectionTimeout      = 0;
    // offset 116:  HeapSegmentReserve Ptr
    uint32_t HeapSegmentReserve          = 0;
    // offset 120:  HeapSegmentCommit Ptr
    uint32_t HeapSegmentCommit           = 0;
    // offset 124:  HeapDeCommitTotalFreeThreshold Ptr
    uint32_t HeapDeCommitTotalFreeThreshold = 0;
    // offset 128:  HeapDeCommitFreeBlockThreshold Ptr
    uint32_t HeapDeCommitFreeBlockThreshold  = 0;
    // offset 132:  NumberOfHeaps u32
    uint32_t NumberOfHeaps               = 0;
    // offset 136:  MaximumNumberOfHeaps u32
    uint32_t MaximumNumberOfHeaps        = 0;
    // offset 140:  ProcessHeaps Ptr
    uint32_t ProcessHeaps                = 0;
    // offset 144:  GdiSharedHandleTable Ptr
    uint32_t GdiSharedHandleTable        = 0;
    // offset 148:  ProcessStarterHelper Ptr
    uint32_t ProcessStarterHelper        = 0;
    // offset 152:  GdiDCAttributeList Ptr
    uint32_t GdiDCAttributeList          = 0;
    // offset 156:  LoaderLock Ptr
    uint32_t LoaderLock                  = 0;
    // offset 160:  OSMajorVersion u32
    uint32_t OSMajorVersion              = 0;
    // offset 164:  OSMinorVersion u32
    uint32_t OSMinorVersion              = 0;
    // offset 168:  OSBuildNumber u16
    uint16_t OSBuildNumber               = 0;
    // offset 170:  OSCSDVersion u16
    uint16_t OSCSDVersion                = 0;
    // offset 172:  OSPlatformId u32
    uint32_t OSPlatformId                = 0;
    // offset 176:  ImageSubsystem u32
    uint32_t ImageSubsystem              = 0;
    // offset 180:  ImageSubsystemMajorVersion u32
    uint32_t ImageSubsystemMajorVersion  = 0;
    // offset 184:  ImageSubsystemMinorVersion Ptr (u32)
    uint32_t ImageSubsystemMinorVersion  = 0;
    // offset 188:  ActiveProcessAffinityMask Ptr (u32)
    uint32_t ActiveProcessAffinityMask   = 0;
    // offset 192:  GdiHandleBuffer[34] (34*u32=136)
    uint32_t GdiHandleBuffer[34]         = {};
    // offset 328:  PostProcessInitRoutine Ptr
    uint32_t PostProcessInitRoutine      = 0;
    // offset 332:  TlsExpansionBitmap Ptr
    uint32_t TlsExpansionBitmap          = 0;
    // offset 336:  TlsExpansionBitmapBits[32] (32*u32=128)
    uint32_t TlsExpansionBitmapBits[32]  = {};
    // offset 464:  SessionId Ptr (u32)
    uint32_t SessionId                   = 0;
    // offset 468:  AppCompatFlags ULARGE_INTEGER (u64)
    uint64_t AppCompatFlags              = 0;
    // offset 476:  AppCompatFlagsUser ULARGE_INTEGER (u64)
    uint64_t AppCompatFlagsUser          = 0;
    // offset 484:  pShimData Ptr
    uint32_t pShimData                   = 0;
    // offset 488:  AppCompatInfo Ptr
    uint32_t AppCompatInfo               = 0;
    UNICODE_STRING_POD<4> CSDVersion;     // offset 492 (nested, size=8)
    // offset 500:  ActivationContextData Ptr
    uint32_t ActivationContextData         = 0;
    // offset 504:  ProcessAssemblyStorageMap Ptr
    uint32_t ProcessAssemblyStorageMap     = 0;
    // offset 508:  SystemDefaultActivationContextData Ptr
    uint32_t SystemDefaultActivationContextData = 0;
    // offset 512:  SystemAssemblyStorageMap Ptr
    uint32_t SystemAssemblyStorageMap     = 0;
    // offset 516:  MinimumStackCommit Ptr
    uint32_t MinimumStackCommit           = 0;
    // offset 520:  FlsCallback Ptr
    uint32_t FlsCallback                  = 0;
    LIST_ENTRY_POD<4> FlsListHead;        // offset 524 (nested, size=8)
    // offset 532:  FlsBitmap Ptr
    uint32_t FlsBitmap                    = 0;
    // offset 536:  FlsBitmapBits[4] (4*u32=16)
    uint32_t FlsBitmapBits[4]             = {};
    // offset 552:  FlsHighIndex Ptr (u32)
    uint32_t FlsHighIndex                 = 0;
    // offset 556:  WerRegistrationData Ptr
    uint32_t WerRegistrationData          = 0;
    // offset 560:  WerShipAssertPtr Ptr
    uint32_t WerShipAssertPtr             = 0;
    // offset 564:  pUnused Ptr
    uint32_t pUnused                      = 0;
    // offset 568:  pImageHeaderHash Ptr
    uint32_t pImageHeaderHash             = 0;
    // offset 572:  TracingFlags u64
    uint64_t TracingFlags                         = 0;
    // offset 580:  CsrServerReadOnlySharedMemoryBase u64
    uint64_t CsrServerReadOnlySharedMemoryBase     = 0;
    // offset 588:  TppWorkerpListLock Ptr (u32)
    uint32_t TppWorkerpListLock                    = 0;
    LIST_ENTRY_POD<4> TppWorkerpList;         // offset 592 (nested, size=8)
    // offset 600:  WaitOnAddressHashTable[128] (128*u32=512)
    uint32_t WaitOnAddressHashTable[128]           = {};
    // total = 1112
};

template <>
struct PEB_POD<8> {
    // offset   0: 4*u8
    uint8_t  InheritedAddressSpace       = 0;
    uint8_t  ReadImageFileExecOptions    = 0;
    uint8_t  BeingDebugged               = 0;
    uint8_t  BitField                    = 0;
    uint32_t pad1                        = 0;  // align Mutant to 8
    // offset   8:  Mutant Ptr
    uint64_t Mutant                      = 0;
    // offset  16:  ImageBaseAddress Ptr
    uint64_t ImageBaseAddress            = 0;
    // offset  24:  Ldr Ptr
    uint64_t Ldr                         = 0;
    // offset  32:  ProcessParameters Ptr
    uint64_t ProcessParameters           = 0;
    // offset  40:  SubSystemData Ptr
    uint64_t SubSystemData               = 0;
    // offset  48:  ProcessHeap Ptr
    uint64_t ProcessHeap                 = 0;
    // offset  56:  FastPebLock Ptr
    uint64_t FastPebLock                 = 0;
    // offset  64:  AtlThunkSListPtr Ptr
    uint64_t AtlThunkSListPtr            = 0;
    // offset  72:  IFEOKey Ptr
    uint64_t IFEOKey                     = 0;
    // offset  80:  CrossProcessFlags Ptr
    uint64_t CrossProcessFlags           = 0;
    // offset  88:  UserSharedInfoPtr Ptr
    uint64_t UserSharedInfoPtr           = 0;
    // offset  96:  SystemReserved u32
    uint32_t SystemReserved              = 0;
    // offset 100:  AtlThunkSListPtr32 u32
    uint32_t AtlThunkSListPtr32          = 0;
    // offset 104:  ApiSetMap Ptr
    uint64_t ApiSetMap                   = 0;
    // offset 112:  TlsExpansionCounter Ptr
    uint64_t TlsExpansionCounter         = 0;
    // offset 120:  TlsBitmap Ptr
    uint64_t TlsBitmap                   = 0;
    // offset 128:  TlsBitmapBits[2] (2*u32=8)
    uint32_t TlsBitmapBits[2]            = {};
    uint32_t pad2                        = 0;  // align to 8
    // offset 136:  ReadOnlySharedMemoryBase Ptr
    uint64_t ReadOnlySharedMemoryBase    = 0;
    // offset 144:  SharedData Ptr
    uint64_t SharedData                  = 0;
    // offset 152:  ReadOnlyStaticServerData Ptr
    uint64_t ReadOnlyStaticServerData    = 0;
    // offset 160:  AnsiCodePageData Ptr
    uint64_t AnsiCodePageData            = 0;
    // offset 168:  OemCodePageData Ptr
    uint64_t OemCodePageData             = 0;
    // offset 176:  UnicodeCaseTableData Ptr
    uint64_t UnicodeCaseTableData        = 0;
    // offset 184:  NumberOfProcessors u32
    uint32_t NumberOfProcessors          = 0;
    // offset 188:  NtGlobalFlag u32
    uint32_t NtGlobalFlag                = 0;
    // offset 192:  CriticalSectionTimeout LARGE_INTEGER (u64)
    uint64_t CriticalSectionTimeout      = 0;
    // offset 200:  HeapSegmentReserve Ptr
    uint64_t HeapSegmentReserve          = 0;
    // offset 208:  HeapSegmentCommit Ptr
    uint64_t HeapSegmentCommit           = 0;
    // offset 216:  HeapDeCommitTotalFreeThreshold Ptr
    uint64_t HeapDeCommitTotalFreeThreshold = 0;
    // offset 224:  HeapDeCommitFreeBlockThreshold Ptr
    uint64_t HeapDeCommitFreeBlockThreshold  = 0;
    // offset 232:  NumberOfHeaps u32
    uint32_t NumberOfHeaps               = 0;
    // offset 236:  MaximumNumberOfHeaps u32
    uint32_t MaximumNumberOfHeaps        = 0;
    // offset 240:  ProcessHeaps Ptr
    uint64_t ProcessHeaps                = 0;
    // offset 248:  GdiSharedHandleTable Ptr
    uint64_t GdiSharedHandleTable        = 0;
    // offset 256:  ProcessStarterHelper Ptr
    uint64_t ProcessStarterHelper        = 0;
    // offset 264:  GdiDCAttributeList Ptr
    uint64_t GdiDCAttributeList          = 0;
    // offset 272:  LoaderLock Ptr
    uint64_t LoaderLock                  = 0;
    // offset 280:  OSMajorVersion u32
    uint32_t OSMajorVersion              = 0;
    // offset 284:  OSMinorVersion u32
    uint32_t OSMinorVersion              = 0;
    // offset 288:  OSBuildNumber u16
    uint16_t OSBuildNumber               = 0;
    // offset 290:  OSCSDVersion u16
    uint16_t OSCSDVersion                = 0;
    // offset 292:  OSPlatformId u32
    uint32_t OSPlatformId                = 0;
    // offset 296:  ImageSubsystem u32
    uint32_t ImageSubsystem              = 0;
    // offset 300:  ImageSubsystemMajorVersion u32
    uint32_t ImageSubsystemMajorVersion  = 0;
    // offset 304:  pad3 (4)  align ImageSubsystemMinorVersion to 8
    uint32_t pad3                        = 0;
    // offset 308:  ImageSubsystemMinorVersion Ptr (u64)
    uint64_t ImageSubsystemMinorVersion  = 0;
    // offset 316:  ActiveProcessAffinityMask Ptr (u64)
    uint64_t ActiveProcessAffinityMask   = 0;
    // offset 324:  GdiHandleBuffer[60] (60*u32=240)
    uint32_t GdiHandleBuffer[60]         = {};
    // offset 564:  PostProcessInitRoutine Ptr
    uint64_t PostProcessInitRoutine      = 0;
    // offset 572:  TlsExpansionBitmap Ptr
    uint64_t TlsExpansionBitmap          = 0;
    // offset 580:  TlsExpansionBitmapBits[32] (32*u32=128)
    uint32_t TlsExpansionBitmapBits[32]  = {};
    uint32_t pad4                        = 0;  // align to 8
    // offset 712:  SessionId Ptr (u64)
    uint64_t SessionId                   = 0;
    // offset 720:  AppCompatFlags ULARGE_INTEGER (u64)
    uint64_t AppCompatFlags              = 0;
    // offset 728:  AppCompatFlagsUser ULARGE_INTEGER (u64)
    uint64_t AppCompatFlagsUser          = 0;
    // offset 736:  pShimData Ptr
    uint64_t pShimData                   = 0;
    // offset 744:  AppCompatInfo Ptr
    uint64_t AppCompatInfo               = 0;
    UNICODE_STRING_POD<8> CSDVersion;     // offset 752 (nested, size=16)
    // offset 768:  ActivationContextData Ptr
    uint64_t ActivationContextData         = 0;
    // offset 776:  ProcessAssemblyStorageMap Ptr
    uint64_t ProcessAssemblyStorageMap     = 0;
    // offset 784:  SystemDefaultActivationContextData Ptr
    uint64_t SystemDefaultActivationContextData = 0;
    // offset 792:  SystemAssemblyStorageMap Ptr
    uint64_t SystemAssemblyStorageMap     = 0;
    // offset 800:  MinimumStackCommit Ptr
    uint64_t MinimumStackCommit           = 0;
    // offset 808:  FlsCallback Ptr
    uint64_t FlsCallback                  = 0;
    LIST_ENTRY_POD<8> FlsListHead;        // offset 816 (nested, size=16)
    // offset 832:  FlsBitmap Ptr
    uint64_t FlsBitmap                    = 0;
    // offset 840:  FlsBitmapBits[4] (4*u32=16)
    uint32_t FlsBitmapBits[4]             = {};
    uint32_t pad5                         = 0;  // align FlsHighIndex to 8
    // offset 860:  FlsHighIndex Ptr
    uint64_t FlsHighIndex                 = 0;
    // offset 868:  WerRegistrationData Ptr
    uint64_t WerRegistrationData          = 0;
    // offset 876:  WerShipAssertPtr Ptr
    uint64_t WerShipAssertPtr             = 0;
    // offset 884:  pUnused Ptr
    uint64_t pUnused                      = 0;
    // offset 892:  pImageHeaderHash Ptr
    uint64_t pImageHeaderHash             = 0;
    // offset 900:  TracingFlags u64
    uint64_t TracingFlags                         = 0;
    // offset 908:  CsrServerReadOnlySharedMemoryBase u64
    uint64_t CsrServerReadOnlySharedMemoryBase     = 0;
    // offset 916:  TppWorkerpListLock Ptr
    uint64_t TppWorkerpListLock                    = 0;
    LIST_ENTRY_POD<8> TppWorkerpList;         // offset 924 (nested, size=16)
    // offset 940:  WaitOnAddressHashTable[128] (128*u64=1024)
    uint64_t WaitOnAddressHashTable[128]           = {};
    // total = 1964
};

template <int PtrSize>
struct PEB : public EmuStructHelper<PEB<PtrSize>>, public PEB_POD<PtrSize> {
    std::string get_mem_tag() const override { return "peb"; }
};

// ==========================================================================================================
// ------ PEB_LDR_DATA --------------------------------------------------------------------------------------
// ==========================================================================================================
// x86: u32(4)+u8[4](4)+Ptr(4)+3*LIST_ENTRY(24)+Ptr(4)+u8(1)+pad(3)+Ptr(4) = 48
// x64: u32(4)+u8[4](4)+pad(4)+Ptr(8)+3*LIST_ENTRY(48)+Ptr(8)+u8(1)+pad(7)+Ptr(8) = 88... let me recalc
// x64: u32(4) + u8[4](4) + pad(4) = 12  SsHandle @12... no, 12 not 8-aligned.
// Actually the Python code:
//   self.Length = u32 [4]
//   self.Initialized = u8[4] [4]
//   self.SsHandle = Ptr [on x64: 8, needs 8-alignment]
// After Length (4) + Initialized (4) = 8, next 8-aligned is 8. So SsHandle @8.
// No padding needed!
//
// x64: u32(4)+u8[4](4)=8 + Ptr(8)@8 + 3*LIST_ENTRY(48)@16 + Ptr(8)@64 + u8(1)@72 + pad(7)@73 + Ptr(8)@80
// total x64 = 88
//
// x86: u32(4)+u8[4](4)=8 + Ptr(4)@8 + 3*LIST_ENTRY(24)@12 + Ptr(4)@36 + u8(1)@40 + pad(3)@41 + Ptr(4)@44
// total x86 = 48
template <int PtrSize>
struct PEB_LDR_DATA_POD;

template <>
struct PEB_LDR_DATA_POD<4> {
    uint32_t Length              = 0; // offset  0
    uint8_t  Initialized[4]      = {}; // offset  4
    uint32_t SsHandle            = 0; // offset  8
    LIST_ENTRY_POD<4> InLoadOrderModuleList;            // offset 12 (nested, size=8)
    LIST_ENTRY_POD<4> InMemoryOrderModuleList;           // offset 20 (nested, size=8)
    LIST_ENTRY_POD<4> InInitializationOrderModuleList;   // offset 28 (nested, size=8)
    uint32_t EntryInProgress         = 0; // offset 36
    uint8_t  ShutdownInProgress      = 0; // offset 40
    uint8_t  pad[3]                 = {}; // offset 41  align ShutdownThreadId to 4
    uint32_t ShutdownThreadId        = 0; // offset 44
    // total = 48
};

template <>
struct PEB_LDR_DATA_POD<8> {
    uint32_t Length              = 0; // offset  0
    uint8_t  Initialized[4]      = {}; // offset  4
    // SsHandle @8 (8-aligned )
    uint64_t SsHandle            = 0; // offset  8
    LIST_ENTRY_POD<8> InLoadOrderModuleList;            // offset 16 (nested, size=16)
    LIST_ENTRY_POD<8> InMemoryOrderModuleList;           // offset 32 (nested, size=16)
    LIST_ENTRY_POD<8> InInitializationOrderModuleList;   // offset 48 (nested, size=16)
    uint64_t EntryInProgress         = 0; // offset 64
    uint8_t  ShutdownInProgress      = 0; // offset 72
    uint8_t  pad[7]                 = {}; // offset 73  align ShutdownThreadId to 8
    uint64_t ShutdownThreadId        = 0; // offset 80
    // total = 88
};

template <int PtrSize>
struct PEB_LDR_DATA : public EmuStructHelper<PEB_LDR_DATA<PtrSize>>, public PEB_LDR_DATA_POD<PtrSize> {
    std::string get_mem_tag() const override { return "peb_ldr_data"; }
};

// ==========================================================================================================
// ------ LDR_DATA_TABLE_ENTRY -----------------------------------------------------------------------------
// ==========================================================================================================
// x86: 3*LIST_ENTRY(24) + 2*Ptr(8) + u32(4) + 2*UNICODE_STRING(16) + u32(4) + u16(2) = 58
// x64: 3*LIST_ENTRY(48) + 2*Ptr(16) + u32(4) + pad(4) + 2*UNICODE_STRING(32) + u32(4) + u16(2) = 110  round to 112
// Let me recalc x64 carefully:
//   0: 3*LIST_ENTRY<8> = 48 bytes
//  48: DllBase Ptr = 8 bytes
//  56: EntryPoint Ptr = 8 bytes
//  64: SizeOfImage u32 = 4 bytes
//  68: pad = 4  align FullDllName to 8
//  72: FullDllName UNICODE_STRING<8> = 16 bytes
//  88: BaseDllName UNICODE_STRING<8> = 16 bytes
// 104: Flags u32 = 4
// 108: LoadCount u16 = 2
// total = 110
template <int PtrSize>
struct LDR_DATA_TABLE_ENTRY_POD;

template <>
struct LDR_DATA_TABLE_ENTRY_POD<4> {
    LIST_ENTRY_POD<4> InLoadOrderLinks;              // offset  0 (nested, size=8)
    LIST_ENTRY_POD<4> InMemoryOrderLinks;            // offset  8 (nested, size=8)
    LIST_ENTRY_POD<4> InInitializationOrderLinks;    // offset 16 (nested, size=8)
    uint32_t DllBase                = 0;  // offset 24
    uint32_t EntryPoint             = 0;  // offset 28
    uint32_t SizeOfImage            = 0;  // offset 32
    UNICODE_STRING_POD<4> FullDllName;          // offset 36 (nested, size=8)
    UNICODE_STRING_POD<4> BaseDllName;          // offset 44 (nested, size=8)
    uint32_t Flags                  = 0;  // offset 52
    uint16_t LoadCount              = 0;  // offset 56
    // total = 58
};

template <>
struct LDR_DATA_TABLE_ENTRY_POD<8> {
    LIST_ENTRY_POD<8> InLoadOrderLinks;              // offset  0 (nested, size=16)
    LIST_ENTRY_POD<8> InMemoryOrderLinks;            // offset 16 (nested, size=16)
    LIST_ENTRY_POD<8> InInitializationOrderLinks;    // offset 32 (nested, size=16)
    uint64_t DllBase                = 0;  // offset 48
    uint64_t EntryPoint             = 0;  // offset 56
    uint32_t SizeOfImage            = 0;  // offset 64
    uint32_t pad1                   = 0;  // offset 68  align UNICODE_STRING to 8
    UNICODE_STRING_POD<8> FullDllName;          // offset 72 (nested, size=16)
    UNICODE_STRING_POD<8> BaseDllName;          // offset 88 (nested, size=16)
    uint32_t Flags                  = 0;  // offset 104
    uint16_t LoadCount              = 0;  // offset 108
    // total = 110
};

template <int PtrSize>
struct LDR_DATA_TABLE_ENTRY : public EmuStructHelper<LDR_DATA_TABLE_ENTRY<PtrSize>>, public LDR_DATA_TABLE_ENTRY_POD<PtrSize> {
    std::string get_mem_tag() const override { return "ldr_data_table_entry"; }
};

// ==========================================================================================================
// ------ CURDIR (Current Directory) ------------------------------------------------------------------------
// ==========================================================================================================
// x86: UNICODE_STRING<4>(8) + Ptr(4) = 12
// x64: UNICODE_STRING<8>(16) + Ptr(8) = 24
template <int PtrSize>
struct CURDIR_POD;

template <>
struct CURDIR_POD<4> {
    UNICODE_STRING_POD<4> DosPath;     // offset 0 (nested, size=8)
    uint32_t Handle                 = 0; // offset 8
    // total = 12
};

template <>
struct CURDIR_POD<8> {
    UNICODE_STRING_POD<8> DosPath;     // offset  0 (nested, size=16)
    uint64_t Handle                 = 0; // offset 16
    // total = 24
};

template <int PtrSize>
struct CURDIR : public EmuStructHelper<CURDIR<PtrSize>>, public CURDIR_POD<PtrSize> {
    std::string get_mem_tag() const override { return "curdir"; }
};

// ==========================================================================================================
// ------ RTL_USER_PROCESS_PARAMETERS ----------------------------------------------------------------------
// This is a large struct. Layout follows the Python definition order.
// ==========================================================================================================
template <int PtrSize>
struct RTL_USER_PROCESS_PARAMETERS_POD;

template <>
struct RTL_USER_PROCESS_PARAMETERS_POD<4> {
    uint32_t MaximumLength    = 0; // offset   0
    uint32_t Length           = 0; // offset   4
    uint32_t Flags            = 0; // offset   8
    uint32_t DebugFlags       = 0; // offset  12
    uint32_t ConsoleHandle    = 0; // offset  16 (Ptr on x86)
    uint32_t ConsoleFlags     = 0; // offset  20
    uint32_t StandardInput    = 0; // offset  24
    uint32_t StandardOutput   = 0; // offset  28
    uint32_t StandardError    = 0; // offset  32
    CURDIR_POD<4> CurrentDirectory;                   // offset  36 (nested, size=12)
    UNICODE_STRING_POD<4> DllPath;                     // offset  48 (nested, size=8)
    UNICODE_STRING_POD<4> ImagePathName;               // offset  56 (nested, size=8)
    UNICODE_STRING_POD<4> CommandLine;                 // offset  64 (nested, size=8)
    uint32_t Environment                = 0; // offset  72
    uint32_t StartingX      = 0; // offset  76
    uint32_t StartingY      = 0; // offset  80
    uint32_t CountX         = 0; // offset  84
    uint32_t CountY         = 0; // offset  88
    uint32_t CountCharsX    = 0; // offset  92
    uint32_t CountCharsY    = 0; // offset  96
    uint32_t FillAttribute  = 0; // offset 100
    uint32_t WindowFlags    = 0; // offset 104
    uint32_t ShowWindowFlags = 0; // offset 108
    UNICODE_STRING_POD<4> WindowTitle;               // offset 112 (nested, size=8)
    UNICODE_STRING_POD<4> DesktopInfo;               // offset 120 (nested, size=8)
    UNICODE_STRING_POD<4> ShellInfo;                 // offset 128 (nested, size=8)
    UNICODE_STRING_POD<4> RuntimeData;               // offset 136 (nested, size=8)
    // total = 144
};

template <>
struct RTL_USER_PROCESS_PARAMETERS_POD<8> {
    uint32_t MaximumLength    = 0; // offset   0
    uint32_t Length           = 0; // offset   4
    uint32_t Flags            = 0; // offset   8
    uint32_t DebugFlags       = 0; // offset  12
    uint64_t ConsoleHandle    = 0; // offset  16
    uint32_t ConsoleFlags     = 0; // offset  24
    uint32_t pad1             = 0; // offset  28  align StandardInput to 8
    uint64_t StandardInput    = 0; // offset  32
    uint64_t StandardOutput   = 0; // offset  40
    uint64_t StandardError    = 0; // offset  48
    CURDIR_POD<8> CurrentDirectory;                   // offset  56 (nested, size=24)
    UNICODE_STRING_POD<8> DllPath;                     // offset  80 (nested, size=16)
    UNICODE_STRING_POD<8> ImagePathName;               // offset  96 (nested, size=16)
    UNICODE_STRING_POD<8> CommandLine;                 // offset 112 (nested, size=16)
    uint64_t Environment                = 0; // offset 128
    uint32_t StartingX      = 0; // offset 136
    uint32_t StartingY      = 0; // offset 140
    uint32_t CountX         = 0; // offset 144
    uint32_t CountY         = 0; // offset 148
    uint32_t CountCharsX    = 0; // offset 152
    uint32_t CountCharsY    = 0; // offset 156
    uint32_t FillAttribute  = 0; // offset 160
    uint32_t WindowFlags    = 0; // offset 164
    uint32_t ShowWindowFlags = 0; // offset 168
    uint32_t pad2           = 0; // offset 172  align WindowTitle to 8
    UNICODE_STRING_POD<8> WindowTitle;               // offset 176 (nested, size=16)
    UNICODE_STRING_POD<8> DesktopInfo;               // offset 192 (nested, size=16)
    UNICODE_STRING_POD<8> ShellInfo;                 // offset 208 (nested, size=16)
    UNICODE_STRING_POD<8> RuntimeData;               // offset 224 (nested, size=16)
    // total = 240
};

template <int PtrSize>
struct RTL_USER_PROCESS_PARAMETERS : public EmuStructHelper<RTL_USER_PROCESS_PARAMETERS<PtrSize>>, public RTL_USER_PROCESS_PARAMETERS_POD<PtrSize> {
    std::string get_mem_tag() const override { return "rtl_user_process_parameters"; }
};

// ==========================================================================================================
// ------ DEVICE_OBJECT -------------------------------------------------------------------------------------
// Note: Very large struct due to embedded KEVENT(4096) and KDPC(72).
// ==========================================================================================================
template <int PtrSize>
struct DEVICE_OBJECT_POD;

template <>
struct DEVICE_OBJECT_POD<4> {
    uint16_t Type                = 0;  // offset    0
    uint16_t Size                = 0;  // offset    2
    uint32_t ReferenceCount      = 0;  // offset    4
    uint32_t DriverObject        = 0;  // offset    8
    uint32_t NextDevice          = 0;  // offset   12
    uint32_t AttachedDevice      = 0;  // offset   16
    uint32_t CurrentIrp          = 0;  // offset   20
    uint32_t Timer               = 0;  // offset   24
    uint32_t Flags               = 0;  // offset   28
    uint32_t Characteristics     = 0;  // offset   32
    uint32_t Vpb                 = 0;  // offset   36
    uint32_t DeviceExtension     = 0;  // offset   40
    uint32_t DeviceType          = 0;  // offset   44
    uint8_t  StackSize           = 0;  // offset   48
    // LIST_ENTRY<4> Queue (8 bytes) - needs 4-alignment from offset 49
    uint8_t  pad1[3]             = {}; // offset   49  align Queue to 4
    LIST_ENTRY_POD<4> Queue;             // offset   52 (nested, size=8)
    uint32_t AlignmentRequirement = 0; // offset   60
    KDEVICE_QUEUE_POD<4> DeviceQueue;  // offset   64 (nested, size=21)
    // KDPC<4> (32 bytes) @85 (85 is not 4-aligned!)
    uint8_t  pad2[3]             = {}; // offset   85
    KDPC_POD<4> Dpc;                       // offset   88 (nested, size=32)
    uint32_t ActiveThreadCount     = 0;      // offset  120
    uint32_t SecurityDescriptor    = 0;      // offset  124
    KEVENT_POD DeviceLock;                 // offset  128 (nested, size=4096)
    uint16_t SectorSize            = 0;      // offset 4224
    uint16_t Spare1                = 0;      // offset 4226
    uint32_t DeviceObjectExtension = 0;      // offset 4228
    uint32_t Reserved              = 0;      // offset 4232
    // total = 4236
};

template <>
struct DEVICE_OBJECT_POD<8> {
    uint16_t Type                = 0;  // offset    0
    uint16_t Size                = 0;  // offset    2
    uint32_t pad1                = 0;  // offset    4  align DriverObject to 8
    uint64_t DriverObject        = 0;  // offset    8
    uint64_t NextDevice          = 0;  // offset   16
    uint64_t AttachedDevice      = 0;  // offset   24
    uint64_t CurrentIrp          = 0;  // offset   32
    uint64_t Timer               = 0;  // offset   40
    uint32_t Flags               = 0;  // offset   48
    uint32_t Characteristics     = 0;  // offset   52
    uint64_t Vpb                 = 0;  // offset   56
    uint64_t DeviceExtension     = 0;  // offset   64
    uint32_t DeviceType          = 0;  // offset   72
    uint8_t  StackSize           = 0;  // offset   76
    uint8_t  pad2[3]             = {}; // offset   77  align Queue to 8
    LIST_ENTRY_POD<8> Queue;             // offset   80 (nested, size=16)
    uint32_t AlignmentRequirement = 0; // offset   96
    uint32_t pad3                = 0;  // offset  100  align DeviceQueue to 8
    KDEVICE_QUEUE_POD<8> DeviceQueue;  // offset  104 (nested, size=33)
    // After DeviceQueue (104-136=33 bytes), pad to align KDPC
    uint8_t  pad4[7]             = {}; // offset  137  align Dpc to 8
    KDPC_POD<8> Dpc;                       // offset  144 (nested, size=64)
    uint32_t ActiveThreadCount     = 0;      // offset  208
    uint32_t pad5                  = 0;      // offset  212  align SecurityDescriptor
    uint64_t SecurityDescriptor    = 0;      // offset  216
    KEVENT_POD DeviceLock;                 // offset  224 (nested, size=4096)
    uint16_t SectorSize            = 0;      // offset 4320
    uint16_t Spare1                = 0;      // offset 4322
    uint32_t pad6                  = 0;      // offset 4324  align to 8
    uint64_t DeviceObjectExtension = 0;      // offset 4328
    uint64_t Reserved              = 0;      // offset 4336
    // total = 4344
};

template <int PtrSize>
struct DEVICE_OBJECT : public EmuStructHelper<DEVICE_OBJECT<PtrSize>>, public DEVICE_OBJECT_POD<PtrSize> {
    std::string get_mem_tag() const override { return "device_object"; }
};

// ==========================================================================================================
// ------ FILE_OBJECT ----------------------------------------------------------------------------------------
// ==========================================================================================================
template <int PtrSize>
struct FILE_OBJECT_POD;

template <>
struct FILE_OBJECT_POD<4> {
    uint16_t Type                     = 0;  // offset     0
    uint16_t Size                     = 0;  // offset     2
    uint32_t DeviceObject             = 0;  // offset     4
    uint32_t Vpb                      = 0;  // offset     8
    uint32_t FsContext                = 0;  // offset    12
    uint32_t FsContext2               = 0;  // offset    16
    uint32_t SectionObjectPointer     = 0;  // offset    20
    uint32_t PrivateCacheMap          = 0;  // offset    24
    uint32_t FinalStatus              = 0;  // offset    28
    uint32_t RelatedFileObject        = 0;  // offset    32
    uint8_t  LockOperation            = 0;  // offset    36
    uint8_t  DeletePending            = 0;  // offset    37
    uint8_t  ReadAccess               = 0;  // offset    38
    uint8_t  WriteAccess              = 0;  // offset    39
    uint8_t  DeleteAccess             = 0;  // offset    40
    uint8_t  SharedRead               = 0;  // offset    41
    uint8_t  SharedWrite              = 0;  // offset    42
    uint8_t  SharedDelete             = 0;  // offset    43
    uint32_t Flags                    = 0;  // offset    44 (4-aligned )
    UNICODE_STRING_POD<4> FileName;      // offset    48 (nested, size=8)
    LARGE_INTEGER_POD CurrentByteOffset;  // offset    56 (LARGE_INTEGER)
    uint32_t Waiters                  = 0;  // offset    64
    uint32_t Busy                     = 0;  // offset    68
    uint32_t LastLock                 = 0;  // offset    72
    KEVENT_POD Lock;                       // offset    76 (nested, size=4096)
    KEVENT_POD Event;                      // offset  4172 (nested, size=4096)
    uint32_t CompletionContext        = 0;  // offset  8268
    uint32_t IrpListLock              = 0;  // offset  8272
    LIST_ENTRY_POD<4> IrpList;           // offset  8276 (nested, size=8)
    uint32_t FileObjectExtension      = 0;  // offset  8284
    // total = 8288
};

template <>
struct FILE_OBJECT_POD<8> {
    uint16_t Type                     = 0;  // offset     0
    uint16_t Size                     = 0;  // offset     2
    uint32_t pad1                     = 0;  // offset     4  align DeviceObject to 8
    uint64_t DeviceObject             = 0;  // offset     8
    uint64_t Vpb                      = 0;  // offset    16
    uint64_t FsContext                = 0;  // offset    24
    uint64_t FsContext2               = 0;  // offset    32
    uint64_t SectionObjectPointer     = 0;  // offset    40
    uint64_t PrivateCacheMap          = 0;  // offset    48
    uint32_t FinalStatus              = 0;  // offset    56
    uint32_t pad2                     = 0;  // offset    60  align RelatedFileObject
    uint64_t RelatedFileObject        = 0;  // offset    64
    uint8_t  LockOperation            = 0;  // offset    72
    uint8_t  DeletePending            = 0;  // offset    73
    uint8_t  ReadAccess               = 0;  // offset    74
    uint8_t  WriteAccess              = 0;  // offset    75
    uint8_t  DeleteAccess             = 0;  // offset    76
    uint8_t  SharedRead               = 0;  // offset    77
    uint8_t  SharedWrite              = 0;  // offset    78
    uint8_t  SharedDelete             = 0;  // offset    79
    uint32_t Flags                    = 0;  // offset    80
    uint32_t pad3                     = 0;  // offset    84  align FileName to 8
    UNICODE_STRING_POD<8> FileName;      // offset    88 (nested, size=16)
    LARGE_INTEGER_POD CurrentByteOffset;  // offset   104 (LARGE_INTEGER)
    uint32_t Waiters                  = 0;  // offset   112
    uint32_t Busy                     = 0;  // offset   116
    uint32_t pad4                     = 0;  // offset   120  align LastLock
    uint64_t LastLock                 = 0;  // offset   128
    KEVENT_POD Lock;                       // offset   136 (nested, size=4096)
    KEVENT_POD Event;                      // offset  4232 (nested, size=4096)
    uint64_t CompletionContext        = 0;  // offset  8328
    uint32_t IrpListLock              = 0;  // offset  8336
    uint32_t pad5                     = 0;  // offset  8340  align IrpList to 8
    LIST_ENTRY_POD<8> IrpList;           // offset  8344 (nested, size=16)
    uint64_t FileObjectExtension      = 0;  // offset  8360
    // total = 8368
};

template <int PtrSize>
struct FILE_OBJECT : public EmuStructHelper<FILE_OBJECT<PtrSize>>, public FILE_OBJECT_POD<PtrSize> {
    std::string get_mem_tag() const override { return "file_object"; }
};

// ==========================================================================================================
// ------ IO_PARAMETERS (union containing DeviceIoControl) -------------------------------------------------
// ==========================================================================================================
template <int PtrSize>
struct IO_PARAMETERS_POD : public DeviceIoControl_POD<PtrSize> {};
template <int PtrSize>
struct IO_PARAMETERS : public EmuStructHelper<IO_PARAMETERS<PtrSize>>, public IO_PARAMETERS_POD<PtrSize> {
    std::string get_mem_tag() const override { return "io_parameters"; }
};

// ==========================================================================================================
// ------ IRP_OVERLAY ----------------------------------------------------------------------------------------
// ==========================================================================================================
template <int PtrSize>
struct IRP_OVERLAY_POD;

template <>
struct IRP_OVERLAY_POD<4> {
    uint32_t UserApcRoutine  = 0; // offset 0
    uint32_t UserApcContext  = 0; // offset 4
};
template <>
struct IRP_OVERLAY_POD<8> {
    uint64_t UserApcRoutine  = 0; // offset 0
    uint64_t UserApcContext  = 0; // offset 8
};
template <int PtrSize>
struct IRP_OVERLAY : public EmuStructHelper<IRP_OVERLAY<PtrSize>>, public IRP_OVERLAY_POD<PtrSize> {
    std::string get_mem_tag() const override { return "irp_overlay"; }
};

// ==========================================================================================================
// ------ IO_STACK_LOCATION ---------------------------------------------------------------------------------
// ==========================================================================================================
// x86: 4*u8(4) + DeviceIoControl(16) + 4*Ptr(16) = 36
// x64: 4*u8(4) + pad(8) + DeviceIoControl(24) + 4*Ptr(32) = 68
template <int PtrSize>
struct IO_STACK_LOCATION_POD;

template <>
struct IO_STACK_LOCATION_POD<4> {
    uint8_t  MajorFunction  = 0;  // offset  0
    uint8_t  MinorFunction  = 0;  // offset  1
    uint8_t  Flags          = 0;  // offset  2
    uint8_t  Control        = 0;  // offset  3
    DeviceIoControl_POD<4> Parameters;  // offset  4 (nested, size=16)
    uint32_t DeviceObject    = 0;  // offset 20
    uint32_t FileObject      = 0;  // offset 24
    uint32_t CompletionRoutine = 0; // offset 28
    uint32_t Context         = 0;  // offset 32
    // total = 36
};

template <>
struct IO_STACK_LOCATION_POD<8> {
    uint8_t  MajorFunction  = 0;  // offset  0
    uint8_t  MinorFunction  = 0;  // offset  1
    uint8_t  Flags          = 0;  // offset  2
    uint8_t  Control        = 0;  // offset  3
    uint8_t  _pad[8]        = {}; // offset  4  x86_64 ABI extra padding before Parameters
    // DeviceIoControl<8> (24 bytes) @12... wait, no. In Python:
    //   if ptr_size == 8: self._padding = ct.c_uint8 * 8
    // The padding is 8 bytes after the 4 control bytes. Then Parameters follows.
    // Parameters starts at offset 4+8=12. But 12 is not 8-aligned.
    // With ctypes, the struct's alignment is max(1, 8) = 8 (due to Ptr fields).
    // 12 is not 8-aligned, so... hmm.
    // Actually wait, in the Python code:
    //   self.MajorFunction = ct.c_uint8
    //   self.MinorFunction = ct.c_uint8
    //   self.Flags = ct.c_uint8
    //   self.Control = ct.c_uint8
    //   if ptr_size == 8: self._padding = ct.c_uint8 * 8
    //   self.Parameters = IO_PARAMETERS
    // The 4 control bytes + 8 padding bytes = 12. 
    // But then Parameters (which contains DeviceIoControl which has uint64_t fields)
    // needs 8-byte alignment. 12 is not 8-aligned.
    // 
    // In ctypes, the struct's effective alignment is the max of its members' alignment.
    // The 4 uint8_t have 1-byte alignment, the padding[8] has 1-byte alignment.
    // IO_PARAMETERS contains DeviceIoControl which has uint64_t, so it has 8-byte alignment.
    // So there should be padding after the _padding[8] to align Parameters to 8.
    // 12 + 4 = 16. So Parameters starts at 16.
    //
    // However, the Python EmuStruct code might handle this differently...
    // Actually in ctypes, when you define a class, the alignment of the whole struct
    // is determined by the member with the largest alignment requirement.
    // IO_PARAMETERS has 8-byte alignment, so IO_STACK_LOCATION has 8-byte alignment.
    // So Parameters starts at 16 (next 8-aligned after 12).
    //
    // Let me recalc:
    // 0-3: control bytes (4)
    // 4-11: _padding (8) = total 12
    // 12-15: padding to align Parameters to 16 = 4 bytes
    // 16-39: DeviceIoControl<8> (24 bytes)
    // 40-71: 4*Ptr (32 bytes)
    // total = 72
    uint8_t  pad2[4]        = {}; // offset 12  align Parameters to 8
    DeviceIoControl_POD<8> Parameters;  // offset 16 (nested, size=24)
    uint64_t DeviceObject    = 0;  // offset 40
    uint64_t FileObject      = 0;  // offset 48
    uint64_t CompletionRoutine = 0; // offset 56
    uint64_t Context         = 0;  // offset 64
    // total = 72
};

template <int PtrSize>
struct IO_STACK_LOCATION : public EmuStructHelper<IO_STACK_LOCATION<PtrSize>>, public IO_STACK_LOCATION_POD<PtrSize> {
    std::string get_mem_tag() const override { return "io_stack_location"; }
};

// ==========================================================================================================
// ------ TAIL_OVERLAY --------------------------------------------------------------------------------------
// ==========================================================================================================
// x86: KDEVICE_QUEUE_ENTRY(13) + pad(3) + 2*Ptr(8) + LIST_ENTRY(8) + 2*Ptr(8) = 40
// x64: KDEVICE_QUEUE_ENTRY(21) + pad(3) + pad_x64(8) + 2*Ptr(16) + LIST_ENTRY(16) + 2*Ptr(16) = 80
// Actually wait, let me re-read Python carefully:
//   class TAIL_OVERLAY(EmuStruct):
//       def __init__(self, ptr_size):
//           self.DeviceQueueEntry = KDEVICE_QUEUE_ENTRY
//           if ptr_size == 8:
//               self.padding = ct.c_uint8 * 8
//           self.Reserved1 = Ptr * 2
//           self.ListEntry = LIST_ENTRY
//           self.CurrentStackLocation = Ptr
//           self.Reserved2 = Ptr
//
// x86: KDEVICE_QUEUE_ENTRY(13) + Reserved1[2](8) + LIST_ENTRY(8) + Ptr(4) + Ptr(4) = 37
// x64: KDEVICE_QUEUE_ENTRY(21) + pad(8) + Reserved1[2](16) + LIST_ENTRY(16) + Ptr(8) + Ptr(8) = 77
template <int PtrSize>
struct TAIL_OVERLAY_POD;

template <>
struct TAIL_OVERLAY_POD<4> {
    KDEVICE_QUEUE_ENTRY_POD<4> DeviceQueueEntry;  // offset  0 (nested, size=13)
    // Reserved1[2] = 8 bytes @13 (13 is not 4-aligned!)
    uint8_t  pad1[3]            = {}; // offset 13
    uint32_t Reserved1[2]       = {}; // offset 16
    LIST_ENTRY_POD<4> ListEntry;                     // offset 24 (nested, size=8)
    uint32_t CurrentStackLocation = 0; // offset 32
    uint32_t Reserved2            = 0; // offset 36
    // total = 40
};

template <>
struct TAIL_OVERLAY_POD<8> {
    KDEVICE_QUEUE_ENTRY_POD<8> DeviceQueueEntry;  // offset  0 (nested, size=21)
    uint8_t  _pad8[8]          = {}; // offset 21  x64 padding
    // Reserved1[2] = 16 bytes @29 (29 is not 8-aligned!)
    uint8_t  pad2[3]           = {}; // offset 29
    uint64_t Reserved1[2]       = {}; // offset 32
    LIST_ENTRY_POD<8> ListEntry;                     // offset 48 (nested, size=16)
    uint64_t CurrentStackLocation = 0; // offset 64
    uint64_t Reserved2            = 0; // offset 72
    // total = 80
};

template <int PtrSize>
struct TAIL_OVERLAY : public EmuStructHelper<TAIL_OVERLAY<PtrSize>>, public TAIL_OVERLAY_POD<PtrSize> {
    std::string get_mem_tag() const override { return "tail_overlay"; }
};

// ==========================================================================================================
// ------ IRP_TAIL ------------------------------------------------------------------------------------------
// ==========================================================================================================
template <int PtrSize>
struct IRP_TAIL_POD {
    TAIL_OVERLAY_POD<PtrSize> Overlay;
};
template <int PtrSize>
struct IRP_TAIL : public EmuStructHelper<IRP_TAIL<PtrSize>>, public IRP_TAIL_POD<PtrSize> {
    std::string get_mem_tag() const override { return "irp_tail"; }
};

// ==========================================================================================================
// ------ IRP (I/O Request Packet) --------------------------------------------------------------------------
// ==========================================================================================================
// x86: u16+u16+Ptr(4)+u32+Ptr(4)+LIST_ENTRY(8)+IO_STATUS_BLOCK(8)+8*u8(8)+2*Ptr(8)+IRP_OVERLAY(8)+2*Ptr(8)+IRP_TAIL(40) = 112
// x64: u16+u16+pad(4)+Ptr(8)+u32+pad(4)+Ptr(8)+LIST_ENTRY(16)+IO_STATUS_BLOCK(16)+8*u8(8)+pad(4)+2*Ptr(16)+IRP_OVERLAY(16)+2*Ptr(16)+IRP_TAIL(80) = 216
template <int PtrSize>
struct IRP_POD;

template <>
struct IRP_POD<4> {
    uint16_t Type              = 0;  // offset   0
    uint16_t Size              = 0;  // offset   2
    uint32_t MdlAddress        = 0;  // offset   4
    uint32_t Flags             = 0;  // offset   8
    uint32_t AssociatedIrp     = 0;  // offset  12
    LIST_ENTRY_POD<4> ThreadListEntry;   // offset  16 (nested, size=8)
    IO_STATUS_BLOCK_POD<4> IoStatus;     // offset  24 (nested, size=8)
    uint8_t  RequestorMode    = 0;  // offset  32
    uint8_t  PendingReturned  = 0;  // offset  33
    uint8_t  StackCount       = 0;  // offset  34
    uint8_t  CurrentLocation  = 0;  // offset  35
    uint8_t  Cancel           = 0;  // offset  36
    uint8_t  CancelIrql       = 0;  // offset  37
    uint8_t  ApcEnvironment   = 0;  // offset  38
    uint8_t  AllocationFlags  = 0;  // offset  39
    uint32_t UserIosb         = 0;  // offset  40
    uint32_t UserEvent        = 0;  // offset  44
    IRP_OVERLAY_POD<4> Overlay;         // offset  48 (nested, size=8)
    uint32_t CancelRoutine    = 0;  // offset  56
    uint32_t UserBuffer       = 0;  // offset  60
    IRP_TAIL_POD<4> Tail;              // offset  64 (nested, size=40)
    // total = 104
};

template <>
struct IRP_POD<8> {
    uint16_t Type              = 0;  // offset   0
    uint16_t Size              = 0;  // offset   2
    uint32_t pad1              = 0;  // offset   4  align MdlAddress to 8
    uint64_t MdlAddress        = 0;  // offset   8
    uint32_t Flags             = 0;  // offset  16
    uint32_t pad2              = 0;  // offset  20  align AssociatedIrp to 8
    uint64_t AssociatedIrp     = 0;  // offset  24
    LIST_ENTRY_POD<8> ThreadListEntry;   // offset  32 (nested, size=16)
    IO_STATUS_BLOCK_POD<8> IoStatus;     // offset  48 (nested, size=16)
    uint8_t  RequestorMode    = 0;  // offset  64
    uint8_t  PendingReturned  = 0;  // offset  65
    uint8_t  StackCount       = 0;  // offset  66
    uint8_t  CurrentLocation  = 0;  // offset  67
    uint8_t  Cancel           = 0;  // offset  68
    uint8_t  CancelIrql       = 0;  // offset  69
    uint8_t  ApcEnvironment   = 0;  // offset  70
    uint8_t  AllocationFlags  = 0;  // offset  71
    uint32_t pad3             = 0;  // offset  72  align UserIosb to 8
    uint64_t UserIosb         = 0;  // offset  80
    uint64_t UserEvent        = 0;  // offset  88
    IRP_OVERLAY_POD<8> Overlay;         // offset  96 (nested, size=16)
    uint64_t CancelRoutine    = 0;  // offset 112
    uint64_t UserBuffer       = 0;  // offset 120
    IRP_TAIL_POD<8> Tail;              // offset 128 (nested, size=80)
    // total = 208
};

template <int PtrSize>
struct IRP : public EmuStructHelper<IRP<PtrSize>>, public IRP_POD<PtrSize> {
    std::string get_mem_tag() const override { return "irp"; }
};

// ==========================================================================================================
// Core structs moved from struct.h
// ==========================================================================================================

//  LIST_ENTRY (POD defined at top) 
// LIST_ENTRY_POD defined at top of file
template <int PtrSize>
struct LIST_ENTRY : public EmuStructHelper<LIST_ENTRY<PtrSize>>, public LIST_ENTRY_POD<PtrSize> {
    std::string get_mem_tag() const override { return "list_entry"; }
};

//  KSYSTEM_TIME 
struct KSYSTEM_TIME : public EmuStructHelper<KSYSTEM_TIME> {
    uint32_t LowPart    = 0;
    uint32_t High1Time  = 0;
    uint32_t High2Time  = 0;
    std::string get_mem_tag() const override { return "ksystem_time"; }
};

//  UNICODE_STRING (POD defined at top) 
// UNICODE_STRING_POD defined at top of file
template <int PtrSize>
struct UNICODE_STRING : public EmuStructHelper<UNICODE_STRING<PtrSize>>, public UNICODE_STRING_POD<PtrSize> {
    std::string get_mem_tag() const override { return "unicode_string"; }
};

//  STRING 
template <int PtrSize>
struct STRING_POD : public UNICODE_STRING_POD<PtrSize> {};

template <int PtrSize>
struct STRING : public EmuStructHelper<STRING<PtrSize>>, public STRING_POD<PtrSize> {
    std::string get_mem_tag() const override { return "string"; }
};

//  OBJECT_ATTRIBUTES 
template <int PtrSize>
struct OBJECT_ATTRIBUTES_POD;

template <>
struct OBJECT_ATTRIBUTES_POD<4> {
    uint32_t Length = 0;
    uint32_t RootDirectory = 0;
    uint32_t ObjectName = 0;
    uint32_t Attributes = 0;
    uint32_t SecurityDescriptor = 0;
    uint32_t SecurityQoS = 0;
};

template <>
struct OBJECT_ATTRIBUTES_POD<8> {
    uint32_t Length = 0;
    uint32_t padding1 = 0;
    uint64_t RootDirectory = 0;
    uint64_t ObjectName = 0;
    uint32_t Attributes = 0;
    uint32_t padding2 = 0;
    uint64_t SecurityDescriptor = 0;
    uint64_t SecurityQoS = 0;
};

template <int PtrSize>
struct OBJECT_ATTRIBUTES : public EmuStructHelper<OBJECT_ATTRIBUTES<PtrSize>>, public OBJECT_ATTRIBUTES_POD<PtrSize> {
    std::string get_mem_tag() const override { return "object_attributes"; }
};

//  IO_STATUS_BLOCK (POD defined at top) 
// IO_STATUS_BLOCK_POD defined at top of file
template <int PtrSize>
struct IO_STATUS_BLOCK : public EmuStructHelper<IO_STATUS_BLOCK<PtrSize>>, public IO_STATUS_BLOCK_POD<PtrSize> {
    std::string get_mem_tag() const override { return "io_status_block"; }
};

//  LARGE_INTEGER 
// LARGE_INTEGER_POD defined earlier (near FILE_STANDARD_INFORMATION)

struct LARGE_INTEGER : public EmuStructHelper<LARGE_INTEGER>, public LARGE_INTEGER_POD {
    std::string get_mem_tag() const override { return "large_integer"; }
};

//  SYSTEM_TIMEOFDAY_INFORMATION 
struct SYSTEM_TIMEOFDAY_INFORMATION : public EmuStructHelper<SYSTEM_TIMEOFDAY_INFORMATION> {
    uint64_t BootTime       = 0;
    uint64_t CurrentTime    = 0;
    uint64_t TimeZoneBias   = 0;
    uint32_t TimeZoneId     = 0;
    uint32_t Reserved       = 0;
    uint64_t BootTimeBias   = 0;
    uint64_t SleepTimeBias  = 0;
    std::string get_mem_tag() const override { return "system_timeofday_info"; }
};

//  DISK_EXTENT 
struct DISK_EXTENT_POD {
    uint32_t DiskNumber = 0;
    uint8_t  padding[4] = {};
    uint64_t StartingOffset = 0;
    uint64_t ExtentLength = 0;
};

struct DISK_EXTENT : public EmuStructHelper<DISK_EXTENT>, public DISK_EXTENT_POD {
    std::string get_mem_tag() const override { return "disk_extent"; }
};

//  VOLUME_DISK_EXTENTS 
struct VOLUME_DISK_EXTENTS : public EmuStructHelper<VOLUME_DISK_EXTENTS> {
    uint32_t NumberOfDiskExtents = 0;
    uint8_t  padding[4] = {};
    DISK_EXTENT_POD Extents[1];
    std::string get_mem_tag() const override { return "volume_disk_extents"; }
};

#pragma pack(pop)

}}} // namespace speakeasy::deffs::nt

#endif // SPEAKEASY_DEFS_NEW_NT_NTOSKRNL_H
