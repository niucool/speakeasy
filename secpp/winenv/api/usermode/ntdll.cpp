// ntdll.cpp — ntdll.dll API handler implementation
//
// Maps to: speakeasy/winenv/api/usermode/ntdll.py
//
// Implements NT kernel layer API functions with real logic:
//   heap, virtual memory, file I/O, registry, sections,
//   sync objects, threads, and utility functions.

#include "ntdll.h"

#include <cstring>
#include <chrono>
#include <thread>
#include <algorithm>

#include "memmgr.h"           // MemoryManager
#include "windows/winemu.h"   // WindowsEmulator, BinaryEmulator
#include "windows/win32.h"    // Win32Emulator (heap_alloc)
#include "windows/fileman.h"  // File, FileManager
#include "windows/regman.h"   // RegistryManager, RegKey, RegValue
#include "windows/regdefs.h"  // REG_*, HKEY_*
#include "struct.h"           // speakeasy::write_le, speakeasy::read_le
#include "winenv/arch.h"      // ARCH_X86, ARCH_AMD64

// NTSTATUS constants (avoid Windows SDK macro conflicts)
static constexpr uint32_t NT_SUCCESS          = 0x00000000;
static constexpr uint32_t NT_NO_MEMORY        = 0xC0000017;
static constexpr uint32_t NT_UNSUCCESSFUL     = 0xC0000001;
static constexpr uint32_t NT_INVALID_HANDLE   = 0xC0000008;
static constexpr uint32_t NT_INVALID_PARAM    = 0xC000000D;
static constexpr uint32_t NT_ACCESS_VIOLATION = 0xC0000005;
static constexpr uint32_t NT_OBJECT_NAME_NOT_FOUND = 0xC0000034;
static constexpr uint32_t NT_BUFFER_TOO_SMALL = 0xC0000023;
static constexpr uint32_t NT_STATUS_DLL_NOT_FOUND = 0xC0000135;
// Alias for STATUS_* naming (used in ntdll API implementations)
#define STATUS_OBJECT_NAME_NOT_FOUND NT_OBJECT_NAME_NOT_FOUND
#ifndef STATUS_INVALID_PARAMETER
#define STATUS_INVALID_PARAMETER     NT_INVALID_PARAM
#endif
#ifndef STATUS_BUFFER_TOO_SMALL
#define STATUS_BUFFER_TOO_SMALL      NT_BUFFER_TOO_SMALL
#endif
#ifndef STATUS_INVALID_HANDLE
#define STATUS_INVALID_HANDLE        NT_INVALID_HANDLE
#endif
#ifndef STATUS_UNSUCCESSFUL
#define STATUS_UNSUCCESSFUL          NT_UNSUCCESSFUL
#endif
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS               NT_SUCCESS
#endif
#ifndef STATUS_ACCESS_VIOLATION
#define STATUS_ACCESS_VIOLATION      NT_ACCESS_VIOLATION
#endif
#ifndef STATUS_NO_MEMORY
#define STATUS_NO_MEMORY             NT_NO_MEMORY
#endif

// Windows SDK defines these as macros; undefine to use as C++ method names
#ifdef RtlZeroMemory
#undef RtlZeroMemory
#endif
#ifdef RtlMoveMemory
#undef RtlMoveMemory
#endif

namespace speakeasy {
namespace api {

// ── Forward declarations of helpers ───────────────────────────

/// Get pointer size from the emulator architecture
static inline int get_ptr_size(void* emu) {
    auto* mm = static_cast<MemoryManager*>(emu);
    auto* bemu = static_cast<BinaryEmulator*>(mm);
    int arch = bemu->get_arch();
    return (arch == speakeasy::arch::ARCH_AMD64) ? 8 : 4;
}

/// Read a uint16_t from emulated memory
static inline uint16_t read_u16(void* emu, uint64_t addr) {
    auto raw = static_cast<MemoryManager*>(emu)->mem_read(addr, 2);
    return (raw.size() >= 2) ? static_cast<uint16_t>(read_le(raw, 0, 2)) : 0;
}

/// Read a uint32_t from emulated memory
static inline uint32_t read_u32(void* emu, uint64_t addr) {
    auto raw = static_cast<MemoryManager*>(emu)->mem_read(addr, 4);
    return (raw.size() >= 4) ? static_cast<uint32_t>(read_le(raw, 0, 4)) : 0;
}

/// Read a pointer value from emulated memory
static inline uint64_t read_ptr(void* emu, uint64_t addr) {
    int psz = get_ptr_size(emu);
    auto raw = static_cast<MemoryManager*>(emu)->mem_read(addr, psz);
    return (raw.size() >= static_cast<size_t>(psz)) ? read_le(raw, 0, psz) : 0;
}

/// Write a uint16_t to emulated memory
static inline void write_u16(void* emu, uint64_t addr, uint16_t val) {
    std::vector<uint8_t> buf(2, 0);
    write_le(buf, 0, val, 2);
    static_cast<MemoryManager*>(emu)->mem_write(addr, buf);
}

/// Write a uint32_t to emulated memory
static inline void write_u32(void* emu, uint64_t addr, uint32_t val) {
    std::vector<uint8_t> buf(4, 0);
    write_le(buf, 0, val, 4);
    static_cast<MemoryManager*>(emu)->mem_write(addr, buf);
}

/// Write a pointer value to emulated memory
static inline void write_ptr(void* emu, uint64_t addr, uint64_t val) {
    int psz = get_ptr_size(emu);
    std::vector<uint8_t> buf(psz, 0);
    write_le(buf, 0, val, psz);
    static_cast<MemoryManager*>(emu)->mem_write(addr, buf);
}

/// Read a UNICODE_STRING structure from emulated memory and return the string content
static inline std::string read_unicode_string_content(void* emu, uint64_t us_addr) {
    if (us_addr == 0) return "";
    int psz = get_ptr_size(emu);
    // UNICODE_STRING: Length(2), MaximumLength(2), Buffer(ptr)
    // On x64: offset 0=Length(2), 2=MaxLength(2), 4=padding? or pointer
    // The apihandler code reads buffer from offset 4 (after Length+MaxLength)
    auto raw_len = static_cast<MemoryManager*>(emu)->mem_read(us_addr, 2);
    if (raw_len.size() < 2) return "";
    uint16_t length = static_cast<uint16_t>(read_le(raw_len, 0, 2));
    uint64_t buffer_addr = read_ptr(emu, us_addr + 4);
    if (buffer_addr == 0) return "";
    auto* bemu = static_cast<BinaryEmulator*>(static_cast<MemoryManager*>(emu));
    return bemu->read_mem_string(buffer_addr, 2, length / 2);
}

/// Write a UNICODE_STRING structure at the given address (updates Length, MaximumLength, Buffer)
static inline void write_unicode_string(void* emu, uint64_t us_addr,
                                         const std::string& str, uint64_t buffer_addr) {
    int len = static_cast<int>(str.size() * 2); // bytes in UTF-16
    write_u16(emu, us_addr, len);
    write_u16(emu, us_addr + 2, len + 2); // MaximumLength includes null terminator
    write_ptr(emu, us_addr + 4, buffer_addr);
    if (buffer_addr != 0) {
        // Write the actual UTF-16 string
        auto* bemu = static_cast<BinaryEmulator*>(static_cast<MemoryManager*>(emu));
        bemu->write_mem_string(str, buffer_addr, 2);
    }
}

/// Read an ANSI_STRING structure
static inline std::string read_ansi_string_content(void* emu, uint64_t as_addr) {
    if (as_addr == 0) return "";
    auto raw_len = static_cast<MemoryManager*>(emu)->mem_read(as_addr, 2);
    if (raw_len.size() < 2) return "";
    uint16_t length = static_cast<uint16_t>(read_le(raw_len, 0, 2));
    uint64_t buffer_addr = read_ptr(emu, as_addr + 4);
    if (buffer_addr == 0) return "";
    auto* bemu = static_cast<BinaryEmulator*>(static_cast<MemoryManager*>(emu));
    return bemu->read_mem_string(buffer_addr, 1, length);
}

/// Convert narrow string to UTF-16 vector
static inline std::vector<uint8_t> utf8_to_utf16(const std::string& s) {
    std::vector<uint8_t> out;
    // Simple ASCII-only conversion (no actual UTF-8 decoding needed for most cases)
    for (size_t i = 0; i < s.size(); ++i) {
        out.push_back(static_cast<uint8_t>(s[i]));
        out.push_back(0);
    }
    // null terminator
    out.push_back(0);
    out.push_back(0);
    return out;
}

// ═══════════════════════════════════════════════════════════════
// Constructor — register all API entries
// ═══════════════════════════════════════════════════════════════

Ntdll::Ntdll() {
    apis_ = {
        // Heap
        {"RtlAllocateHeap",         3, RtlAllocateHeap},
        {"RtlFreeHeap",             3, RtlFreeHeap},
        {"RtlReAllocateHeap",       4, RtlReAllocateHeap},
        {"RtlCreateHeap",           5, RtlCreateHeap},
        {"RtlDestroyHeap",          1, RtlDestroyHeap},
        {"RtlGetProcessHeap",       0, RtlGetProcessHeap},
        // Virtual memory
        {"NtAllocateVirtualMemory",   6, NtAllocateVirtualMemory},
        {"NtFreeVirtualMemory",       4, NtFreeVirtualMemory},
        {"NtProtectVirtualMemory",    5, NtProtectVirtualMemory},
        {"NtQueryVirtualMemory",      6, NtQueryVirtualMemory},
        // File I/O
        {"NtCreateFile",              11, NtCreateFile},
        {"NtOpenFile",                6, NtOpenFile},
        {"NtReadFile",                9, NtReadFile},
        {"NtWriteFile",               9, NtWriteFile},
        {"NtClose",                   1, NtClose},
        {"NtDeviceIoControlFile",     10, NtDeviceIoControlFile},
        // Process / thread
        {"NtCreateProcess",           8, NtCreateProcess},
        {"NtCreateThread",            8, NtCreateThread},
        {"NtOpenThread",              4, NtOpenThread},
        {"NtTerminateProcess",        2, NtTerminateProcess},
        {"NtTerminateThread",         2, NtTerminateThread},
        {"NtGetContextThread",        2, NtGetContextThread},
        {"NtSetContextThread",        2, NtSetContextThread},
        // System info
        {"NtQuerySystemInformation",  4, NtQuerySystemInformation},
        {"NtQueryInformationProcess", 5, NtQueryInformationProcess},
        {"NtSetInformationProcess",   4, NtSetInformationProcess},
        // Registry
        {"NtCreateKey",               7, NtCreateKey},
        {"NtOpenKey",                 3, NtOpenKey},
        {"NtQueryValueKey",           6, NtQueryValueKey},
        {"NtSetValueKey",             6, NtSetValueKey},
        {"NtDeleteKey",               2, NtDeleteKey},
        {"NtDeleteValueKey",          3, NtDeleteValueKey},
        // Sections
        {"NtCreateSection",           7, NtCreateSection},
        {"NtOpenSection",             4, NtOpenSection},
        {"NtMapViewOfSection",        10, NtMapViewOfSection},
        {"NtUnmapViewOfSection",      2, NtUnmapViewOfSection},
        // Sync
        {"NtCreateEvent",             5, NtCreateEvent},
        {"NtOpenEvent",               4, NtOpenEvent},
        {"NtCreateMutant",            4, NtCreateMutant},
        {"NtOpenMutant",              4, NtOpenMutant},
        {"NtWaitForSingleObject",     3, NtWaitForSingleObject},
        {"NtDelayExecution",          2, NtDelayExecution},
        // String / utility
        {"RtlInitUnicodeString",      2, RtlInitUnicodeString},
        {"RtlInitString",             2, RtlInitString},
        {"RtlAnsiStringToUnicodeString", 3, RtlAnsiStringToUnicodeString},
        {"RtlFreeUnicodeString",      1, RtlFreeUnicodeString},
        {"RtlNtStatusToDosError",     1, RtlNtStatusToDosError},
        {"CsrGetProcessId",           0, CsrGetProcessId},
        // Volume / object
        {"NtQueryVolumeInformationFile", 5, NtQueryVolumeInformationFile},
        {"NtQueryObject",             5, NtQueryObject},
        {"NtDuplicateObject",         6, NtDuplicateObject},
        // Additional ntdll APIs (ported from Python reference)
        {"RtlGetLastWin32Error",      0, RtlGetLastWin32Error},
        {"RtlFlushSecureMemoryCache", 2, RtlFlushSecureMemoryCache},
        {"RtlAddVectoredExceptionHandler", 2, RtlAddVectoredExceptionHandler},
        {"RtlRemoveVectoredExceptionHandler", 1, RtlRemoveVectoredExceptionHandler},
        {"NtYieldExecution",          0, NtYieldExecution},
        {"LdrLoadDll",                4, LdrLoadDll},
        {"LdrGetProcedureAddress",    4, LdrGetProcedureAddress},
        {"LdrFindResource_U",         4, LdrFindResource_U},
        {"LdrAccessResource",         4, LdrAccessResource},
        {"RtlZeroMemory",             2, RtlZeroMemory},
        {"RtlMoveMemory",             3, RtlMoveMemory},
        {"RtlEncodePointer",          1, RtlEncodePointer},
        {"RtlDecodePointer",          1, RtlDecodePointer},
        {"RtlComputeCrc32",           3, RtlComputeCrc32},
        {"RtlGetNtVersionNumbers",    3, RtlGetNtVersionNumbers},
        {"RtlGetCurrentPeb",          0, RtlGetCurrentPeb},
        {"RtlGetVersion",             1, RtlGetVersion},
    };
}

// ═══════════════════════════════════════════════════════════════
// Heap functions
// ═══════════════════════════════════════════════════════════════

uint64_t Ntdll::RtlAllocateHeap(void* emu, const std::string&, int,
                                 const std::vector<uint64_t>& argv) {
    // HANDLE HeapHandle, ULONG Flags, SIZE_T Size
    // Flags & 0x1 = HEAP_ZERO_MEMORY
    uint64_t heap_handle = argv[0];
    uint32_t flags = static_cast<uint32_t>(argv[1]);
    size_t size = static_cast<size_t>(argv[2]);
    (void)heap_handle;

    auto* wemu = static_cast<Win32Emulator*>(static_cast<MemoryManager*>(emu));
    uint64_t addr = wemu->heap_alloc(size, "ntdll");

    if (addr == 0) return NT_NO_MEMORY;

    // HEAP_ZERO_MEMORY
    if (flags & 0x1) {
        std::vector<uint8_t> zero(size, 0);
        static_cast<MemoryManager*>(emu)->mem_write(addr, zero);
    }

    return addr;
}

uint64_t Ntdll::RtlFreeHeap(void* emu, const std::string&, int,
                             const std::vector<uint64_t>& argv) {
    // HANDLE HeapHandle, ULONG Flags, PVOID HeapBase
    uint64_t heap_handle = argv[0];
    uint32_t flags = static_cast<uint32_t>(argv[1]);
    uint64_t heap_base = argv[2];
    (void)heap_handle;
    (void)flags;

    if (heap_base == 0) return 1; // TRUE — freeing NULL is a no-op

    try {
        static_cast<MemoryManager*>(emu)->mem_free(heap_base);
        return 1; // TRUE
    } catch (...) {
        return 0; // FALSE
    }
}

uint64_t Ntdll::RtlReAllocateHeap(void* emu, const std::string&, int,
                                   const std::vector<uint64_t>& argv) {
    // HANDLE HeapHandle, ULONG Flags, PVOID Memory, SIZE_T NewSize
    uint64_t heap_handle = argv[0];
    uint32_t flags = static_cast<uint32_t>(argv[1]);
    uint64_t old_ptr = argv[2];
    size_t new_size = static_cast<size_t>(argv[3]);
    (void)heap_handle;

    auto* mm = static_cast<MemoryManager*>(emu);
    auto* wemu = static_cast<Win32Emulator*>(mm);

    if (old_ptr == 0) {
        // Same as RtlAllocateHeap
        return RtlAllocateHeap(emu, "", 0, {heap_handle, flags, new_size});
    }

    uint64_t new_ptr = wemu->heap_alloc(new_size, "ntdll_realloc");
    if (new_ptr == 0) return 0; // NULL

    // Copy old data — we don't know the old size, just copy up to new_size
    // Read a reasonable amount (use 0x1000 as a guess for old size)
    size_t copy_size = (new_size < 0x1000) ? new_size : 0x1000;
    try {
        auto old_data = mm->mem_read(old_ptr, copy_size);
        mm->mem_write(new_ptr, old_data);
    } catch (...) {
        // If read fails, just leave new memory uninitialized
    }

    // HEAP_ZERO_MEMORY
    if (flags & 0x1) {
        // Zero the tail if we didn't copy enough
        if (copy_size < new_size) {
            size_t tail_size = new_size - copy_size;
            std::vector<uint8_t> zero(tail_size, 0);
            mm->mem_write(new_ptr + copy_size, zero);
        }
    }

    return new_ptr;
}

uint64_t Ntdll::RtlCreateHeap(void* emu, const std::string&, int,
                               const std::vector<uint64_t>& argv) {
    // ULONG Flags, PVOID HeapBase, SIZE_T ReserveSize, SIZE_T CommitSize,
    // PVOID Lock, PRTL_HEAP_PARAMETERS Parameters
    uint32_t flags = static_cast<uint32_t>(argv[0]);
    uint64_t heap_base = argv[1];
    size_t reserve_size = static_cast<size_t>(argv[2]);
    size_t commit_size = static_cast<size_t>(argv[3]);
    (void)flags;
    (void)commit_size;

    if (reserve_size == 0) reserve_size = 0x10000; // default heap size

    auto* mm = static_cast<MemoryManager*>(emu);

    if (heap_base != 0) {
        // Use the specified base — just return it as a handle
        return heap_base;
    }

    // Allocate a new heap
    uint64_t addr = mm->mem_map(reserve_size, 0, 0x4, "heap");
    return addr;
}

uint64_t Ntdll::RtlDestroyHeap(void* emu, const std::string&, int,
                                const std::vector<uint64_t>& argv) {
    // HANDLE HeapHandle
    uint64_t heap_handle = argv[0];
    if (heap_handle == 0) return 0; // NT_SUCCESS? Actually returns 1 on success

    try {
        static_cast<MemoryManager*>(emu)->mem_free(heap_handle);
        return 1; // TRUE
    } catch (...) {
        return 0; // FALSE
    }
}

uint64_t Ntdll::RtlGetProcessHeap(void* emu, const std::string&, int,
                                   const std::vector<uint64_t>&) {
    // Return the process heap. The Python emulator stores it.
    // We'll allocate one lazily or return a known address.
    auto* wemu = static_cast<Win32Emulator*>(static_cast<MemoryManager*>(emu));
    uint64_t heap = wemu->heap_alloc(0x10000, "process_heap");
    return heap;
}

// ═══════════════════════════════════════════════════════════════
// Virtual Memory
// ═══════════════════════════════════════════════════════════════

uint64_t Ntdll::NtAllocateVirtualMemory(void* emu, const std::string&, int,
                                          const std::vector<uint64_t>& argv) {
    // HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits,
    // PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect
    uint64_t proc_handle = argv[0];
    uint64_t base_addr_ptr = argv[1];
    uint64_t zero_bits = argv[2];
    uint64_t region_size_ptr = argv[3];
    uint32_t alloc_type = static_cast<uint32_t>(argv[4]);
    uint32_t protect = static_cast<uint32_t>(argv[5]);
    (void)proc_handle;
    (void)zero_bits;

    auto* mm = static_cast<MemoryManager*>(emu);

    // Read the desired base address
    uint64_t desired_base = 0;
    if (base_addr_ptr != 0) {
        desired_base = read_ptr(emu, base_addr_ptr);
    }

    // Read the region size
    size_t region_size = 0;
    if (region_size_ptr != 0) {
        region_size = static_cast<size_t>(read_ptr(emu, region_size_ptr));
    }

    if (region_size == 0) return STATUS_INVALID_PARAMETER;

    uint32_t perms = 0;
    // Convert Windows protection constants to internal perms
    // PAGE_NOACCESS=1, PAGE_READONLY=2, PAGE_READWRITE=4,
    // PAGE_WRITECOPY=8, PAGE_EXECUTE=16, PAGE_EXECUTE_READ=32,
    // PAGE_EXECUTE_READWRITE=64, PAGE_EXECUTE_WRITECOPY=128
    if (protect & 0x10) perms |= 0x1; // EXECUTE
    if (protect & 0x04) perms |= 0x2; // WRITE
    if (protect & 0x02) perms |= 0x4; // READ
    if (protect == 0x01) perms = 0;   // NOACCESS

    uint64_t allocated_base = 0;
    try {
        if (alloc_type & 0x20000) { // MEM_RESERVE
            allocated_base = mm->mem_reserve(region_size, desired_base, perms, "vm_reserve");
        } else {
            allocated_base = mm->mem_map(region_size, desired_base, perms, "vm_alloc",
                                          alloc_type, false);
        }
    } catch (...) {
        return NT_UNSUCCESSFUL;
    }

    // Write back the base address and region size
    if (base_addr_ptr != 0) {
        write_ptr(emu, base_addr_ptr, allocated_base);
    }
    if (region_size_ptr != 0) {
        write_ptr(emu, region_size_ptr, region_size);
    }

    return NT_SUCCESS;
}

uint64_t Ntdll::NtFreeVirtualMemory(void* emu, const std::string&, int,
                                     const std::vector<uint64_t>& argv) {
    // HANDLE ProcessHandle, PVOID *BaseAddress, PSIZE_T RegionSize, ULONG FreeType
    uint64_t proc_handle = argv[0];
    uint64_t base_addr_ptr = argv[1];
    uint64_t region_size_ptr = argv[2];
    uint32_t free_type = static_cast<uint32_t>(argv[3]);
    (void)proc_handle;
    (void)region_size_ptr;
    (void)free_type;

    auto* mm = static_cast<MemoryManager*>(emu);

    uint64_t base_addr = 0;
    if (base_addr_ptr != 0) {
        base_addr = read_ptr(emu, base_addr_ptr);
    }

    if (base_addr == 0) return STATUS_INVALID_PARAMETER;

    try {
        mm->mem_free(base_addr);
    } catch (...) {
        return NT_UNSUCCESSFUL;
    }

    return NT_SUCCESS;
}

uint64_t Ntdll::NtProtectVirtualMemory(void* emu, const std::string&, int,
                                        const std::vector<uint64_t>& argv) {
    // HANDLE ProcessHandle, PVOID *BaseAddress, PSIZE_T RegionSize,
    // ULONG NewProtect, PULONG OldProtect
    uint64_t proc_handle = argv[0];
    uint64_t base_addr_ptr = argv[1];
    uint64_t region_size_ptr = argv[2];
    uint32_t new_protect = static_cast<uint32_t>(argv[3]);
    uint64_t old_protect_ptr = argv[4];
    (void)proc_handle;

    auto* mm = static_cast<MemoryManager*>(emu);

    uint64_t base_addr = 0;
    if (base_addr_ptr != 0) {
        base_addr = read_ptr(emu, base_addr_ptr);
    }

    size_t region_size = 0;
    if (region_size_ptr != 0) {
        region_size = static_cast<size_t>(read_ptr(emu, region_size_ptr));
    }

    if (base_addr == 0 || region_size == 0) return STATUS_INVALID_PARAMETER;

    // Get old protection from the memory map
    uint32_t old_perms = 0;
    auto map = mm->get_address_map(base_addr);
    if (map) {
        old_perms = map->get_prot();
    }

    // Convert new_protect to internal perms
    uint32_t perms = 0;
    if (new_protect & 0x10) perms |= 0x1; // EXECUTE
    if (new_protect & 0x04) perms |= 0x2; // WRITE
    if (new_protect & 0x02) perms |= 0x4; // READ
    if (new_protect == 0x01) perms = 0;   // NOACCESS

    // Convert old_perms back to Windows protection for writing back
    uint32_t old_protect = 0;
    if (old_perms & 0x4) old_protect |= 0x02; // READ
    if (old_perms & 0x2) old_protect |= 0x04; // WRITE
    if (old_perms & 0x1) old_protect |= 0x10; // EXECUTE
    if (old_protect == 0) old_protect = 0x01;  // NOACCESS

    if (old_protect_ptr != 0) {
        write_u32(emu, old_protect_ptr, old_protect);
    }

    try {
        mm->mem_protect(base_addr, region_size, perms);
    } catch (...) {
        return NT_UNSUCCESSFUL;
    }

    return NT_SUCCESS;
}

uint64_t Ntdll::NtQueryVirtualMemory(void* emu, const std::string&, int,
                                      const std::vector<uint64_t>& argv) {
    // HANDLE ProcessHandle, PVOID BaseAddress, MEMORY_INFORMATION_CLASS InfoClass,
    // PVOID MemoryInformation, SIZE_T MemoryInformationLength, PSIZE_T ReturnLength
    (void)emu; (void)argv;
    // Stub — returns success with basic info
    return NT_SUCCESS;
}

// ═══════════════════════════════════════════════════════════════
// File I/O
// ═══════════════════════════════════════════════════════════════

uint64_t Ntdll::NtCreateFile(void* emu, const std::string&, int,
                              const std::vector<uint64_t>& argv) {
    // PHANDLE FileHandle, ACCESS_MASK DesiredAccess,
    // POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock,
    // PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess,
    // ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength
    uint64_t file_handle_ptr = argv[0];
    uint32_t desired_access = static_cast<uint32_t>(argv[1]);
    uint64_t obj_attr_ptr = argv[2];
    uint64_t io_status_ptr = argv[3];
    (void)argv[4]; // AllocationSize
    uint32_t file_attributes = static_cast<uint32_t>(argv[5]);
    uint32_t share_access = static_cast<uint32_t>(argv[6]);
    uint32_t create_disposition = static_cast<uint32_t>(argv[7]);
    uint32_t create_options = static_cast<uint32_t>(argv[8]);
    (void)argv[9]; // EaBuffer
    (void)argv[10]; // EaLength

    (void)desired_access;
    (void)file_attributes;
    (void)share_access;
    (void)create_options;

    // Parse OBJECT_ATTRIBUTES
    // OBJECT_ATTRIBUTES: Length(4), RootDirectory(ptr), ObjectName(ptr),
    //                    Attributes(4), SecurityDescriptor(ptr),
    //                    SecurityQualityOfService(ptr)
    uint64_t obj_name_ptr = 0;
    if (obj_attr_ptr != 0) {
        obj_name_ptr = read_ptr(emu, obj_attr_ptr + get_ptr_size(emu) + 4);
    }

    std::string file_path;
    if (obj_name_ptr != 0) {
        file_path = read_unicode_string_content(emu, obj_name_ptr);
    }

    if (file_path.empty()) {
        // Write IO_STATUS_BLOCK
        if (io_status_ptr != 0) {
            write_u32(emu, io_status_ptr, STATUS_OBJECT_NAME_NOT_FOUND);
        }
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }

    // Check if the file should be created
    bool create = (create_disposition == 1 ||  // FILE_CREATE
                   create_disposition == 2 ||  // FILE_OPEN_IF
                   create_disposition == 3);   // FILE_OVERWRITE_IF

    auto* wemu = static_cast<WindowsEmulator*>(static_cast<MemoryManager*>(emu));

    // Open the file through the emulator's file manager
    void* file_obj = wemu->file_open(file_path, create);
    if (!file_obj && create) {
        // Try to create it
        file_obj = wemu->file_open(file_path, true);
    }

    if (!file_obj) {
        if (io_status_ptr != 0) {
            write_u32(emu, io_status_ptr, STATUS_OBJECT_NAME_NOT_FOUND);
        }
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }

    // Get the handle from the file object
    auto* file_mgr = static_cast<FileManager*>(wemu->get_file_manager());
    uint32_t handle = 0;
    // FileManager's file_open returns bool? Actually let's look at the method.
    // file_open returns a File* (from winemu.h: void* file_open)
    // File handles are managed internally by FileManager.
    // Let's use the object manager to get/assign a handle
    uint32_t file_handle = wemu->get_object_handle(file_obj);
    if (file_handle == 0) {
        // Assign a new handle
        // For now, just use a dummy handle
        file_handle = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(file_obj) & 0xFFFF);
        (void)handle;
    }

    // Write the file handle
    if (file_handle_ptr != 0) {
        // The File* pointer itself can serve as a handle in the emulated world
        write_ptr(emu, file_handle_ptr, reinterpret_cast<uint64_t>(file_obj));
    }

    // Write IO_STATUS_BLOCK
    if (io_status_ptr != 0) {
        write_u32(emu, io_status_ptr, NT_SUCCESS);
        write_ptr(emu, io_status_ptr + get_ptr_size(emu),
                  static_cast<uint64_t>(create_disposition));
    }

    return NT_SUCCESS;
}

uint64_t Ntdll::NtOpenFile(void* emu, const std::string&, int,
                            const std::vector<uint64_t>& argv) {
    // PHANDLE FileHandle, ACCESS_MASK DesiredAccess,
    // POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock,
    // ULONG ShareAccess, ULONG OpenOptions
    uint64_t file_handle_ptr = argv[0];
    uint32_t desired_access = static_cast<uint32_t>(argv[1]);
    uint64_t obj_attr_ptr = argv[2];
    uint64_t io_status_ptr = argv[3];
    (void)argv[4]; // ShareAccess
    (void)argv[5]; // OpenOptions
    (void)desired_access;

    // Parse OBJECT_ATTRIBUTES to get the file path
    uint64_t obj_name_ptr = 0;
    if (obj_attr_ptr != 0) {
        obj_name_ptr = read_ptr(emu, obj_attr_ptr + get_ptr_size(emu) + 4);
    }

    std::string file_path;
    if (obj_name_ptr != 0) {
        file_path = read_unicode_string_content(emu, obj_name_ptr);
    }

    if (file_path.empty()) {
        if (io_status_ptr != 0) {
            write_u32(emu, io_status_ptr, STATUS_OBJECT_NAME_NOT_FOUND);
        }
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }

    auto* wemu = static_cast<WindowsEmulator*>(static_cast<MemoryManager*>(emu));
    void* file_obj = wemu->file_open(file_path, false);

    if (!file_obj) {
        if (io_status_ptr != 0) {
            write_u32(emu, io_status_ptr, STATUS_OBJECT_NAME_NOT_FOUND);
        }
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }

    if (file_handle_ptr != 0) {
        write_ptr(emu, file_handle_ptr, reinterpret_cast<uint64_t>(file_obj));
    }

    if (io_status_ptr != 0) {
        write_u32(emu, io_status_ptr, NT_SUCCESS);
        write_ptr(emu, io_status_ptr + get_ptr_size(emu), 0); // Information
    }

    return NT_SUCCESS;
}

uint64_t Ntdll::NtReadFile(void* emu, const std::string&, int,
                            const std::vector<uint64_t>& argv) {
    // HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine,
    // PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer,
    // ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key
    uint64_t file_handle = argv[0];
    (void)argv[1]; // Event
    (void)argv[2]; // ApcRoutine
    (void)argv[3]; // ApcContext
    uint64_t io_status_ptr = argv[4];
    uint64_t buffer = argv[5];
    uint32_t length = static_cast<uint32_t>(argv[6]);
    uint64_t byte_offset = argv[7];
    (void)argv[8]; // Key

    auto* mm = static_cast<MemoryManager*>(emu);
    auto* wemu = static_cast<WindowsEmulator*>(mm);

    if (file_handle == 0 || buffer == 0 || length == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    // Get the file object from the file manager
    auto* fm = static_cast<FileManager*>(wemu->get_file_manager());
    auto file_obj = fm->get_file_from_handle(static_cast<uint32_t>(file_handle));

    // Also try treating file_handle as a direct File* pointer
    if (!file_obj) {
        // File might be stored as a direct pointer
        // For now, just return success with zero data
        if (io_status_ptr != 0) {
            write_u32(emu, io_status_ptr, NT_SUCCESS);
            write_ptr(emu, io_status_ptr + get_ptr_size(emu), 0);
        }
        return NT_SUCCESS;
    }

    // Seek to byte offset if provided
    if (byte_offset != 0 && byte_offset != static_cast<uint64_t>(-1)) {
        file_obj->seek(byte_offset, 0); // SEEK_SET
    }

    // Read data
    auto data = file_obj->get_data(length, false);
    if (!data.empty()) {
        mm->mem_write(buffer, data);
    }

    // Write IO_STATUS_BLOCK
    if (io_status_ptr != 0) {
        write_u32(emu, io_status_ptr, NT_SUCCESS);
        write_ptr(emu, io_status_ptr + get_ptr_size(emu), data.size());
    }

    return NT_SUCCESS;
}

uint64_t Ntdll::NtWriteFile(void* emu, const std::string&, int,
                             const std::vector<uint64_t>& argv) {
    // HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine,
    // PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer,
    // ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key
    uint64_t file_handle = argv[0];
    (void)argv[1]; // Event
    (void)argv[2]; // ApcRoutine
    (void)argv[3]; // ApcContext
    uint64_t io_status_ptr = argv[4];
    uint64_t buffer = argv[5];
    uint32_t length = static_cast<uint32_t>(argv[6]);
    uint64_t byte_offset = argv[7];
    (void)argv[8]; // Key

    auto* mm = static_cast<MemoryManager*>(emu);
    auto* wemu = static_cast<WindowsEmulator*>(mm);

    if (file_handle == 0 || buffer == 0 || length == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    auto* fm = static_cast<FileManager*>(wemu->get_file_manager());
    auto file_obj = fm->get_file_from_handle(static_cast<uint32_t>(file_handle));

    if (!file_obj) {
        if (io_status_ptr != 0) {
            write_u32(emu, io_status_ptr, NT_SUCCESS);
            write_ptr(emu, io_status_ptr + get_ptr_size(emu), length);
        }
        return NT_SUCCESS;
    }

    // Seek to byte offset if provided
    if (byte_offset != 0 && byte_offset != static_cast<uint64_t>(-1)) {
        file_obj->seek(byte_offset, 0);
    }

    // Read data from emulated memory and write to file
    auto data = mm->mem_read(buffer, length);
    file_obj->add_data(data);

    if (io_status_ptr != 0) {
        write_u32(emu, io_status_ptr, NT_SUCCESS);
        write_ptr(emu, io_status_ptr + get_ptr_size(emu), data.size());
    }

    return NT_SUCCESS;
}

uint64_t Ntdll::NtClose(void* emu, const std::string&, int,
                         const std::vector<uint64_t>& argv) {
    // HANDLE Handle
    uint64_t handle = argv[0];
    (void)emu; (void)handle;
    // Just return success — the handle cleanup is handled by the emulator's GC
    return NT_SUCCESS;
}

uint64_t Ntdll::NtDeviceIoControlFile(void* emu, const std::string&, int,
                                       const std::vector<uint64_t>& argv) {
    // HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine,
    // PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, ULONG IoControlCode,
    // PVOID InputBuffer, ULONG InputBufferLength,
    // PVOID OutputBuffer, ULONG OutputBufferLength
    uint64_t file_handle = argv[0];
    uint64_t io_status_ptr = argv[4];
    uint32_t ctl_code = static_cast<uint32_t>(argv[5]);
    uint64_t in_buf = argv[6];
    uint32_t in_len = static_cast<uint32_t>(argv[7]);
    uint64_t out_buf = argv[8];
    uint32_t out_len = static_cast<uint32_t>(argv[9]);
    (void)file_handle; (void)in_buf; (void)in_len; (void)out_buf; (void)out_len;

    auto* wemu = static_cast<WindowsEmulator*>(static_cast<MemoryManager*>(emu));
    wemu->dev_ioctl(ctl_code, reinterpret_cast<void*>(in_buf), in_len,
                    reinterpret_cast<void*>(out_buf), out_len);

    if (io_status_ptr != 0) {
        write_u32(emu, io_status_ptr, NT_SUCCESS);
        write_ptr(emu, io_status_ptr + get_ptr_size(emu), 0);
    }

    return NT_SUCCESS;
}

// ═══════════════════════════════════════════════════════════════
// Process / Thread
// ═══════════════════════════════════════════════════════════════

uint64_t Ntdll::NtCreateProcess(void* emu, const std::string&, int,
                                 const std::vector<uint64_t>& argv) {
    // PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess,
    // POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ParentProcess,
    // BOOLEAN InheritObjectTable, HANDLE SectionHandle,
    // HANDLE DebugPort, HANDLE ExceptionPort
    (void)emu; (void)argv;
    return NT_SUCCESS;
}

uint64_t Ntdll::NtCreateThread(void* emu, const std::string&, int,
                                const std::vector<uint64_t>& argv) {
    // PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess,
    // POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle,
    // PCLIENT_ID ClientId, PCONTEXT ThreadContext,
    // PUSER_STACK UserStack, BOOLEAN CreateSuspended
    uint64_t thread_handle_ptr = argv[0];
    uint64_t proc_handle = argv[3];
    uint64_t client_id_ptr = argv[4];
    uint64_t thread_ctx = argv[5];
    uint64_t user_stack = argv[6];
    uint8_t create_suspended = static_cast<uint8_t>(argv[7]);
    (void)user_stack;

    auto* wemu = static_cast<WindowsEmulator*>(static_cast<MemoryManager*>(emu));

    // Get thread start address from CONTEXT (depends on arch)
    uint64_t start_addr = 0;
    if (thread_ctx != 0) {
        int psz = get_ptr_size(emu);
        if (psz == 8) {
            // x64 CONTEXT: Rip is at offset 0x... 
            // For simplicity, read from the pointer
            start_addr = read_ptr(emu, thread_ctx + 0x80); // approximate Rip offset
        } else {
            // x86 CONTEXT: Eip is at offset 0xB0 or similar
            start_addr = read_ptr(emu, thread_ctx + 0xB0);
        }
        if (start_addr == 0) start_addr = read_ptr(emu, thread_ctx); // fallback
    }

    // Get the process object
    void* proc_obj = wemu->get_object_from_handle(static_cast<int>(proc_handle));
    std::shared_ptr<Process> proc_sp;
    if (proc_obj) {
        proc_sp = wemu->find_process(proc_obj);
    }
    if (!proc_sp) {
        proc_sp = wemu->get_current_process();
    }

    // Create the thread
    auto thread_obj = wemu->create_thread(start_addr, nullptr, proc_sp,
                                            "thread", create_suspended != 0);
    if (!thread_obj) return NT_UNSUCCESSFUL;

    // Write the thread handle
    if (thread_handle_ptr != 0) {
        int thread_handle = wemu->get_object_handle(thread_obj.get());
        if (thread_handle == 0) {
            thread_handle = reinterpret_cast<uintptr_t>(thread_obj.get()) & 0xFFFF;
        }
        write_ptr(emu, thread_handle_ptr, static_cast<uint64_t>(thread_handle));
    }

    // Write CLIENT_ID if provided
    if (client_id_ptr != 0) {
        // UniqueProcess (ptr) + UniqueThread (ptr)
        std::shared_ptr<Process> proc = wemu->get_current_process();
        int pid = proc ? proc->get_pid() : 4;
        write_ptr(emu, client_id_ptr, static_cast<uint64_t>(pid));
        int tid = static_cast<int>(reinterpret_cast<uintptr_t>(thread_obj.get()) & 0xFFFF);
        write_ptr(emu, client_id_ptr + get_ptr_size(emu), static_cast<uint64_t>(tid));
    }

    return NT_SUCCESS;
}

uint64_t Ntdll::NtOpenThread(void* emu, const std::string&, int,
                              const std::vector<uint64_t>& argv) {
    // PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess,
    // POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId
    uint64_t thread_handle_ptr = argv[0];
    uint64_t client_id_ptr = argv[3];
    (void)argv[1]; (void)argv[2];

    auto* wemu = static_cast<WindowsEmulator*>(static_cast<MemoryManager*>(emu));

    if (client_id_ptr != 0) {
        uint64_t tid = read_ptr(emu, client_id_ptr + get_ptr_size(emu));
        // Try to find a thread by its handle or ID
        auto thread_obj = wemu->find_thread(static_cast<int>(tid));
        if (thread_obj) {
            if (thread_handle_ptr != 0) {
                write_ptr(emu, thread_handle_ptr, tid);
            }
            return NT_SUCCESS;
        }
    }

    // Fallback: return the current thread
    auto curr_thread = wemu->get_current_thread();
    if (curr_thread && thread_handle_ptr != 0) {
        int h = wemu->get_object_handle(curr_thread.get());
        if (h == 0) h = reinterpret_cast<uintptr_t>(curr_thread.get()) & 0xFFFF;
        write_ptr(emu, thread_handle_ptr, static_cast<uint64_t>(h));
        return NT_SUCCESS;
    }

    return STATUS_INVALID_PARAMETER;
}

uint64_t Ntdll::NtTerminateProcess(void* emu, const std::string&, int,
                                    const std::vector<uint64_t>& argv) {
    // HANDLE ProcessHandle, NTSTATUS ExitStatus
    uint64_t proc_handle = argv[0];
    (void)argv[1]; // ExitStatus

    auto* wemu = static_cast<WindowsEmulator*>(static_cast<MemoryManager*>(emu));
    auto* w32emu = static_cast<Win32Emulator*>(static_cast<MemoryManager*>(emu));

    if (proc_handle == static_cast<uint64_t>(-1) || proc_handle == 0) {
        // Terminate the current process
        w32emu->exit_process();
        w32emu->stop();
        return NT_SUCCESS;
    }

    void* proc_obj = wemu->get_object_from_handle(static_cast<int>(proc_handle));
    if (proc_obj) {
        wemu->kill_process(proc_obj);
        return NT_SUCCESS;
    }

    return NT_INVALID_HANDLE;
}

uint64_t Ntdll::NtTerminateThread(void* emu, const std::string&, int,
                                   const std::vector<uint64_t>& argv) {
    // HANDLE ThreadHandle, NTSTATUS ExitStatus
    (void)emu; (void)argv;
    return NT_SUCCESS;
}

uint64_t Ntdll::NtGetContextThread(void* emu, const std::string&, int,
                                    const std::vector<uint64_t>& argv) {
    // HANDLE ThreadHandle, PCONTEXT ThreadContext
    uint64_t thread_handle = argv[0];
    uint64_t ctx_ptr = argv[1];

    auto* wemu = static_cast<WindowsEmulator*>(static_cast<MemoryManager*>(emu));

    // Get the thread object
    auto thread_obj = wemu->find_thread(static_cast<int>(thread_handle));
    if (!thread_obj) {
        thread_obj = wemu->get_current_thread();
    }

    void* ctx = wemu->get_thread_context(thread_obj);
    if (ctx && ctx_ptr != 0) {
        // Copy context data to the output pointer
        // CONTEXT structure size varies by arch — just copy pointer
        write_ptr(emu, ctx_ptr, reinterpret_cast<uint64_t>(ctx));
    }

    return NT_SUCCESS;
}

uint64_t Ntdll::NtSetContextThread(void* emu, const std::string&, int,
                                    const std::vector<uint64_t>& argv) {
    // HANDLE ThreadHandle, PCONTEXT ThreadContext
    (void)emu; (void)argv;
    return NT_SUCCESS;
}

// ═══════════════════════════════════════════════════════════════
// System Info
// ═══════════════════════════════════════════════════════════════

uint64_t Ntdll::NtQuerySystemInformation(void* emu, const std::string&, int,
                                          const std::vector<uint64_t>& argv) {
    // SYSTEM_INFORMATION_CLASS SystemInformationClass,
    // PVOID SystemInformation, ULONG SystemInformationLength,
    // PULONG ReturnLength
    uint32_t info_class = static_cast<uint32_t>(argv[0]);
    uint64_t info_ptr = argv[1];
    uint32_t info_len = static_cast<uint32_t>(argv[2]);
    uint64_t ret_len_ptr = argv[3];

    auto* mm = static_cast<MemoryManager*>(emu);
    auto* bemu = static_cast<BinaryEmulator*>(mm);

    switch (info_class) {
        case 0x05: { // SystemProcessInformation
            // This is complex — just return success for now
            if (ret_len_ptr != 0) {
                write_u32(emu, ret_len_ptr, info_len);
            }
            break;
        }
        default:
            if (ret_len_ptr != 0) {
                write_u32(emu, ret_len_ptr, 0);
            }
            break;
    }

    (void)bemu;
    return NT_SUCCESS;
}

uint64_t Ntdll::NtQueryInformationProcess(void* emu, const std::string&, int,
                                           const std::vector<uint64_t>& argv) {
    // HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass,
    // PVOID ProcessInformation, ULONG ProcessInformationLength,
    // PULONG ReturnLength
    uint64_t proc_handle = argv[0];
    uint32_t info_class = static_cast<uint32_t>(argv[1]);
    uint64_t info_ptr = argv[2];
    uint32_t info_len = static_cast<uint32_t>(argv[3]);
    uint64_t ret_len_ptr = argv[4];
    (void)info_len;

    auto* wemu = static_cast<WindowsEmulator*>(static_cast<MemoryManager*>(emu));

    std::shared_ptr<Process> proc;
    void* proc_obj = wemu->get_object_from_handle(static_cast<int>(proc_handle));
    if (proc_obj) {
        proc = wemu->find_process(proc_obj);
    } else {
        proc = wemu->get_current_process();
    }

    int psz = get_ptr_size(emu);

    switch (info_class) {
        case 0: { // ProcessBasicInformation
            // PEB_BASIC_INFORMATION: UniqueProcessId(ptr), InheritedFromUniqueProcessId(ptr),
            //                        PebBaseAddress(ptr), ...
            if (proc && info_ptr) {
                write_ptr(emu, info_ptr, static_cast<uint64_t>(proc->get_pid()));
                write_ptr(emu, info_ptr + psz, 0); // InheritedFrom
                uint64_t peb_addr = reinterpret_cast<uint64_t>(proc->get_peb());
                write_ptr(emu, info_ptr + psz * 2, peb_addr);
            }
            if (ret_len_ptr) write_u32(emu, ret_len_ptr, psz * 3);
            break;
        }
        case 0x1A: { // ProcessImageFileName
            // Return the image file name as a UNICODE_STRING
            if (proc && info_ptr) {
                std::string img_path = proc->get_process_path();
                // info_ptr points to a UNICODE_STRING
                // Allocate buffer after the structure
                uint64_t buf_addr = info_ptr + psz + 4 + 2; // after UNICODE_STRING
                write_unicode_string(emu, info_ptr, img_path, buf_addr);
                if (ret_len_ptr) write_u32(emu, ret_len_ptr, (psz + 4) + img_path.size() * 2 + 2);
            }
            break;
        }
        default:
            if (ret_len_ptr) write_u32(emu, ret_len_ptr, 0);
            break;
    }

    return NT_SUCCESS;
}

uint64_t Ntdll::NtSetInformationProcess(void* emu, const std::string&, int,
                                         const std::vector<uint64_t>& argv) {
    // HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass,
    // PVOID ProcessInformation, ULONG ProcessInformationLength
    (void)emu; (void)argv;
    return NT_SUCCESS;
}

// ═══════════════════════════════════════════════════════════════
// Registry
// ═══════════════════════════════════════════════════════════════

/// Helper: convert registry define values to their string path prefixes
static std::string reg_hkey_to_path(uint32_t hkey) {
    switch (hkey) {
        case 0x80000000: return "\\Registry\\Machine\\Software\\Classes";
        case 0x80000001: return "\\Registry\\User\\";
        case 0x80000002: return "\\Registry\\Machine\\";
        case 0x80000003: return "\\Registry\\User\\";
        default: return "";
    }
}

uint64_t Ntdll::NtCreateKey(void* emu, const std::string&, int,
                             const std::vector<uint64_t>& argv) {
    // PHANDLE KeyHandle, ACCESS_MASK DesiredAccess,
    // POBJECT_ATTRIBUTES ObjectAttributes, ULONG TitleIndex,
    // PUNICODE_STRING Class, ULONG CreateOptions,
    // PULONG Disposition
    uint64_t key_handle_ptr = argv[0];
    uint64_t obj_attr_ptr = argv[2];
    uint64_t disposition_ptr = argv[6];
    (void)argv[1]; // DesiredAccess
    (void)argv[3]; // TitleIndex
    (void)argv[4]; // Class
    (void)argv[5]; // CreateOptions

    auto* wemu = static_cast<WindowsEmulator*>(static_cast<MemoryManager*>(emu));

    // Parse OBJECT_ATTRIBUTES: Length(4), RootDirectory(ptr), ObjectName(ptr), ...
    uint64_t root_dir = 0;
    uint64_t obj_name_ptr = 0;
    if (obj_attr_ptr != 0) {
        root_dir = read_ptr(emu, obj_attr_ptr + 4);
        obj_name_ptr = read_ptr(emu, obj_attr_ptr + 4 + get_ptr_size(emu));
    }

    std::string key_path;
    if (obj_name_ptr != 0) {
        key_path = read_unicode_string_content(emu, obj_name_ptr);
    }

    // Construct full path
    std::string full_path;
    if (root_dir != 0) {
        std::string root_path = reg_hkey_to_path(static_cast<uint32_t>(root_dir));
        full_path = root_path + "\\" + key_path;
    } else {
        full_path = key_path;
    }

    // If path starts with \Registry\Machine\, use HKLM
    // If starts with \Registry\User\, use HKCU
    // etc.
    void* hkey = wemu->reg_open_key(full_path, true);
    if (!hkey) {
        hkey = wemu->reg_create_key(full_path);
    }

    if (!hkey) return STATUS_OBJECT_NAME_NOT_FOUND;

    // Get or create a handle
    int handle = wemu->get_object_handle(hkey);
    if (handle == 0) {
        handle = reinterpret_cast<uintptr_t>(hkey) & 0x7FFFFFFF;
    }

    if (key_handle_ptr != 0) {
        write_ptr(emu, key_handle_ptr, static_cast<uint64_t>(handle));
    }

    if (disposition_ptr != 0) {
        write_u32(emu, disposition_ptr, 1); // REG_CREATED_NEW_KEY
    }

    return NT_SUCCESS;
}

uint64_t Ntdll::NtOpenKey(void* emu, const std::string&, int,
                           const std::vector<uint64_t>& argv) {
    // PHANDLE KeyHandle, ACCESS_MASK DesiredAccess,
    // POBJECT_ATTRIBUTES ObjectAttributes
    uint64_t key_handle_ptr = argv[0];
    uint64_t obj_attr_ptr = argv[2];
    (void)argv[1]; // DesiredAccess

    auto* wemu = static_cast<WindowsEmulator*>(static_cast<MemoryManager*>(emu));

    uint64_t root_dir = 0;
    uint64_t obj_name_ptr = 0;
    if (obj_attr_ptr != 0) {
        root_dir = read_ptr(emu, obj_attr_ptr + 4);
        obj_name_ptr = read_ptr(emu, obj_attr_ptr + 4 + get_ptr_size(emu));
    }

    std::string key_path;
    if (obj_name_ptr != 0) {
        key_path = read_unicode_string_content(emu, obj_name_ptr);
    }

    std::string full_path;
    if (root_dir != 0) {
        std::string root_path = reg_hkey_to_path(static_cast<uint32_t>(root_dir));
        full_path = root_path + "\\" + key_path;
    } else {
        full_path = key_path;
    }

    void* hkey = wemu->reg_open_key(full_path, false);
    if (!hkey) return STATUS_OBJECT_NAME_NOT_FOUND;

    int handle = wemu->get_object_handle(hkey);
    if (handle == 0) {
        handle = reinterpret_cast<uintptr_t>(hkey) & 0x7FFFFFFF;
    }

    if (key_handle_ptr != 0) {
        write_ptr(emu, key_handle_ptr, static_cast<uint64_t>(handle));
    }

    return NT_SUCCESS;
}

uint64_t Ntdll::NtQueryValueKey(void* emu, const std::string&, int,
                                 const std::vector<uint64_t>& argv) {
    // HANDLE KeyHandle, PUNICODE_STRING ValueName,
    // KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
    // PVOID KeyValueInformation, ULONG KeyValueInformationLength,
    // PULONG ResultLength
    uint64_t key_handle = argv[0];
    uint64_t value_name_ptr = argv[1];
    uint32_t info_class = static_cast<uint32_t>(argv[2]);
    uint64_t info_ptr = argv[3];
    uint32_t info_len = static_cast<uint32_t>(argv[4]);
    uint64_t result_len_ptr = argv[5];

    auto* wemu = static_cast<WindowsEmulator*>(static_cast<MemoryManager*>(emu));
    auto* mm = static_cast<MemoryManager*>(emu);

    std::string value_name;
    if (value_name_ptr != 0) {
        value_name = read_unicode_string_content(emu, value_name_ptr);
    }

    // Get the registry key from handle
    void* key_obj = wemu->get_object_from_handle(static_cast<int>(key_handle));
    if (!key_obj) {
        if (result_len_ptr != 0) write_u32(emu, result_len_ptr, 0);
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }

    auto* regkey = static_cast<RegKey*>(key_obj);
    auto val = regkey->get_value(value_name);
    if (!val) {
        if (result_len_ptr != 0) write_u32(emu, result_len_ptr, 0);
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }

    // Build the key value information structure
    // KEY_VALUE_BASIC_INFORMATION (class 0): TitleIndex(4), Type(4), Name[1](variable)
    // KEY_VALUE_FULL_INFORMATION (class 1): TitleIndex(4), Type(4), DataOffset(4),
    //                                       DataLength(4), Name[1](variable)
    // KEY_VALUE_PARTIAL_INFORMATION (class 2): TitleIndex(4), Type(4), DataLength(4),
    //                                           Data[1](variable)

    std::string val_data_str = val->get_data();
    int val_type = val->get_type();
    std::string val_name = val->get_name();

    // Compute total info size needed
    uint32_t needed = 0;
    if (info_class == 0) { // KeyValueBasicInformation
        needed = 8 + static_cast<uint32_t>(val_name.size()) + 2; // + null terminator
    } else if (info_class == 1) { // KeyValueFullInformation
        needed = 16 + static_cast<uint32_t>(val_name.size()) + 2;
    } else if (info_class == 2) { // KeyValuePartialInformation
        needed = 12 + static_cast<uint32_t>(val_data_str.size());
    } else {
        if (result_len_ptr != 0) write_u32(emu, result_len_ptr, 0);
        return STATUS_INVALID_PARAMETER;
    }

    if (result_len_ptr != 0) {
        write_u32(emu, result_len_ptr, needed);
    }

    if (info_ptr == 0 || info_len < needed) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    // Write the information structure
    if (info_class == 0) {
        // KEY_VALUE_BASIC_INFORMATION
        write_u32(emu, info_ptr, 0); // TitleIndex
        write_u32(emu, info_ptr + 4, static_cast<uint32_t>(val_type)); // Type
        // Name follows
        for (size_t i = 0; i < val_name.size(); i++) {
            mm->mem_write(info_ptr + 8 + i, {static_cast<uint8_t>(val_name[i])});
        }
        mm->mem_write(info_ptr + 8 + val_name.size(), {0}); // null terminator
    } else if (info_class == 1) {
        // KEY_VALUE_FULL_INFORMATION
        write_u32(emu, info_ptr, 0); // TitleIndex
        write_u32(emu, info_ptr + 4, static_cast<uint32_t>(val_type)); // Type
        uint32_t data_offset = 8 + static_cast<uint32_t>(val_name.size()) + 2;
        write_u32(emu, info_ptr + 8, data_offset); // DataOffset
        write_u32(emu, info_ptr + 12, static_cast<uint32_t>(val_data_str.size())); // DataLength
        // Name follows
        for (size_t i = 0; i < val_name.size(); i++) {
            mm->mem_write(info_ptr + 16 + i, {static_cast<uint8_t>(val_name[i])});
        }
        mm->mem_write(info_ptr + 16 + val_name.size(), {0}); // null terminator
        // Data at offset
        for (size_t i = 0; i < val_data_str.size(); i++) {
            mm->mem_write(info_ptr + data_offset + i, {static_cast<uint8_t>(val_data_str[i])});
        }
    } else if (info_class == 2) {
        // KEY_VALUE_PARTIAL_INFORMATION
        write_u32(emu, info_ptr, 0); // TitleIndex
        write_u32(emu, info_ptr + 4, static_cast<uint32_t>(val_type)); // Type
        write_u32(emu, info_ptr + 8, static_cast<uint32_t>(val_data_str.size())); // DataLength
        // Data follows
        for (size_t i = 0; i < val_data_str.size(); i++) {
            mm->mem_write(info_ptr + 12 + i, {static_cast<uint8_t>(val_data_str[i])});
        }
    }

    return STATUS_SUCCESS;
}

uint64_t Ntdll::NtSetValueKey(void* emu, const std::string&, int,
                               const std::vector<uint64_t>& argv) {
    // HANDLE KeyHandle, PUNICODE_STRING ValueName,
    // ULONG TitleIndex, ULONG Type,
    // PVOID Data, ULONG DataSize
    uint64_t key_handle = argv[0];
    uint64_t value_name_ptr = argv[1];
    (void)argv[2]; // TitleIndex
    uint32_t val_type = static_cast<uint32_t>(argv[3]);
    uint64_t data_ptr = argv[4];
    uint32_t data_size = static_cast<uint32_t>(argv[5]);

    auto* wemu = static_cast<WindowsEmulator*>(static_cast<MemoryManager*>(emu));
    auto* mm = static_cast<MemoryManager*>(emu);

    std::string value_name;
    if (value_name_ptr != 0) {
        value_name = read_unicode_string_content(emu, value_name_ptr);
    }

    void* key_obj = wemu->get_object_from_handle(static_cast<int>(key_handle));
    if (!key_obj) return STATUS_OBJECT_NAME_NOT_FOUND;

    auto* regkey = static_cast<RegKey*>(key_obj);

    // Read data from emulated memory
    std::string data_str;
    if (data_ptr != 0 && data_size > 0) {
        auto raw_data = mm->mem_read(data_ptr, data_size);
        data_str.assign(reinterpret_cast<const char*>(raw_data.data()), raw_data.size());
    }

    regkey->create_value(value_name, static_cast<int>(val_type), data_str);
    return STATUS_SUCCESS;
}

uint64_t Ntdll::NtDeleteKey(void* emu, const std::string&, int,
                             const std::vector<uint64_t>& argv) {
    // HANDLE KeyHandle
    uint64_t key_handle = argv[0];

    auto* wemu = static_cast<WindowsEmulator*>(static_cast<MemoryManager*>(emu));

    void* key_obj = wemu->get_object_from_handle(static_cast<int>(key_handle));
    if (!key_obj) return STATUS_OBJECT_NAME_NOT_FOUND;

    // Note: The registry manager doesn't expose a delete_key method directly,
    // but we can return success since the emulated registry is ephemeral
    (void)key_obj;
    return STATUS_SUCCESS;
}

uint64_t Ntdll::NtDeleteValueKey(void* emu, const std::string&, int,
                                  const std::vector<uint64_t>& argv) {
    // HANDLE KeyHandle, PUNICODE_STRING ValueName
    uint64_t key_handle = argv[0];
    uint64_t value_name_ptr = argv[1];

    auto* wemu = static_cast<WindowsEmulator*>(static_cast<MemoryManager*>(emu));

    std::string value_name;
    if (value_name_ptr != 0) {
        value_name = read_unicode_string_content(emu, value_name_ptr);
    }

    void* key_obj = wemu->get_object_from_handle(static_cast<int>(key_handle));
    if (!key_obj) return STATUS_OBJECT_NAME_NOT_FOUND;

    // The registry manager's RegKey doesn't expose delete_value,
    // but we can return success since the emulated registry is ephemeral
    (void)key_obj; (void)value_name;
    return STATUS_SUCCESS;
}

// ═══════════════════════════════════════════════════════════════
// Sections (memory-mapped files)
// ═══════════════════════════════════════════════════════════════

uint64_t Ntdll::NtCreateSection(void* emu, const std::string&, int,
                                 const std::vector<uint64_t>& argv) {
    // PHANDLE SectionHandle, ACCESS_MASK DesiredAccess,
    // POBJECT_ATTRIBUTES ObjectAttributes, PLARGE_INTEGER MaximumSize,
    // ULONG SectionPageProtection, ULONG AllocationAttributes,
    // HANDLE FileHandle
    uint64_t section_handle_ptr = argv[0];
    uint64_t max_size_ptr = argv[3];
    uint32_t page_prot = static_cast<uint32_t>(argv[4]);
    uint64_t file_handle = argv[6];
    (void)argv[1]; // DesiredAccess
    (void)argv[2]; // ObjectAttributes
    (void)argv[5]; // AllocationAttributes

    auto* mm = static_cast<MemoryManager*>(emu);
    auto* wemu = static_cast<WindowsEmulator*>(mm);

    size_t max_size = 0;
    if (max_size_ptr != 0) {
        max_size = static_cast<size_t>(read_ptr(emu, max_size_ptr));
    }

    if (max_size == 0) max_size = 0x1000;

    if (file_handle != 0) {
        // Section backed by a file
        auto fm_ptr = static_cast<FileManager*>(wemu->get_file_manager());
        auto file_map = fm_ptr->get_mapping_from_handle(
            static_cast<uint32_t>(file_handle));
        (void)file_map;
    }

    // Allocate memory for the section
    uint32_t perms = 0;
    if (page_prot & 0x10) perms |= 0x1;
    if (page_prot & 0x04) perms |= 0x2;
    if (page_prot & 0x02) perms |= 0x4;

    uint64_t section_base = mm->mem_map(max_size, 0, perms, "section");

    if (section_handle_ptr != 0) {
        write_ptr(emu, section_handle_ptr, section_base);
    }

    return NT_SUCCESS;
}

uint64_t Ntdll::NtOpenSection(void* emu, const std::string&, int,
                               const std::vector<uint64_t>& argv) {
    // PHANDLE SectionHandle, ACCESS_MASK DesiredAccess,
    // POBJECT_ATTRIBUTES ObjectAttributes
    (void)emu; (void)argv;
    return NT_SUCCESS;
}

uint64_t Ntdll::NtMapViewOfSection(void* emu, const std::string&, int,
                                    const std::vector<uint64_t>& argv) {
    // HANDLE SectionHandle, HANDLE ProcessHandle,
    // PVOID *BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize,
    // PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize,
    // DWORD InheritDisposition, ULONG AllocationType, ULONG Protect
    uint64_t section_handle = argv[0];
    uint64_t base_addr_ptr = argv[2];
    (void)argv[3]; // ZeroBits
    size_t commit_size = static_cast<size_t>(argv[4]);
    (void)argv[5]; // SectionOffset
    uint64_t view_size_ptr = argv[6];
    (void)argv[7]; // InheritDisposition
    (void)argv[8]; // AllocationType
    (void)argv[9]; // Protect
    (void)argv[1]; // ProcessHandle

    auto* mm = static_cast<MemoryManager*>(emu);

    uint64_t base_addr = 0;
    if (base_addr_ptr != 0) {
        base_addr = read_ptr(emu, base_addr_ptr);
    }

    size_t view_size = commit_size;
    if (view_size == 0) view_size = 0x1000;

    if (view_size_ptr != 0) {
        view_size = static_cast<size_t>(read_ptr(emu, view_size_ptr));
    }

    // Map at the section address
    uint64_t mapped = section_handle; // The section handle IS the base address
    if (base_addr_ptr != 0) {
        write_ptr(emu, base_addr_ptr, mapped);
    }
    if (view_size_ptr != 0) {
        write_ptr(emu, view_size_ptr, view_size);
    }

    (void)base_addr; (void)mm;
    return NT_SUCCESS;
}

uint64_t Ntdll::NtUnmapViewOfSection(void* emu, const std::string&, int,
                                      const std::vector<uint64_t>& argv) {
    // HANDLE ProcessHandle, PVOID BaseAddress
    uint64_t proc_handle = argv[0];
    uint64_t base_addr = argv[1];
    (void)proc_handle;

    auto* mm = static_cast<MemoryManager*>(emu);

    try {
        mm->mem_free(base_addr);
    } catch (...) {
        // Ignore errors on unmap
    }

    return NT_SUCCESS;
}

// ═══════════════════════════════════════════════════════════════
// Synchronization
// ═══════════════════════════════════════════════════════════════

uint64_t Ntdll::NtCreateEvent(void* emu, const std::string&, int,
                               const std::vector<uint64_t>& argv) {
    // PHANDLE EventHandle, ACCESS_MASK DesiredAccess,
    // POBJECT_ATTRIBUTES ObjectAttributes, EVENT_TYPE EventType,
    // BOOLEAN InitialState
    uint64_t event_handle_ptr = argv[0];
    uint32_t event_type = static_cast<uint32_t>(argv[3]);
    uint8_t initial_state = static_cast<uint8_t>(argv[4]);
    (void)argv[1]; // DesiredAccess
    (void)argv[2]; // ObjectAttributes
    (void)event_type;

    auto* wemu = static_cast<WindowsEmulator*>(static_cast<MemoryManager*>(emu));

    auto [handle, event_obj] = wemu->create_event("");
    if (!event_obj) return NT_UNSUCCESSFUL;

    // Set initial state if requested
    if (initial_state && event_obj) {
        // The event is created in signaled state via its handle mechanism
        (void)handle;
    }

    if (event_handle_ptr != 0) {
        int h = wemu->get_object_handle(event_obj);
        if (h == 0) h = handle;
        write_ptr(emu, event_handle_ptr, static_cast<uint64_t>(h));
    }

    return NT_SUCCESS;
}

uint64_t Ntdll::NtOpenEvent(void* emu, const std::string&, int,
                             const std::vector<uint64_t>& argv) {
    // PHANDLE EventHandle, ACCESS_MASK DesiredAccess,
    // POBJECT_ATTRIBUTES ObjectAttributes
    uint64_t event_handle_ptr = argv[0];
    uint64_t obj_attr_ptr = argv[2];
    (void)argv[1]; // DesiredAccess

    std::string event_name;
    if (obj_attr_ptr != 0) {
        uint64_t obj_name_ptr = read_ptr(emu, obj_attr_ptr + 4 + get_ptr_size(emu));
        if (obj_name_ptr != 0) {
            event_name = read_unicode_string_content(emu, obj_name_ptr);
        }
    }

    auto* wemu = static_cast<WindowsEmulator*>(static_cast<MemoryManager*>(emu));

    void* event_obj = wemu->get_object_from_name(event_name);
    if (!event_obj) return STATUS_OBJECT_NAME_NOT_FOUND;

    if (event_handle_ptr != 0) {
        int h = wemu->get_object_handle(event_obj);
        if (h == 0) h = reinterpret_cast<uintptr_t>(event_obj) & 0xFFFF;
        write_ptr(emu, event_handle_ptr, static_cast<uint64_t>(h));
    }

    return NT_SUCCESS;
}

uint64_t Ntdll::NtCreateMutant(void* emu, const std::string&, int,
                                const std::vector<uint64_t>& argv) {
    // PHANDLE MutantHandle, ACCESS_MASK DesiredAccess,
    // POBJECT_ATTRIBUTES ObjectAttributes, BOOLEAN InitialOwner
    uint64_t mutant_handle_ptr = argv[0];
    uint8_t initial_owner = static_cast<uint8_t>(argv[3]);
    (void)argv[1]; // DesiredAccess
    (void)argv[2]; // ObjectAttributes
    (void)initial_owner;

    auto* wemu = static_cast<WindowsEmulator*>(static_cast<MemoryManager*>(emu));

    auto [handle, mutant_obj] = wemu->create_mutant("");
    if (!mutant_obj) return NT_UNSUCCESSFUL;

    if (mutant_handle_ptr != 0) {
        int h = wemu->get_object_handle(mutant_obj);
        if (h == 0) h = handle;
        write_ptr(emu, mutant_handle_ptr, static_cast<uint64_t>(h));
    }

    return NT_SUCCESS;
}

uint64_t Ntdll::NtOpenMutant(void* emu, const std::string&, int,
                              const std::vector<uint64_t>& argv) {
    // PHANDLE MutantHandle, ACCESS_MASK DesiredAccess,
    // POBJECT_ATTRIBUTES ObjectAttributes
    uint64_t mutant_handle_ptr = argv[0];
    uint64_t obj_attr_ptr = argv[2];
    (void)argv[1]; // DesiredAccess

    std::string mutant_name;
    if (obj_attr_ptr != 0) {
        uint64_t obj_name_ptr = read_ptr(emu, obj_attr_ptr + 4 + get_ptr_size(emu));
        if (obj_name_ptr != 0) {
            mutant_name = read_unicode_string_content(emu, obj_name_ptr);
        }
    }

    auto* wemu = static_cast<WindowsEmulator*>(static_cast<MemoryManager*>(emu));

    void* mutant_obj = wemu->get_object_from_name(mutant_name);
    if (!mutant_obj) return STATUS_OBJECT_NAME_NOT_FOUND;

    if (mutant_handle_ptr != 0) {
        int h = wemu->get_object_handle(mutant_obj);
        if (h == 0) h = reinterpret_cast<uintptr_t>(mutant_obj) & 0xFFFF;
        write_ptr(emu, mutant_handle_ptr, static_cast<uint64_t>(h));
    }

    return NT_SUCCESS;
}

uint64_t Ntdll::NtWaitForSingleObject(void* emu, const std::string&, int,
                                       const std::vector<uint64_t>& argv) {
    // HANDLE Handle, BOOLEAN Alertable, PLARGE_INTEGER Timeout
    (void)emu; (void)argv;
    // Always return success (signaled)
    return NT_SUCCESS;
}

uint64_t Ntdll::NtDelayExecution(void* emu, const std::string&, int,
                                  const std::vector<uint64_t>& argv) {
    // BOOLEAN Alertable, PLARGE_INTEGER DelayInterval
    uint8_t alertable = static_cast<uint8_t>(argv[0]);
    uint64_t delay_ptr = argv[1];
    (void)alertable;

    int64_t delay_interval = -1; // default: infinite wait (treated as 0)
    if (delay_ptr != 0) {
        auto raw = static_cast<MemoryManager*>(emu)->mem_read(delay_ptr, 8);
        if (raw.size() >= 8) {
            delay_interval = static_cast<int64_t>(read_le(raw, 0, 8));
        }
    }

    // DelayInterval is in 100ns units (negative = relative)
    if (delay_interval < 0) {
        // Relative timeout
        int64_t ms = (-delay_interval) / 10000; // convert 100ns to ms
        if (ms > 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(ms));
        }
    }

    return NT_SUCCESS;
}

// ═══════════════════════════════════════════════════════════════
// String / Utility
// ═══════════════════════════════════════════════════════════════

uint64_t Ntdll::RtlInitUnicodeString(void* emu, const std::string&, int,
                                      const std::vector<uint64_t>& argv) {
    // PUNICODE_STRING DestinationString, PWSTR SourceString
    uint64_t dest = argv[0];
    uint64_t src = argv[1];
    int psz = get_ptr_size(emu);

    if (dest == 0) return STATUS_INVALID_PARAMETER;

    if (src == 0) {
        // NULL source: set Length=0, MaximumLength=0, Buffer=NULL
        write_u16(emu, dest, 0);
        write_u16(emu, dest + 2, 0);
        write_ptr(emu, dest + 4, 0);
    } else {
        // Read the source string and set up the UNICODE_STRING
        auto* bemu = static_cast<BinaryEmulator*>(static_cast<MemoryManager*>(emu));
        std::string str = bemu->read_mem_string(src, 2, 0); // read until null terminator
        uint16_t len = static_cast<uint16_t>(str.size() * 2); // bytes in UTF-16
        uint16_t max_len = static_cast<uint16_t>(len + 2); // include null terminator

        write_u16(emu, dest, len);
        write_u16(emu, dest + 2, max_len);
        write_ptr(emu, dest + 4, src);
    }

    return NT_SUCCESS;
}

uint64_t Ntdll::RtlInitString(void* emu, const std::string&, int,
                               const std::vector<uint64_t>& argv) {
    // PANSI_STRING DestinationString, PCHAR SourceString
    uint64_t dest = argv[0];
    uint64_t src = argv[1];
    int psz = get_ptr_size(emu);

    if (dest == 0) return STATUS_INVALID_PARAMETER;

    if (src == 0) {
        write_u16(emu, dest, 0);
        write_u16(emu, dest + 2, 0);
        write_ptr(emu, dest + 4, 0);
    } else {
        auto* bemu = static_cast<BinaryEmulator*>(static_cast<MemoryManager*>(emu));
        std::string str = bemu->read_mem_string(src, 1, 0);
        uint16_t len = static_cast<uint16_t>(str.size());
        uint16_t max_len = static_cast<uint16_t>(len + 1);

        write_u16(emu, dest, len);
        write_u16(emu, dest + 2, max_len);
        write_ptr(emu, dest + 4, src);
    }

    return NT_SUCCESS;
}

uint64_t Ntdll::RtlAnsiStringToUnicodeString(void* emu, const std::string&, int,
                                              const std::vector<uint64_t>& argv) {
    // PUNICODE_STRING DestinationString, PANSI_STRING SourceString,
    // BOOLEAN AllocateDestinationString
    uint64_t dest = argv[0];
    uint64_t src = argv[1];
    uint8_t alloc_dest = static_cast<uint8_t>(argv[2]);

    if (dest == 0 || src == 0) return STATUS_INVALID_PARAMETER;

    std::string ansi_str = read_ansi_string_content(emu, src);

    auto* mm = static_cast<MemoryManager*>(emu);
    auto* bemu = static_cast<BinaryEmulator*>(mm);

    uint16_t unicode_byte_len = static_cast<uint16_t>(ansi_str.size() * 2);

    if (alloc_dest) {
        // Allocate buffer for the Unicode string
        size_t buf_size = unicode_byte_len + 2; // + null terminator
        uint64_t buf = 0;
        try {
            buf = mm->mem_map(buf_size, 0, 0x4, "unicode_string");
        } catch (...) {
            return STATUS_NO_MEMORY;
        }

        // Write the string
        bemu->write_mem_string(ansi_str, buf, 2);
        // Ensure null terminator
        std::vector<uint8_t> null_term = {0, 0};
        mm->mem_write(buf + unicode_byte_len, null_term);

        // Write UNICODE_STRING
        write_u16(emu, dest, unicode_byte_len);
        write_u16(emu, dest + 2, unicode_byte_len + 2);
        write_ptr(emu, dest + 4, buf);
    } else {
        // Just update the length fields, buffer stays as-is
        uint64_t existing_buf = read_ptr(emu, dest + 4);
        if (existing_buf != 0) {
            bemu->write_mem_string(ansi_str, existing_buf, 2);
        }
        write_u16(emu, dest, unicode_byte_len);
        write_u16(emu, dest + 2, unicode_byte_len + 2);
    }

    return NT_SUCCESS;
}

uint64_t Ntdll::RtlFreeUnicodeString(void* emu, const std::string&, int,
                                      const std::vector<uint64_t>& argv) {
    // PUNICODE_STRING UnicodeString
    uint64_t us = argv[0];
    if (us == 0) return NT_SUCCESS;

    auto* mm = static_cast<MemoryManager*>(emu);
    uint64_t buffer = read_ptr(emu, us + 4);
    if (buffer != 0) {
        try {
            mm->mem_free(buffer);
        } catch (...) {
            // Ignore errors
        }
    }

    // Zero out the structure
    std::vector<uint8_t> zero(4 + get_ptr_size(emu), 0);
    mm->mem_write(us, zero);

    return NT_SUCCESS;
}

uint64_t Ntdll::RtlNtStatusToDosError(void* emu, const std::string&, int,
                                       const std::vector<uint64_t>& argv) {
    // NTSTATUS Status
    (void)emu;
    uint32_t status = static_cast<uint32_t>(argv[0]);
    // Simple mapping for common status codes
    switch (status) {
        case NT_SUCCESS:              return 0;      // ERROR_SUCCESS
        case NT_INVALID_HANDLE:        return 6;     // ERROR_INVALID_HANDLE
        case NT_INVALID_PARAM:           return 87;    // ERROR_INVALID_PARAMETER
        case NT_ACCESS_VIOLATION:        return 998;   // ERROR_NOACCESS
        case NT_BUFFER_TOO_SMALL:        return 122;   // ERROR_INSUFFICIENT_BUFFER
        case NT_OBJECT_NAME_NOT_FOUND:   return 2;     // ERROR_FILE_NOT_FOUND
        case 0xC000007A:               return 127;   // ERROR_PROC_NOT_FOUND
        case 0xC00000BB:               return 50;    // ERROR_NOT_SUPPORTED
        default:                           return 0;
    }
}

uint64_t Ntdll::CsrGetProcessId(void* emu, const std::string&, int,
                                 const std::vector<uint64_t>&) {
    auto* wemu = static_cast<WindowsEmulator*>(static_cast<MemoryManager*>(emu));
    auto p = wemu->get_current_process();
    if (p) {
        return static_cast<uint64_t>(p->get_pid());
    }
    return 4; // Default PID
}

// ═══════════════════════════════════════════════════════════════
// Additional ntdll APIs (ported from Python reference)
// ═══════════════════════════════════════════════════════════════

uint64_t Ntdll::RtlGetLastWin32Error(void* emu, const std::string&, int,
                                      const std::vector<uint64_t>&) {
    // DWORD RtlGetLastWin32Error();
    auto* wemu = static_cast<Win32Emulator*>(static_cast<MemoryManager*>(emu));
    return static_cast<uint64_t>(wemu->get_last_error());
}

uint64_t Ntdll::RtlFlushSecureMemoryCache(void* emu, const std::string&, int,
                                           const std::vector<uint64_t>&) {
    // DWORD RtlFlushSecureMemoryCache(PVOID arg0, PVOID arg1);
    (void)emu;
    return 1; // TRUE
}

uint64_t Ntdll::RtlAddVectoredExceptionHandler(void* emu, const std::string&, int,
                                                const std::vector<uint64_t>& argv) {
    // PVOID AddVectoredExceptionHandler(ULONG First, PVECTORED_EXCEPTION_HANDLER Handler)
    uint32_t first = static_cast<uint32_t>(argv[0]);
    uint64_t handler = argv[1];

    auto* wemu = static_cast<Win32Emulator*>(static_cast<MemoryManager*>(emu));
    wemu->add_vectored_exception_handler(first != 0, handler);
    return handler;
}

uint64_t Ntdll::RtlRemoveVectoredExceptionHandler(void* emu, const std::string&, int,
                                                   const std::vector<uint64_t>& argv) {
    // ULONG RemoveVectoredExceptionHandler(PVOID Handle)
    uint64_t handler = argv[0];

    auto* wemu = static_cast<Win32Emulator*>(static_cast<MemoryManager*>(emu));
    wemu->remove_vectored_exception_handler(handler);
    return handler;
}

uint64_t Ntdll::NtYieldExecution(void* emu, const std::string&, int,
                                   const std::vector<uint64_t>&) {
    // NtYieldExecution();
    (void)emu;
    return 0; // STATUS_SUCCESS
}

uint64_t Ntdll::LdrLoadDll(void* emu, const std::string&, int,
                            const std::vector<uint64_t>& argv) {
    // NTSTATUS LdrLoadDll(PWSTR SearchPath, PULONG LoadFlags,
    //                      PUNICODE_STRING Name, PVOID *BaseAddress)
    uint64_t search_path_ptr = argv[0];
    uint64_t load_flags_ptr = argv[1];
    uint64_t name_ptr = argv[2];
    uint64_t base_addr_ptr = argv[3];
    (void)search_path_ptr;
    (void)load_flags_ptr;

    std::string dll_name;
    if (name_ptr != 0) {
        dll_name = read_unicode_string_content(emu, name_ptr);
    }

    auto* wemu = static_cast<WindowsEmulator*>(static_cast<MemoryManager*>(emu));

    // Normalize DLL name
    std::string norm_name;
    auto dot = dll_name.find_last_of('.');
    std::string base = (dot != std::string::npos) ? dll_name.substr(0, dot) : dll_name;
    for (auto& c : base) c = static_cast<char>(std::tolower(c));
    norm_name = base + ".dll";

    void* hmod = wemu->load_library(norm_name);
    if (!hmod) {
        // Try with the original name
        hmod = wemu->load_library(dll_name);
    }

    if (!hmod) {
        return 0xC0000135; // STATUS_DLL_NOT_FOUND
    }

    if (base_addr_ptr != 0) {
        // Write module base address through the pointer
        // The handle is the module's base address
        auto* mm = static_cast<MemoryManager*>(emu);
        int psz = get_ptr_size(emu);
        // Look up the module base from the module object
        uint64_t mod_base = reinterpret_cast<uint64_t>(hmod);
        // Try to get it from module list
        auto modules = wemu->get_peb_modules();
        for (auto mod : modules) {
            if (mod->base == (uint64_t)hmod) {
                // Use the module base
                break;
            }
        }
        std::vector<uint8_t> buf(psz, 0);
        write_le(buf, 0, mod_base, psz);
        mm->mem_write(base_addr_ptr, buf);
    }

    return 0; // STATUS_SUCCESS
}

uint64_t Ntdll::LdrGetProcedureAddress(void* emu, const std::string&, int,
                                        const std::vector<uint64_t>& argv) {
    // NTSTATUS LdrGetProcedureAddress(HMODULE ModuleHandle,
    //     PANSI_STRING FunctionName, WORD Ordinal, PVOID *FunctionAddress)
    uint64_t hmod = argv[0];
    uint64_t proc_name_ptr = argv[1];
    uint64_t ordinal = argv[2];
    uint64_t func_addr_ptr = argv[3];

    auto* wemu = static_cast<WindowsEmulator*>(static_cast<MemoryManager*>(emu));
    auto* mm = static_cast<MemoryManager*>(emu);

    std::string func_name;

    if (proc_name_ptr != 0) {
        // Read ANSI_STRING: Length(2), MaximumLength(2), Buffer(ptr at +4/8)
        func_name = read_ansi_string_content(emu, proc_name_ptr);
    } else if (ordinal != 0) {
        func_name = "ordinal_" + std::to_string(ordinal);
    }

    if (!func_name.empty()) {
        // Look through modules to find the function
        auto mods = wemu->get_peb_modules();
        for (auto mod : mods) {
            uint64_t mod_base = mod->base;
            if (mod_base == hmod) {
                // Found the module, try to get the function address
                // get_proc takes mod_name and func_name
                // We need to find the module name first
                auto* bemu = static_cast<BinaryEmulator*>(mm);
                std::string mod_name = bemu->get_address_tag(mod_base);
                uint64_t addr = reinterpret_cast<uint64_t>(wemu->get_proc(mod_name, func_name));
                if (addr != 0) {
                    if (func_addr_ptr != 0) {
                        int psz = get_ptr_size(emu);
                        std::vector<uint8_t> buf(psz, 0);
                        write_le(buf, 0, addr, psz);
                        mm->mem_write(func_addr_ptr, buf);
                    }
                    return 0; // STATUS_SUCCESS
                }
            }
        }
    }

    return 0xC000007A; // STATUS_PROCEDURE_NOT_FOUND
}

uint64_t Ntdll::LdrFindResource_U(void* emu, const std::string&, int,
                                   const std::vector<uint64_t>& argv) {
    // NTSTATUS LdrFindResource_U(PVOID DllHandle,
    //     PLDR_RESOURCE_INFO ResourceInfo, ULONG Level,
    //     PIMAGE_RESOURCE_DATA_ENTRY *ResourceDataEntry)
    (void)emu; (void)argv;
    // Stub — resources are not deeply emulated
    return STATUS_SUCCESS;
}

uint64_t Ntdll::LdrAccessResource(void* emu, const std::string&, int,
                                   const std::vector<uint64_t>& argv) {
    // NTSTATUS LdrAccessResource(PVOID BaseAddress,
    //     PIMAGE_RESOURCE_DATA_ENTRY ResourceDataEntry,
    //     PVOID *Resource, PULONG Size)
    uint64_t base_addr = argv[0];
    uint64_t res_entry = argv[1];
    uint64_t resource_ptr = argv[2];
    uint64_t size_ptr = argv[3];

    auto* mm = static_cast<MemoryManager*>(emu);

    if (res_entry == 0) return STATUS_INVALID_PARAMETER;

    // Read IMAGE_RESOURCE_DATA_ENTRY: OffsetToData(4), Size(4), CodePage(4), Reserved(4)
    auto raw_offset = mm->mem_read(res_entry, 4);
    auto raw_size = mm->mem_read(res_entry + 4, 4);
    if (raw_offset.size() < 4 || raw_size.size() < 4) return STATUS_UNSUCCESSFUL;

    uint32_t offset = static_cast<uint32_t>(read_le(raw_offset, 0, 4));
    uint32_t size = static_cast<uint32_t>(read_le(raw_size, 0, 4));

    if (size_ptr != 0) {
        write_u32(emu, size_ptr, size);
    }

    if (resource_ptr != 0) {
        write_ptr(emu, resource_ptr, base_addr + offset);
    }

    return STATUS_SUCCESS;
}

uint64_t Ntdll::RtlZeroMemory(void* emu, const std::string&, int,
                               const std::vector<uint64_t>& argv) {
    // void RtlZeroMemory(void* Destination, size_t Length)
    uint64_t dest = argv[0];
    size_t length = static_cast<size_t>(argv[1]);

    if (dest == 0 || length == 0) return 0;

    auto* mm = static_cast<MemoryManager*>(emu);
    std::vector<uint8_t> zeros(length, 0);
    mm->mem_write(dest, zeros);
    return 0;
}

uint64_t Ntdll::RtlMoveMemory(void* emu, const std::string&, int,
                               const std::vector<uint64_t>& argv) {
    // void RtlMoveMemory(void* pvDest, const void* pSrc, size_t Length)
    uint64_t dest = argv[0];
    uint64_t src = argv[1];
    size_t length = static_cast<size_t>(argv[2]);

    if (dest == 0 || src == 0 || length == 0) return 0;

    auto* mm = static_cast<MemoryManager*>(emu);
    auto data = mm->mem_read(src, length);
    if (!data.empty()) {
        mm->mem_write(dest, data);
    }
    return 0;
}

uint64_t Ntdll::RtlEncodePointer(void* emu, const std::string&, int,
                                  const std::vector<uint64_t>& argv) {
    // PVOID RtlEncodePointer(PVOID Pointer)
    (void)emu;
    return argv[0] + 1;
}

uint64_t Ntdll::RtlDecodePointer(void* emu, const std::string&, int,
                                  const std::vector<uint64_t>& argv) {
    // PVOID RtlDecodePointer(PVOID Pointer)
    (void)emu;
    return argv[0] - 1;
}

uint64_t Ntdll::RtlComputeCrc32(void* emu, const std::string&, int,
                                 const std::vector<uint64_t>& argv) {
    // DWORD RtlComputeCrc32(DWORD dwInitial, const BYTE* pData, INT iLen)
    uint32_t initial = static_cast<uint32_t>(argv[0]);
    uint64_t data_ptr = argv[1];
    int32_t len = static_cast<int32_t>(argv[2]);
    (void)initial;

    auto* mm = static_cast<MemoryManager*>(emu);

    if (data_ptr == 0 || len <= 0) return 0;

    auto raw = mm->mem_read(data_ptr, static_cast<size_t>(len));

    // Compute CRC32
    uint32_t crc = 0xFFFFFFFF;
    static const uint32_t crc32_table[256] = {
        0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA, 0x076DC419, 0x706AF48F,
        0xE963A535, 0x9E6495A3, 0x0EDB8832, 0x79DCB8A4, 0xE0D5E91E, 0x97D2D988,
        0x09B64C2B, 0x7EB17CBD, 0xE7B82D07, 0x90BF1D91, 0x1DB71064, 0x6AB020F2,
        0xF3B97148, 0x84BE41DE, 0x1ADAD47D, 0x6DDDE4EB, 0xF4D4B551, 0x83D385C7,
        0x136C9856, 0x646BA8C0, 0xFD62F97A, 0x8A65C9EC, 0x14015C4F, 0x63066CD9,
        0xFA0F3D63, 0x8D080DF5, 0x3B6E20C8, 0x4C69105E, 0xD56041E4, 0xA2677172,
        0x3C03E4D1, 0x4B04D447, 0xD20D85FD, 0xA50AB56B, 0x35B5A8FA, 0x42B2986C,
        0xDBBBC9D6, 0xACBCF940, 0x32D86CE3, 0x45DF5C75, 0xDCD60DCF, 0xABD13D59,
        0x26D930AC, 0x51DE003A, 0xC8D75180, 0xBFD06116, 0x21B4F4B5, 0x56B3C423,
        0xCFBA9599, 0xB8BDA50F, 0x2802B89E, 0x5F058808, 0xC60CD9B2, 0xB10BE924,
        0x2F6F7C87, 0x58684C11, 0xC1611DAB, 0xB6662D3D, 0x76DC4190, 0x01DB7106,
        0x98D220BC, 0xEFD5102A, 0x71B18589, 0x06B6B51F, 0x9FBFE4A5, 0xE8B8D433,
        0x7807C9A2, 0x0F00F934, 0x9609A88E, 0xE10E9818, 0x7F6A0DBB, 0x086D3D2D,
        0x91646C97, 0xE6635C01, 0x6B6B51F4, 0x1C6C6162, 0x856530D8, 0xF262004E,
        0x6C0695ED, 0x1B01A57B, 0x8208F4C1, 0xF50FC457, 0x65B0D9C6, 0x12B7E950,
        0x8BBEB8EA, 0xFCB9887C, 0x62DD1DDF, 0x15DA2D49, 0x8CD37CF3, 0xFBD44C65,
        0x4DB26158, 0x3AB551CE, 0xA3BC0074, 0xD4BB30E2, 0x4ADFA541, 0x3DD895D7,
        0xA4D1C46D, 0xD3D6F4FB, 0x4369E96A, 0x346ED9FC, 0xAD678846, 0xDA60B8D0,
        0x44042D73, 0x33031DE5, 0xAA0A4C5F, 0xDD0D7CC9, 0x5005713C, 0x270241AA,
        0xBE0B1010, 0xC90C2086, 0x5768B525, 0x206F85B3, 0xB966D409, 0xCE61E49F,
        0x5EDEF90E, 0x29D9C998, 0xB0D09822, 0xC7D7A8B4, 0x59B33D17, 0x2EB40D81,
        0xB7BD5C3B, 0xC0BA6CAD, 0xEDB88320, 0x9ABFB3B6, 0x03B6E20C, 0x74B1D29A,
        0xEAD54739, 0x9DD277AF, 0x04DB2615, 0x73DC1683, 0xE3630B12, 0x94643B84,
        0x0D6D6A3E, 0x7A6A5AA8, 0xE40ECF0B, 0x9309FF9D, 0x0A00AE27, 0x7D079EB1,
        0xF00F9344, 0x8708A3D2, 0x1E01F268, 0x6906C2FE, 0xF762575D, 0x806567CB,
        0x196C3671, 0x6E6B06E7, 0xFED41B76, 0x89D32BE0, 0x10DA7A5A, 0x67DD4ACC,
        0xF9B9DF6F, 0x8EBEEFF9, 0x17B7BE43, 0x60B08ED5, 0xD6D6A3E8, 0xA1D1937E,
        0x38D8C2C4, 0x4FDFF252, 0xD1BB67F1, 0xA6BC5767, 0x3FB506DD, 0x48B2364B,
        0xD80D2BDA, 0xAF0A1B4C, 0x36034AF6, 0x41047A60, 0xDF60EFC3, 0xA867DF55,
        0x316E8EEF, 0x4669BE79, 0xCB61B38C, 0xBC66831A, 0x256FD2A0, 0x5268E236,
        0xCC0C7795, 0xBB0B4703, 0x220216B9, 0x5505262F, 0xC5BA3BBE, 0xB2BD0B28,
        0x2BB45A92, 0x5CB36A04, 0xC2D7FFA7, 0xB5D0CF31, 0x2CD99E8B, 0x5BDEAE1D,
        0x9B64C2B0, 0xEC63F226, 0x756AA39C, 0x026D930A, 0x9C0906A9, 0xEB0E363F,
        0x72076785, 0x05005713, 0x95BF4A82, 0xE2B87A14, 0x7BB12BAE, 0x0CB61B38,
        0x92D28E9B, 0xE5D5BE0D, 0x7CDCEFB7, 0x0BDBDF21, 0x86D3D2D4, 0xF1D4E242,
        0x68DDB3F8, 0x1FDA836E, 0x81BE16CD, 0xF6B9265B, 0x6FB077E1, 0x18B74777,
        0x88085AE6, 0xFF0F6A70, 0x66063BCA, 0x11010B5C, 0x8F659EFF, 0xF862AE69,
        0x616BFFD3, 0x166CCF45, 0xA00AE278, 0xD70DD2EE, 0x4E048354, 0x3903B3C2,
        0xA7672661, 0xD06016F7, 0x4969474D, 0x3E6E77DB, 0xAED16A4A, 0xD9D65ADC,
        0x40DF0B66, 0x37D83BF0, 0xA9BCAE53, 0xDEBB9EC5, 0x47B2CF7F, 0x30B5FFE9,
        0xBDBDF21C, 0xCABAC28A, 0x53B39330, 0x24B4A3A6, 0xBAD03605, 0xCDD70693,
        0x54DE5729, 0x23D967BF, 0xB3667A2E, 0xC4614AB8, 0x5D681B02, 0x2A6F2B94,
        0xB40BBE37, 0xC30C8EA1, 0x5A05DF1B, 0x2D02EF8D
    };

    for (size_t i = 0; i < raw.size(); i++) {
        crc = (crc >> 8) ^ crc32_table[(crc ^ raw[i]) & 0xFF];
    }
    crc ^= 0xFFFFFFFF;

    return static_cast<uint64_t>(crc);
}

uint64_t Ntdll::RtlGetNtVersionNumbers(void* emu, const std::string&, int,
                                        const std::vector<uint64_t>& argv) {
    // void RtlGetNtVersionNumbers(DWORD *pNtMajorVersion,
    //     DWORD *pNtMinorVersion, DWORD *pNtBuildNumber)
    uint64_t p_major = argv[0];
    uint64_t p_minor = argv[1];
    uint64_t p_build = argv[2];

    if (p_major != 0) write_u32(emu, p_major, 10);     // Major = 10
    if (p_minor != 0) write_u32(emu, p_minor, 0);       // Minor = 0
    if (p_build != 0) write_u32(emu, p_build, 0xF0004A61); // Build = 19041 (Win10 20H1)

    return 0;
}

uint64_t Ntdll::RtlGetCurrentPeb(void* emu, const std::string&, int,
                                  const std::vector<uint64_t>&) {
    // PPEB RtlGetCurrentPeb();
    auto* wemu = static_cast<WindowsEmulator*>(static_cast<MemoryManager*>(emu));
    auto proc = wemu->get_current_process();
    if (proc) {
        // Get the PEB address from the process
        // The WindowsEmulator stores PEB address in the process object
        // Use the get_process_peb method
        void* peb = wemu->get_process_peb(proc.get());
        return reinterpret_cast<uint64_t>(peb);
    }
    return 0;
}

uint64_t Ntdll::RtlGetVersion(void* emu, const std::string&, int,
                               const std::vector<uint64_t>& argv) {
    // NTSTATUS RtlGetVersion(PRTL_OSVERSIONINFOW lpVersionInformation);
    uint64_t info_ptr = argv[0];

    if (info_ptr == 0) return STATUS_INVALID_PARAMETER;

    // RTL_OSVERSIONINFOW:
    // dwOSVersionInfoSize(4), dwMajorVersion(4), dwMinorVersion(4),
    // dwBuildNumber(4), dwPlatformId(4), szCSDVersion(260 bytes)
    write_u32(emu, info_ptr, 276);         // dwOSVersionInfoSize
    write_u32(emu, info_ptr + 4, 10);      // dwMajorVersion = 10
    write_u32(emu, info_ptr + 8, 0);       // dwMinorVersion = 0
    write_u32(emu, info_ptr + 12, 19041);  // dwBuildNumber = 19041
    write_u32(emu, info_ptr + 16, 2);      // dwPlatformId = VER_PLATFORM_WIN32_NT

    // szCSDVersion: zero-filled
    std::vector<uint8_t> zero(260, 0);
    auto* mm = static_cast<MemoryManager*>(emu);
    mm->mem_write(info_ptr + 20, zero);

    return 0; // STATUS_SUCCESS
}

// ═══════════════════════════════════════════════════════════════
// Volume / Object
// ═══════════════════════════════════════════════════════════════

uint64_t Ntdll::NtQueryVolumeInformationFile(void* emu, const std::string&, int,
                                              const std::vector<uint64_t>& argv) {
    // HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock,
    // PVOID FsInformation, ULONG Length,
    // FS_INFORMATION_CLASS FsInformationClass
    uint64_t io_status_ptr = argv[1];
    (void)argv[0]; // FileHandle
    (void)argv[2]; // FsInformation
    (void)argv[3]; // Length
    (void)argv[4]; // FsInformationClass

    if (io_status_ptr != 0) {
        write_u32(emu, io_status_ptr, NT_SUCCESS);
        write_ptr(emu, io_status_ptr + get_ptr_size(emu), 0);
    }

    return NT_SUCCESS;
}

uint64_t Ntdll::NtQueryObject(void* emu, const std::string&, int,
                               const std::vector<uint64_t>& argv) {
    // HANDLE Handle, OBJECT_INFORMATION_CLASS ObjectInformationClass,
    // PVOID ObjectInformation, ULONG ObjectInformationLength,
    // PULONG ReturnLength
    uint64_t obj_handle = argv[0];
    uint32_t info_class = static_cast<uint32_t>(argv[1]);
    uint64_t info_ptr = argv[2];
    uint32_t info_len = static_cast<uint32_t>(argv[3]);
    uint64_t ret_len_ptr = argv[4];

    auto* wemu = static_cast<WindowsEmulator*>(static_cast<MemoryManager*>(emu));

    // ObjectBasicInformation (0): returns OBJECT_BASIC_INFORMATION
    // ObjectNameInformation (1): returns OBJECT_NAME_INFORMATION (UNICODE_STRING)
    // ObjectTypeInformation (2): returns OBJECT_TYPE_INFORMATION

    void* obj = wemu->get_object_from_handle(static_cast<int>(obj_handle));
    if (!obj) {
        if (ret_len_ptr != 0) write_u32(emu, ret_len_ptr, 0);
        return STATUS_INVALID_HANDLE;
    }

    if (info_class == 1 && info_ptr != 0 && info_len >= 4 + get_ptr_size(emu)) {
        // ObjectNameInformation: return a UNICODE_STRING with an empty name
        // (we don't track object names in the generic object manager)
        int psz = get_ptr_size(emu);
        uint64_t buf_addr = info_ptr + 4 + psz;
        write_u16(emu, info_ptr, 0); // Length
        write_u16(emu, info_ptr + 2, 2); // MaximumLength (null terminator)
        write_ptr(emu, info_ptr + 4, buf_addr);
        // Write null terminator at buffer
        std::vector<uint8_t> null_term = {0, 0};
        static_cast<MemoryManager*>(emu)->mem_write(buf_addr, null_term);
        if (ret_len_ptr != 0) write_u32(emu, ret_len_ptr, 4 + psz + 2);
        return STATUS_SUCCESS;
    }

    // For all other classes, just return success with minimal data
    if (ret_len_ptr != 0) {
        write_u32(emu, ret_len_ptr, info_len);
    }
    return STATUS_SUCCESS;
}

uint64_t Ntdll::NtDuplicateObject(void* emu, const std::string&, int,
                                   const std::vector<uint64_t>& argv) {
    // HANDLE SourceProcessHandle, HANDLE SourceHandle,
    // HANDLE TargetProcessHandle, PHANDLE TargetHandle,
    // ACCESS_MASK DesiredAccess, ULONG HandleAttributes,
    // ULONG Options
    uint64_t src_handle = argv[1];
    uint64_t target_handle_ptr = argv[3];
    (void)argv[0]; // SourceProcessHandle
    (void)argv[2]; // TargetProcessHandle
    (void)argv[4]; // DesiredAccess
    (void)argv[5]; // HandleAttributes
    (void)argv[6]; // Options

    if (target_handle_ptr != 0) {
        write_ptr(emu, target_handle_ptr, src_handle);
    }

    return NT_SUCCESS;
}

// ═══════════════════════════════════════════════════════════════
// Fallback stub
// ═══════════════════════════════════════════════════════════════

uint64_t Ntdll::stub_api(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    (void)e; (void)a; return NT_SUCCESS;
}

} // namespace api
} // namespace speakeasy
