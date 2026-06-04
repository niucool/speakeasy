// ntoskrnl.cpp  Windows NT Kernel handler (implemented, ~154 APIs)
#include "ntoskrnl.h"
#include "../../../helper.h"

#include <cstdint>
#include <cstring>
#include <vector>
#include <string>
#include <algorithm>
#include <cctype>

#include "memmgr.h"
#include "struct.h"
#include "winenv/arch.h"
#include "windows/winemu.h"

// Undefine Windows SDK macros that collide with our function names
#ifdef RtlMoveMemory
#undef RtlMoveMemory
#endif
#ifdef RtlCopyMemory
#undef RtlCopyMemory
#endif
#ifdef RtlFillMemory
#undef RtlFillMemory
#endif
#ifdef RtlZeroMemory
#undef RtlZeroMemory
#endif
#ifdef RtlEqualMemory
#undef RtlEqualMemory
#endif
#ifdef memmove
#undef memmove
#endif
#ifdef memcpy
#undef memcpy
#endif
#ifdef memset
#undef memset
#endif
#ifdef strchr
#undef strchr
#endif
#ifdef strrchr
#undef strrchr
#endif

using namespace speakeasy;

namespace speakeasy { namespace api { namespace kernelmode {

//  Typed cast helpers 
static inline WindowsEmulator* we(void* e) { return static_cast<WindowsEmulator*>(e); }
static inline BinaryEmulator* be(void* e) { return static_cast<BinaryEmulator*>(e); }
static inline MemoryManager* mm(void* e) { return static_cast<MemoryManager*>(e); }
static inline int ptr_sz(void* e) { return we(e)->get_ptr_size(); }

//  NTSTATUS constants (avoid Windows SDK macro conflicts) 
static constexpr uint64_t KERN_STATUS_SUCCESS                  = 0x00000000;
static constexpr uint64_t KERN_STATUS_INFO_LENGTH_MISMATCH    = 0xC0000004;
static constexpr uint64_t KERN_STATUS_INVALID_PARAMETER       = 0xC000000D;
static constexpr uint64_t KERN_STATUS_OBJECT_NAME_NOT_FOUND   = 0xC0000034;
static constexpr uint64_t KERN_STATUS_UNSUCCESSFUL            = 0xC0000001;
static constexpr uint64_t KERN_STATUS_NOT_FOUND               = 0xC0000135;

// SYSTEM_INFORMATION_CLASS values
static constexpr int KERN_SYSTEM_MODULE_INFORMATION           = 0x0B;
static constexpr int KERN_SYSTEM_TIMEOFDAY_INFORMATION        = 0x03;
static constexpr int KERN_SYSTEM_KERNEL_DEBUGGER_INFORMATION  = 0x23;
static constexpr int KERN_SYSTEM_CODEINTEGRITY_INFORMATION    = 0x5B;
static constexpr int KERN_SYSTEM_PROCESS_INFORMATION          = 0x05;

Ntoskrnl::Ntoskrnl(void* emu) : ApiHandler(emu) {
    INIT_API_TABLE(Ntoskrnl)
    // Object/Reference
    REG(Ntoskrnl, ObfDereferenceObject, 1)        REG(Ntoskrnl, ObfReferenceObject, 1)
    REG(Ntoskrnl, ZwClose, 1)                      REG(Ntoskrnl, ObOpenObjectByPointer, 7)
    REG(Ntoskrnl, ObReferenceObjectByName, 8)      REG(Ntoskrnl, ObReferenceObjectByHandle, 6)
    REG(Ntoskrnl, ObMakeTemporaryObject, 1)        REG(Ntoskrnl, ObGetFilterVersion, 0)
    REG(Ntoskrnl, ObRegisterCallbacks, 2)          REG(Ntoskrnl, ObSetSecurityObjectByPointer, 3)
    // Debug/Print
    REG(Ntoskrnl, DbgPrint, 0)                     REG(Ntoskrnl, DbgPrintEx, 0)
    // String/Format
    REG(Ntoskrnl, _vsnprintf, 4)                   REG(Ntoskrnl, vsprintf_s, 4)
    REG(Ntoskrnl, _snwprintf, 0)                   REG(Ntoskrnl, sprintf, 0)
    REG(Ntoskrnl, _snprintf, 0)
    // Rtl string
    REG(Ntoskrnl, RtlAnsiStringToUnicodeString, 3) REG(Ntoskrnl, RtlInitAnsiString, 2)
    REG(Ntoskrnl, RtlInitUnicodeString, 2)         REG(Ntoskrnl, RtlFreeUnicodeString, 1)
    REG(Ntoskrnl, RtlCopyUnicodeString, 2)         REG(Ntoskrnl, RtlEqualUnicodeString, 3)
    REG(Ntoskrnl, RtlGetVersion, 1)                REG(Ntoskrnl, RtlCompareMemory, 3)
    REG(Ntoskrnl, RtlMoveMemory, 3)
    // Memory/Pool
    REG(Ntoskrnl, ExAllocatePoolWithTag, 3)        REG(Ntoskrnl, ExFreePoolWithTag, 2)
    REG(Ntoskrnl, ExAllocatePool, 2)               REG(Ntoskrnl, ExFreePool, 1)
    REG(Ntoskrnl, FsRtlAllocatePool, 2)            REG(Ntoskrnl, RtlAllocateHeap, 3)
    REG(Ntoskrnl, RtlFreeHeap, 3)                  REG(Ntoskrnl, MmAllocateContiguousMemory, 2)
    REG(Ntoskrnl, MmFreeContiguousMemory, 1)       REG(Ntoskrnl, MmIsAddressValid, 1)
    REG(Ntoskrnl, MmMapLockedPagesSpecifyCache, 6) REG(Ntoskrnl, MmUnlockPages, 1)
    REG(Ntoskrnl, MmGetSystemRoutineAddress, 1)    REG(Ntoskrnl, MmIsDriverVerifying, 1)
    // memcpy/memset/etc
    REG(Ntoskrnl, memmove, 3)                      REG(Ntoskrnl, memcpy, 3)
    REG(Ntoskrnl, memset, 3)
    // Wide char string
    REG(Ntoskrnl, wcscpy, 2)                       REG(Ntoskrnl, wcsncpy, 3)
    REG(Ntoskrnl, wcslen, 1)                       REG(Ntoskrnl, wcschr, 2)
    REG(Ntoskrnl, wcscat, 2)                       REG(Ntoskrnl, wcsnlen, 2)
    REG(Ntoskrnl, strrchr, 2)                      REG(Ntoskrnl, strchr, 2)
    REG(Ntoskrnl, _wcsnicmp, 3)                    REG(Ntoskrnl, _stricmp, 2)
    REG(Ntoskrnl, _wcsicmp, 2)                     REG(Ntoskrnl, mbstowcs, 3)
    // I/O
    REG(Ntoskrnl, IoDeleteDriver, 1)               REG(Ntoskrnl, IoCreateDevice, 7)
    REG(Ntoskrnl, IoCreateDeviceSecure, 9)         REG(Ntoskrnl, IoCreateSymbolicLink, 2)
    REG(Ntoskrnl, IofCompleteRequest, 2)           REG(Ntoskrnl, IoDeleteSymbolicLink, 1)
    REG(Ntoskrnl, IoDeleteDevice, 1)               REG(Ntoskrnl, IoCreateSynchronizationEvent, 2)
    REG(Ntoskrnl, IoAllocateIrp, 2)                REG(Ntoskrnl, IoFreeIrp, 1)
    REG(Ntoskrnl, IoReuseIrp, 2)                   REG(Ntoskrnl, IoAllocateMdl, 5)
    REG(Ntoskrnl, IoFreeMdl, 1)                    REG(Ntoskrnl, IofCallDriver, 2)
    REG(Ntoskrnl, IoSetCompletionRoutineEx, 7)     REG(Ntoskrnl, IoGetDeviceObjectPointer, 4)
    REG(Ntoskrnl, IoGetCurrentProcess, 0)          REG(Ntoskrnl, IoWMIRegistrationControl, 2)
    REG(Ntoskrnl, IoRegisterBootDriverReinitialization, 3)
    REG(Ntoskrnl, IoRegisterShutdownNotification, 1)
    REG(Ntoskrnl, IoUnregisterShutdownNotification, 1)
    // Ke (Kernel)
    REG(Ntoskrnl, KeInitializeMutex, 2)            REG(Ntoskrnl, KeSetEvent, 3)
    REG(Ntoskrnl, KeInitializeEvent, 3)            REG(Ntoskrnl, KeResetEvent, 1)
    REG(Ntoskrnl, KeClearEvent, 1)                 REG(Ntoskrnl, KeInitializeTimer, 1)
    REG(Ntoskrnl, KeSetTimer, 3)                   REG(Ntoskrnl, KeCancelTimer, 1)
    REG(Ntoskrnl, KeDelayExecutionThread, 3)       REG(Ntoskrnl, KeWaitForSingleObject, 5)
    REG(Ntoskrnl, KeInitializeApc, 8)              REG(Ntoskrnl, KeInsertQueueApc, 4)
    REG(Ntoskrnl, KeInitializeDpc, 3)              REG(Ntoskrnl, KeStackAttachProcess, 2)
    REG(Ntoskrnl, KeUnstackDetachProcess, 1)       REG(Ntoskrnl, KeQuerySystemTime, 1)
    REG(Ntoskrnl, KeAcquireSpinLockRaiseToDpc, 1)
    REG(Ntoskrnl, KeEnterCriticalRegion, 0)        REG(Ntoskrnl, KeLeaveCriticalRegion, 0)
    // Ps (Process)
    REG(Ntoskrnl, PsCreateSystemThread, 7)         REG(Ntoskrnl, PsLookupProcessByProcessId, 2)
    REG(Ntoskrnl, PsLookupThreadByThreadId, 2)     REG(Ntoskrnl, PsGetProcessPeb, 1)
    REG(Ntoskrnl, PsTerminateSystemThread, 1)      REG(Ntoskrnl, PsGetVersion, 4)
    REG(Ntoskrnl, PsSetCreateProcessNotifyRoutineEx, 2)
    REG(Ntoskrnl, PsSetLoadImageNotifyRoutine, 1)
    REG(Ntoskrnl, PsRemoveLoadImageNotifyRoutine, 1)
    REG(Ntoskrnl, PsSetCreateThreadNotifyRoutine, 1)
    REG(Ntoskrnl, PsRemoveCreateThreadNotifyRoutine, 1)
    // Zw/Nt system calls
    REG(Ntoskrnl, ZwQuerySystemInformation, 4)     REG(Ntoskrnl, ZwProtectVirtualMemory, 5)
    REG(Ntoskrnl, ZwWriteVirtualMemory, 5)         REG(Ntoskrnl, ZwAllocateVirtualMemory, 6)
    REG(Ntoskrnl, ZwOpenEvent, 3)                  REG(Ntoskrnl, ZwCreateEvent, 5)
    REG(Ntoskrnl, ZwDeviceIoControlFile, 10)       REG(Ntoskrnl, ZwDeleteKey, 1)
    REG(Ntoskrnl, ZwQueryInformationProcess, 5)    REG(Ntoskrnl, ZwOpenKey, 3)
    REG(Ntoskrnl, ZwQueryValueKey, 6)              REG(Ntoskrnl, ZwCreateFile, 11)
    REG(Ntoskrnl, ZwOpenFile, 6)                   REG(Ntoskrnl, ZwQueryInformationFile, 5)
    REG(Ntoskrnl, ZwWriteFile, 9)                  REG(Ntoskrnl, ZwReadFile, 9)
    REG(Ntoskrnl, ZwCreateSection, 7)              REG(Ntoskrnl, ZwUnmapViewOfSection, 2)
    REG(Ntoskrnl, ZwMapViewOfSection, 10)          REG(Ntoskrnl, ZwGetContextThread, 2)
    REG(Ntoskrnl, ZwSetContextThread, 2)           REG(Ntoskrnl, NtSetInformationThread, 4)
    // Mm (Memory Management)
    REG(Ntoskrnl, MmProbeAndLockPages, 3)
    // Ex (Executive)
    REG(Ntoskrnl, ExInitializeResourceLite, 1)     REG(Ntoskrnl, ExAcquireResourceExclusiveLite, 2)
    REG(Ntoskrnl, ExAcquireResourceSharedLite, 2)  REG(Ntoskrnl, ExReleaseResourceLite, 1)
    REG(Ntoskrnl, ExAcquireFastMutex, 1)           REG(Ntoskrnl, ExReleaseFastMutex, 1)
    REG(Ntoskrnl, ExQueueWorkItem, 2)              REG(Ntoskrnl, ExSystemTimeToLocalTime, 2)
    // Security
    REG(Ntoskrnl, RtlLengthRequiredSid, 1)         REG(Ntoskrnl, RtlInitializeSid, 3)
    REG(Ntoskrnl, RtlSubAuthoritySid, 2)           REG(Ntoskrnl, RtlCreateAcl, 3)
    REG(Ntoskrnl, RtlSetDaclSecurityDescriptor, 4) REG(Ntoskrnl, RtlCreateSecurityDescriptor, 2)
    REG(Ntoskrnl, RtlAddAccessAllowedAce, 4)
    // Registry
    REG(Ntoskrnl, RtlQueryRegistryValuesEx, 5)
    // Timer/Power
    REG(Ntoskrnl, PoDeletePowerRequest, 1)
    // Kd
    REG(Ntoskrnl, KdDisableDebugger, 0)            REG(Ntoskrnl, KdChangeOption, 0)
    // Cm (Configuration Manager)
    REG(Ntoskrnl, CmRegisterCallbackEx, 6)         REG(Ntoskrnl, CmRegisterCallback, 3)
    REG(Ntoskrnl, CmUnRegisterCallback, 1)
    // Etw
    REG(Ntoskrnl, EtwRegister, 4)
    // Image
    REG(Ntoskrnl, RtlImageDirectoryEntryToData, 4)
    // Compression
    REG(Ntoskrnl, RtlGetCompressionWorkSpaceSize, 3) REG(Ntoskrnl, RtlDecompressBuffer, 6)
    // Misc
    REG(Ntoskrnl, RtlTimeToTimeFields, 2)
    REG(Ntoskrnl, _allshl, 2)
    END_API_TABLE
}

//  Helper: read a STRING (ANSI_STRING) from memory 
static std::string read_ansi_string_from_mem(void* e, uint64_t addr) {
    if (!addr) return "";
    int psz = ptr_sz(e);
    // STRING: { USHORT Length; USHORT MaximumLength; PCHAR Buffer; }
    size_t hdr = 4 + static_cast<size_t>(psz);
    auto raw = mm(e)->mem_read(addr, hdr);
    uint16_t len = static_cast<uint16_t>(read_le(raw, 0, 2));
    uint64_t buf = (psz == 8) ? static_cast<uint64_t>(read_le(raw, 8, 8))
                               : static_cast<uint64_t>(read_le(raw, 4, 4));
    if (!buf || len == 0) return "";
    auto data = mm(e)->mem_read(buf, static_cast<size_t>(len));
    return std::string(data.begin(), data.end());
}

//  Helper: read a UNICODE_STRING from memory 
static std::u16string read_unicode_string_from_mem(void* e, uint64_t addr) {
    if (!addr) return {};
    int psz = ptr_sz(e);
    // UNICODE_STRING: { USHORT Length; USHORT MaximumLength; PWSTR Buffer; }
    size_t hdr = 4 + static_cast<size_t>(psz);
    auto raw = mm(e)->mem_read(addr, hdr);
    uint16_t len = static_cast<uint16_t>(read_le(raw, 0, 2));
    uint64_t buf = (psz == 8) ? static_cast<uint64_t>(read_le(raw, 8, 8))
                               : static_cast<uint64_t>(read_le(raw, 4, 4));
    if (!buf || len == 0) return {};
    auto data = mm(e)->mem_read(buf, static_cast<size_t>(len));
    std::u16string result;
    for (size_t i = 0; i + 1 < data.size(); i += 2) {
        char16_t c = static_cast<char16_t>(read_le(data, i, 2));
        result.push_back(c);
        if (c == 0) break;
    }
    return result;
}

//  Helper: write UNICODE_STRING fields 
static void write_unicode_string_fields(void* e, uint64_t addr, uint16_t length, uint16_t maxlen, uint64_t buffer) {
    int psz = ptr_sz(e);
    auto data = std::vector<uint8_t>(4 + static_cast<size_t>(psz));
    write_le(data, 0, static_cast<uint64_t>(length), 2);
    write_le(data, 2, static_cast<uint64_t>(maxlen), 2);
    write_le(data, 4, buffer, psz);
    mm(e)->mem_write(addr, data);
}

//  Helper: read a wide string from a raw pointer 
static std::u16string read_wide_string_ptr(void* e, uint64_t addr, int max = 0) {
    if (!addr) return {};
    std::u16string result;
    for (int i = 0; max <= 0 || i < max; i++) {
        auto raw = mm(e)->mem_read(addr + static_cast<uint64_t>(i) * 2, 2);
        char16_t c = static_cast<char16_t>(read_le(raw, 0, 2));
        result.push_back(c);
        if (c == 0) break;
    }
    return result;
}

//  Helper: read an ANSI string from a raw pointer 
static std::string read_ansi_string_ptr(void* e, uint64_t addr, int max = 0) {
    if (!addr) return "";
    std::string result;
    for (int i = 0; max <= 0 || i < max; i++) {
        auto raw = mm(e)->mem_read(addr + static_cast<uint64_t>(i), 1);
        char c = static_cast<char>(raw[0]);
        result.push_back(c);
        if (c == 0) break;
    }
    return result;
}

// 
// IMPLEMENTATIONS
// 

//  Object/Reference 

uint64_t Ntoskrnl::ObfDereferenceObject(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // void ObfDereferenceObject(a);
    (void)e; (void)a;
    return 0;
}

uint64_t Ntoskrnl::ObfReferenceObject(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a;
    return 0;
}

uint64_t Ntoskrnl::ZwClose(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // __kernel_entry NTSYSCALLAPI NTSTATUS ZwClose(HANDLE Handle);
    (void)e; (void)a;
    return KERN_STATUS_SUCCESS;
}

uint64_t Ntoskrnl::ObOpenObjectByPointer(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a;
    return KERN_STATUS_SUCCESS;
}

uint64_t Ntoskrnl::ObReferenceObjectByName(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a;
    return KERN_STATUS_SUCCESS;
}

uint64_t Ntoskrnl::ObReferenceObjectByHandle(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a;
    return KERN_STATUS_SUCCESS;
}

uint64_t Ntoskrnl::ObMakeTemporaryObject(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a;
    return 0;
}

uint64_t Ntoskrnl::ObGetFilterVersion(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a;
    return 0;
}

uint64_t Ntoskrnl::ObRegisterCallbacks(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a;
    return KERN_STATUS_SUCCESS;
}

uint64_t Ntoskrnl::ObSetSecurityObjectByPointer(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a;
    return KERN_STATUS_SUCCESS;
}

//  Debug/Print 

uint64_t Ntoskrnl::DbgPrint(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // ULONG DbgPrint(PCSTR Format, ...);
    uint64_t fmt = a[0];
    std::string msg = read_ansi_string_ptr(e, fmt);
    // Just log it
    (void)msg;
    return static_cast<uint64_t>(msg.length());
}

uint64_t Ntoskrnl::DbgPrintEx(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // ULONG DbgPrintEx(ULONG ComponentId, ULONG Level, PCSTR Format, ...);
    uint64_t fmt = (ptr_sz(e) == 8) ? a[2] : a[2];
    (void)fmt;
    std::string msg = read_ansi_string_ptr(e, fmt);
    (void)msg;
    return static_cast<uint64_t>(msg.length());
}

//  String/Format 

uint64_t Ntoskrnl::_vsnprintf(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // int _vsnprintf(char *buffer, size_t count, const char *format, va_list argptr)
    uint64_t buffer = a[0];
    uint64_t count = a[1];
    uint64_t format = a[2];
    (void)a[3]; // argptr - skip for now
    
    std::string fmt = read_ansi_string_ptr(e, format);
    
    if (!buffer || count == 0) return 0;
    
    size_t n = (fmt.length() < count - 1) ? fmt.length() : (static_cast<size_t>(count) - 1);
    auto data = std::vector<uint8_t>(fmt.begin(), fmt.begin() + static_cast<ptrdiff_t>(n));
    data.push_back(0);
    mm(e)->mem_write(buffer, data);
    
    return static_cast<uint64_t>(n);
}

uint64_t Ntoskrnl::vsprintf_s(void* e, const std::vector<uint64_t>& a, void* ctx) {
    return _vsnprintf(e, a, ctx);
}

uint64_t Ntoskrnl::sprintf(void* e, const std::vector<uint64_t>& a, void* ctx) {
    uint64_t buf = a[0];
    uint64_t format = a[1];
    
    std::string fmt = read_ansi_string_ptr(e, format);
    auto data = std::vector<uint8_t>(fmt.begin(), fmt.end());
    data.push_back(0);
    if (buf) mm(e)->mem_write(buf, data);
    return static_cast<uint64_t>(fmt.length());
}

uint64_t Ntoskrnl::_snprintf(void* e, const std::vector<uint64_t>& a, void* ctx) {
    return _vsnprintf(e, a, ctx);
}

uint64_t Ntoskrnl::_snwprintf(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a;
    return 0;
}

//  Rtl string 

uint64_t Ntoskrnl::RtlInitAnsiString(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // VOID RtlInitAnsiString(PANSI_STRING DestinationString, PCSZ SourceString)
    uint64_t dest = a[0];
    uint64_t src = a[1];
    
    if (!dest) return 0;
    
    int psz = ptr_sz(e);
    std::string str = read_ansi_string_ptr(e, src);
    uint16_t len = static_cast<uint16_t>(str.length());
    
    // Write STRING: { USHORT Length; USHORT MaximumLength; PCHAR Buffer; }
    auto data = std::vector<uint8_t>(4 + static_cast<size_t>(psz));
    write_le(data, 0, static_cast<uint64_t>(len), 2);
    write_le(data, 2, static_cast<uint64_t>(len), 2);
    write_le(data, 4, src, psz);
    mm(e)->mem_write(dest, data);
    
    return 0;
}

uint64_t Ntoskrnl::RtlInitUnicodeString(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // VOID RtlInitUnicodeString(PUNICODE_STRING DestinationString, PCWSTR SourceString)
    uint64_t dest = a[0];
    uint64_t src = a[1];
    
    if (!dest) return 0;
    
    int psz = ptr_sz(e);
    
    if (src) {
        auto ustr = read_wide_string_ptr(e, src);
        uint16_t len = static_cast<uint16_t>(ustr.length() * 2); // bytes
        write_unicode_string_fields(e, dest, len, len, src);
    } else {
        write_unicode_string_fields(e, dest, 0, 0, 0);
    }
    
    return 0;
}

uint64_t Ntoskrnl::RtlFreeUnicodeString(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // VOID RtlFreeUnicodeString(PUNICODE_STRING UnicodeString)
    uint64_t us = a[0];
    if (!us) return 0;
    
    int psz = ptr_sz(e);
    auto raw = mm(e)->mem_read(us, 4 + static_cast<size_t>(psz));
    uint64_t buf = (psz == 8) ? static_cast<uint64_t>(read_le(raw, 8, 8))
                               : static_cast<uint64_t>(read_le(raw, 4, 4));
    if (buf) mm(e)->mem_free(buf);
    
    return 0;
}

uint64_t Ntoskrnl::RtlAnsiStringToUnicodeString(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // NTSTATUS RtlAnsiStringToUnicodeString(DestinationString, SourceString, AllocateDestinationString)
    uint64_t dest = a[0];
    uint64_t src = a[1];
    uint64_t do_alloc = a[2];
    
    if (!dest || !src) return KERN_STATUS_UNSUCCESSFUL;
    
    std::string ansi = read_ansi_string_from_mem(e, src);
    if (ansi.empty()) return KERN_STATUS_SUCCESS;
    
    int psz = ptr_sz(e);
    uint16_t size = static_cast<uint16_t>(ansi.length() * 2); // UTF-16 size
    
    if (do_alloc) {
        uint64_t buf = mm(e)->mem_map(static_cast<size_t>(size), 0, common::PERM_MEM_RWX,
                                      "api.struct.STRING." + ansi);
        auto wdata = std::vector<uint8_t>(static_cast<size_t>(size));
        for (size_t i = 0; i < ansi.length(); i++) {
            write_le(wdata, i * 2, static_cast<uint64_t>(static_cast<unsigned char>(ansi[i])), 2);
        }
        mm(e)->mem_write(buf, wdata);
        write_unicode_string_fields(e, dest, size, size, buf);
    } else {
        // Check if output buffer is large enough
        auto raw = mm(e)->mem_read(dest, 4);
        uint16_t maxlen = static_cast<uint16_t>(read_le(raw, 2, 2));
        if (maxlen < size) {
            return KERN_STATUS_UNSUCCESSFUL;
        }
        write_unicode_string_fields(e, dest, size, maxlen, 0);
    }
    
    return KERN_STATUS_SUCCESS;
}

uint64_t Ntoskrnl::RtlCopyUnicodeString(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // VOID RtlCopyUnicodeString(PUNICODE_STRING DestinationString, PUNICODE_STRING SourceString)
    uint64_t dst = a[0];
    uint64_t src = a[1];
    
    if (!src || !dst) return 0;
    
    auto src_str = read_unicode_string_from_mem(e, src);
    int psz = ptr_sz(e);
    
    auto dst_raw = mm(e)->mem_read(dst, 4);
    uint16_t dst_maxlen = static_cast<uint16_t>(read_le(dst_raw, 2, 2));
    
    uint16_t copy_len = static_cast<uint16_t>(src_str.length() * 2);
    if (copy_len > dst_maxlen) copy_len = dst_maxlen;
    
    // Read src buffer and copy
    auto raw_src = mm(e)->mem_read(src, 4 + static_cast<size_t>(psz));
    uint64_t src_buf = (psz == 8) ? static_cast<uint64_t>(read_le(raw_src, 8, 8))
                                   : static_cast<uint64_t>(read_le(raw_src, 4, 4));
    
    if (src_buf && copy_len > 0) {
        auto data = mm(e)->mem_read(src_buf, static_cast<size_t>(copy_len));
        auto dst_raw2 = mm(e)->mem_read(dst, 4 + static_cast<size_t>(psz));
        uint64_t dst_buf = (psz == 8) ? static_cast<uint64_t>(read_le(dst_raw2, 8, 8))
                                       : static_cast<uint64_t>(read_le(dst_raw2, 4, 4));
        if (dst_buf) {
            mm(e)->mem_write(dst_buf, data);
        }
    }
    
    // Update length
    write_le(dst_raw, 0, static_cast<uint64_t>(copy_len), 2);
    mm(e)->mem_write(dst, dst_raw);
    
    return 0;
}

uint64_t Ntoskrnl::RtlEqualUnicodeString(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // BOOLEAN RtlEqualUnicodeString(String1, String2, CaseInSensitive)
    uint64_t s1 = a[0];
    uint64_t s2 = a[1];
    uint64_t case_insens = a[2];
    
    auto u1 = read_unicode_string_from_mem(e, s1);
    auto u2 = read_unicode_string_from_mem(e, s2);
    
    if (case_insens) {
        // Case insensitive compare
        std::u16string l1, l2;
        for (auto c : u1) l1.push_back(static_cast<char16_t>(std::tolower(static_cast<int>(c))));
        for (auto c : u2) l2.push_back(static_cast<char16_t>(std::tolower(static_cast<int>(c))));
        return (l1 == l2) ? 1 : 0;
    }
    return (u1 == u2) ? 1 : 0;
}

uint64_t Ntoskrnl::RtlGetVersion(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // NTSTATUS RtlGetVersion(PRTL_OSVERSIONINFOW lpVersionInformation)
    uint64_t ver = a[0];
    if (!ver) return KERN_STATUS_INVALID_PARAMETER;
    
    // RTL_OSVERSIONINFOW: { ULONG dwOSVersionInfoSize; ULONG dwMajorVersion; ... }
    auto data = std::vector<uint8_t>(static_cast<size_t>(ptr_sz(e)) * 8, 0);
    write_le(data, 4, static_cast<uint64_t>(10), 4);  // MajorVersion = 10
    write_le(data, 8, static_cast<uint64_t>(0), 4);   // MinorVersion = 0
    write_le(data, 12, static_cast<uint64_t>(0), 4);  // BuildNumber
    write_le(data, 16, static_cast<uint64_t>(0), 4);  // PlatformId
    mm(e)->mem_write(ver, data);
    
    return KERN_STATUS_SUCCESS;
}

uint64_t Ntoskrnl::RtlCompareMemory(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // SIZE_T RtlCompareMemory(const void *Source1, const void *Source2, SIZE_T Length)
    uint64_t s1 = a[0];
    uint64_t s2 = a[1];
    uint64_t len = a[2];
    
    if (len == 0) return 0;
    
    auto d1 = mm(e)->mem_read(s1, static_cast<size_t>(len));
    auto d2 = mm(e)->mem_read(s2, static_cast<size_t>(len));
    
    size_t match = 0;
    for (size_t i = 0; i < d1.size() && i < d2.size(); i++) {
        if (d1[i] == d2[i]) match++;
        else break;
    }
    
    return static_cast<uint64_t>(match);
}

uint64_t Ntoskrnl::RtlMoveMemory(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // void RtlMoveMemory(void* Destination, const void* Source, size_t Length)
    return memcpy(e, a, ctx);
}

//  Memory/Pool 

uint64_t Ntoskrnl::ExAllocatePoolWithTag(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // PVOID ExAllocatePoolWithTag(POOL_TYPE PoolType, SIZE_T NumberOfBytes, ULONG Tag)
    uint64_t pool_type = a[0];
    uint64_t num_bytes = a[1];
    uint64_t tag = a[2];
    
    if (num_bytes == 0) num_bytes = 1;
    
    std::string tag_str = "Pool";
    if (tag) {
        char buf[5] = {0};
        buf[0] = static_cast<char>(tag & 0xFF);
        buf[1] = static_cast<char>((tag >> 8) & 0xFF);
        buf[2] = static_cast<char>((tag >> 16) & 0xFF);
        buf[3] = static_cast<char>((tag >> 24) & 0xFF);
        tag_str = std::string(buf);
    }
    
    (void)pool_type;
    return mm(e)->mem_map(static_cast<size_t>(num_bytes), 0, common::PERM_MEM_RWX,
                          "api.pool." + tag_str);
}

uint64_t Ntoskrnl::ExFreePoolWithTag(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // VOID ExFreePoolWithTag(PVOID P, ULONG Tag)
    uint64_t p = a[0];
    if (p) mm(e)->mem_free(p);
    return 0;
}

uint64_t Ntoskrnl::ExAllocatePool(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // PVOID ExAllocatePool(POOL_TYPE PoolType, SIZE_T NumberOfBytes)
    uint64_t num_bytes = a[1];
    if (num_bytes == 0) num_bytes = 1;
    return mm(e)->mem_map(static_cast<size_t>(num_bytes), 0, common::PERM_MEM_RWX, "api.pool");
}

uint64_t Ntoskrnl::ExFreePool(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // void ExFreePool(PVOID P)
    uint64_t p = a[0];
    if (p) mm(e)->mem_free(p);
    return 0;
}

uint64_t Ntoskrnl::FsRtlAllocatePool(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // PVOID FsRtlAllocatePool(POOL_TYPE PoolType, SIZE_T NumberOfBytes)
    uint64_t num_bytes = a[1];
    if (num_bytes == 0) num_bytes = 1;
    return mm(e)->mem_map(static_cast<size_t>(num_bytes), 0, common::PERM_MEM_RWX, "api.fsrtl.pool");
}

uint64_t Ntoskrnl::RtlAllocateHeap(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // PVOID RtlAllocateHeap(PVOID HeapHandle, ULONG Flags, SIZE_T Size)
    uint64_t size = a[2];
    if (size == 0) size = 1;
    return mm(e)->mem_map(static_cast<size_t>(size), 0, common::PERM_MEM_RWX, "api.heap");
}

uint64_t Ntoskrnl::RtlFreeHeap(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // BOOLEAN RtlFreeHeap(PVOID HeapHandle, ULONG Flags, PVOID HeapBase)
    uint64_t addr = a[2];
    if (addr) mm(e)->mem_free(addr);
    return 1; // TRUE
}

uint64_t Ntoskrnl::MmAllocateContiguousMemory(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // PVOID MmAllocateContiguousMemory(SIZE_T NumberOfBytes, PHYSICAL_ADDRESS HighestAcceptableAddress)
    uint64_t num_bytes = a[0];
    if (num_bytes == 0) num_bytes = 1;
    return mm(e)->mem_map(static_cast<size_t>(num_bytes), 0, common::PERM_MEM_RWX,
                          "api.contiguous");
}

uint64_t Ntoskrnl::MmFreeContiguousMemory(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // VOID MmFreeContiguousMemory(PVOID BaseAddress)
    uint64_t addr = a[0];
    if (addr) mm(e)->mem_free(addr);
    return 0;
}

uint64_t Ntoskrnl::MmIsAddressValid(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // BOOLEAN MmIsAddressValid(PVOID VirtualAddress)
    uint64_t addr = a[0];
    return we(e)->is_address_valid(addr) ? 1 : 0;
}

uint64_t Ntoskrnl::MmMapLockedPagesSpecifyCache(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // PVOID MmMapLockedPagesSpecifyCache(PMDL MemoryDescriptorList, KPROCESSOR_MODE AccessMode, ...)
    uint64_t mdl = a[0];
    if (!mdl) return 0;
    // Read MDL: contains ByteCount at offset, just allocate new memory
    auto raw = mm(e)->mem_read(mdl, ptr_sz(e) * 4);
    uint64_t byte_count = (ptr_sz(e) == 8) ? static_cast<uint64_t>(read_le(raw, 24, 4))
                                            : static_cast<uint64_t>(read_le(raw, 16, 4));
    if (byte_count == 0) byte_count = 0x1000;
    return mm(e)->mem_map(static_cast<size_t>(byte_count), 0, common::PERM_MEM_RWX,
                          "api.mdl.map");
}

uint64_t Ntoskrnl::MmUnlockPages(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a;
    return 0;
}

uint64_t Ntoskrnl::MmGetSystemRoutineAddress(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // PVOID MmGetSystemRoutineAddress(PUNICODE_STRING SystemRoutineName)
    uint64_t name = a[0];
    auto ustr = read_unicode_string_from_mem(e, name);
    std::string fn_name;
    for (auto c : ustr) {
        if (c == 0) break;
        fn_name.push_back(static_cast<char>(c));
    }
    return reinterpret_cast<uint64_t>(we(e)->get_proc("ntoskrnl", fn_name));
}

uint64_t Ntoskrnl::MmIsDriverVerifying(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a;
    return 0; // FALSE - driver is not being verified
}

//  memcpy/memset/etc 

uint64_t Ntoskrnl::memmove(void* e, const std::vector<uint64_t>& a, void* ctx) {
    return memcpy(e, a, ctx);
}

uint64_t Ntoskrnl::memcpy(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // void *memcpy(void *dest, const void *src, size_t count)
    uint64_t dest = a[0];
    uint64_t src = a[1];
    uint64_t count = a[2];
    
    if (count == 0) return dest;
    
    auto data = mm(e)->mem_read(src, static_cast<size_t>(count));
    mm(e)->mem_write(dest, data);
    return dest;
}

uint64_t Ntoskrnl::memset(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // void *memset(void *dest, int c, size_t count)
    uint64_t dest = a[0];
    uint64_t c = a[1] & 0xFF;
    uint64_t count = a[2];
    
    if (count == 0) return dest;
    
    auto data = std::vector<uint8_t>(static_cast<size_t>(count), static_cast<uint8_t>(c));
    mm(e)->mem_write(dest, data);
    return dest;
}

//  Wide char string 

uint64_t Ntoskrnl::wcscpy(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // wchar_t *wcscpy(wchar_t *strDestination, const wchar_t *strSource)
    uint64_t dest = a[0];
    uint64_t src = a[1];
    
    auto ws = read_wide_string_ptr(e, src);
    // Write including null terminator
    auto data = std::vector<uint8_t>();
    for (auto c : ws) {
        auto tmp = std::vector<uint8_t>(2);
        write_le(tmp, 0, static_cast<uint64_t>(c), 2);
        data.insert(data.end(), tmp.begin(), tmp.end());
    }
    mm(e)->mem_write(dest, data);
    
    return static_cast<uint64_t>(ws.length());
}

uint64_t Ntoskrnl::wcsncpy(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // wchar_t *wcsncpy(wchar_t *strDest, const wchar_t *strSource, size_t count)
    uint64_t dest = a[0];
    uint64_t src = a[1];
    uint64_t count = a[2];
    
    auto ws = read_wide_string_ptr(e, src, static_cast<int>(count));
    
    auto data = std::vector<uint8_t>();
    for (size_t i = 0; i < ws.size() && i < static_cast<size_t>(count); i++) {
        auto tmp = std::vector<uint8_t>(2);
        write_le(tmp, 0, static_cast<uint64_t>(ws[i]), 2);
        data.insert(data.end(), tmp.begin(), tmp.end());
    }
    mm(e)->mem_write(dest, data);
    
    return static_cast<uint64_t>(ws.length());
}

uint64_t Ntoskrnl::wcslen(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // size_t wcslen(const wchar_t *str)
    uint64_t str = a[0];
    auto ws = read_wide_string_ptr(e, str);
    return static_cast<uint64_t>(ws.length());
}

uint64_t Ntoskrnl::wcsnlen(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // size_t wcsnlen(const wchar_t *str, size_t max)
    uint64_t str = a[0];
    uint64_t max = a[1];
    auto ws = read_wide_string_ptr(e, str, static_cast<int>(max));
    return static_cast<uint64_t>(ws.length());
}

uint64_t Ntoskrnl::wcschr(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // wchar_t *wcschr(const wchar_t *str, wchar_t c)
    uint64_t str = a[0];
    uint64_t c = a[1];
    
    auto ws = read_wide_string_ptr(e, str);
    char16_t needle = static_cast<char16_t>(c & 0xFFFF);
    
    for (size_t i = 0; i < ws.length(); i++) {
        if (ws[i] == needle) {
            return str + static_cast<uint64_t>(i) * 2;
        }
    }
    return 0; // Not found
}

uint64_t Ntoskrnl::wcscat(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // wchar_t *wcscat(wchar_t *strDestination, const wchar_t *strSource)
    uint64_t dest = a[0];
    uint64_t src = a[1];
    
    auto dws = read_wide_string_ptr(e, dest);
    auto sws = read_wide_string_ptr(e, src);
    
    auto data = std::vector<uint8_t>();
    for (auto c : dws) {
        if (c == 0) break;
        auto tmp = std::vector<uint8_t>(2);
        write_le(tmp, 0, static_cast<uint64_t>(c), 2);
        data.insert(data.end(), tmp.begin(), tmp.end());
    }
    for (auto c : sws) {
        if (c == 0) break;
        auto tmp = std::vector<uint8_t>(2);
        write_le(tmp, 0, static_cast<uint64_t>(c), 2);
        data.insert(data.end(), tmp.begin(), tmp.end());
    }
    // null terminator
    data.push_back(0); data.push_back(0);
    mm(e)->mem_write(dest, data);
    return dest;
}

uint64_t Ntoskrnl::strrchr(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // char *strrchr(const char *str, int c)
    uint64_t str = a[0];
    uint64_t c = a[1];
    
    auto s = read_ansi_string_ptr(e, str);
    uint8_t needle = static_cast<uint8_t>(c & 0xFF);
    
    auto it = std::find(s.rbegin(), s.rend(), static_cast<char>(needle));
    if (it != s.rend()) {
        size_t offset = s.rend() - it - 1;
        return str + static_cast<uint64_t>(offset);
    }
    return 0;
}

uint64_t Ntoskrnl::strchr(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // char *strchr(const char *str, int c)
    uint64_t str = a[0];
    uint64_t c = a[1];
    
    auto s = read_ansi_string_ptr(e, str);
    uint8_t needle = static_cast<uint8_t>(c & 0xFF);
    
    for (size_t i = 0; i < s.length(); i++) {
        if (static_cast<uint8_t>(s[i]) == needle) {
            return str + static_cast<uint64_t>(i);
        }
    }
    return 0;
}

uint64_t Ntoskrnl::_wcsnicmp(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // int _wcsnicmp(const wchar_t *string1, const wchar_t *string2, size_t count)
    uint64_t s1 = a[0];
    uint64_t s2 = a[1];
    uint64_t count = a[2];
    
    auto ws1 = read_wide_string_ptr(e, s1, static_cast<int>(count));
    auto ws2 = read_wide_string_ptr(e, s2, static_cast<int>(count));
    
    // Case insensitive compare
    for (size_t i = 0; i < ws1.length() && i < ws2.length() && i < static_cast<size_t>(count); i++) {
        auto c1 = static_cast<char16_t>(std::tolower(static_cast<int>(ws1[i])));
        auto c2 = static_cast<char16_t>(std::tolower(static_cast<int>(ws2[i])));
        if (c1 < c2) return -1;
        if (c1 > c2) return 1;
    }
    return 0;
}

uint64_t Ntoskrnl::_stricmp(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // int _stricmp(const char *string1, const char *string2)
    uint64_t s1 = a[0];
    uint64_t s2 = a[1];
    
    if (!s1 || !s2) return 1;
    
    auto cs1 = read_ansi_string_ptr(e, s1);
    auto cs2 = read_ansi_string_ptr(e, s2);
    
    // Case insensitive
    cs1 = speakeasy::to_lower(cs1);
    cs2 = speakeasy::to_lower(cs2);
    
    if (cs1 == cs2) return 0;
    return (cs1 < cs2) ? -1 : 1;
}

uint64_t Ntoskrnl::_wcsicmp(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // int _wcsicmp(const wchar_t *string1, const wchar_t *string2)
    uint64_t s1 = a[0];
    uint64_t s2 = a[1];
    
    auto ws1 = read_wide_string_ptr(e, s1);
    auto ws2 = read_wide_string_ptr(e, s2);
    
    for (size_t i = 0; i < ws1.length() && i < ws2.length(); i++) {
        auto c1 = static_cast<char16_t>(std::tolower(static_cast<int>(ws1[i])));
        auto c2 = static_cast<char16_t>(std::tolower(static_cast<int>(ws2[i])));
        if (c1 < c2) return -1;
        if (c1 > c2) return 1;
    }
    return 0;
}

uint64_t Ntoskrnl::mbstowcs(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // size_t mbstowcs(wchar_t *dest, const char *src, size_t max)
    uint64_t dest = a[0];
    uint64_t src = a[1];
    uint64_t max = a[2];
    
    auto s = read_ansi_string_ptr(e, src);
    size_t len = (s.length() < static_cast<size_t>(max)) ? s.length() : static_cast<size_t>(max);
    
    if (dest) {
        auto data = std::vector<uint8_t>(len * 2);
        for (size_t i = 0; i < len; i++) {
            write_le(data, i * 2, static_cast<uint64_t>(static_cast<unsigned char>(s[i])), 2);
        }
        mm(e)->mem_write(dest, data);
    }
    
    return static_cast<uint64_t>(len);
}

//  I/O 

uint64_t Ntoskrnl::IoDeleteDriver(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // VOID IoDeleteDriver(PDRIVER_OBJECT DriverObject)
    (void)e; (void)a;
    return 0;
}

uint64_t Ntoskrnl::IoCreateDevice(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // NTSTATUS IoCreateDevice(DriverObject, DeviceExtensionSize, DeviceName, DeviceType, ...)
    uint64_t drv = a[0];
    uint64_t ext_size = a[1];
    uint64_t name = a[2];
    uint64_t devtype = a[3];
    uint64_t chars = a[4];
    uint64_t exclusive = a[5];
    uint64_t out_addr = a[6];
    
    (void)ext_size; (void)devtype; (void)chars; (void)exclusive;
    
    if (!drv) return KERN_STATUS_INVALID_PARAMETER;
    
    // Allocate a DEVICE_OBJECT
    size_t dev_obj_size = 80; // rough DEVICE_OBJECT size
    uint64_t dev_obj = mm(e)->mem_map(dev_obj_size, 0, common::PERM_MEM_RWX, "api.struct.DEVICE_OBJECT");
    
    if (name) {
        auto dev_name = read_unicode_string_from_mem(e, name);
        (void)dev_name;
    }
    
    if (out_addr) {
        size_t psz = static_cast<size_t>(ptr_sz(e));
        auto data = std::vector<uint8_t>(psz);
        write_le(data, 0, dev_obj, psz);
        mm(e)->mem_write(out_addr, data);
    }
    
    return KERN_STATUS_SUCCESS;
}

uint64_t Ntoskrnl::IoCreateDeviceSecure(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // NTSTATUS IoCreateDeviceSecure(...)
    // Similar to IoCreateDevice but with SDDL string and GUID
    return IoCreateDevice(e, a, ctx);
}

uint64_t Ntoskrnl::IoCreateSymbolicLink(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // NTSTATUS IoCreateSymbolicLink(SymbolicLinkName, DeviceName)
    uint64_t link_name = a[0];
    uint64_t dev_name = a[1];
    
    auto link = read_unicode_string_from_mem(e, link_name);
    auto dev = read_unicode_string_from_mem(e, dev_name);
    
    // Add symlink (stub - ObjectManager not fully wired)
    (void)link; (void)dev;
    
    return KERN_STATUS_SUCCESS;
}

uint64_t Ntoskrnl::IofCompleteRequest(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // VOID IoCompleteRequest(PIRP Irp, CCHAR PriorityBoost)
    (void)e; (void)a;
    return 0;
}

uint64_t Ntoskrnl::IoDeleteSymbolicLink(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // NTSTATUS IoDeleteSymbolicLink(PUNICODE_STRING SymbolicLinkName)
    (void)e; (void)a;
    return KERN_STATUS_SUCCESS;
}

uint64_t Ntoskrnl::IoDeleteDevice(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // VOID IoDeleteDevice(PDEVICE_OBJECT DeviceObject)
    (void)e; (void)a;
    return KERN_STATUS_SUCCESS;
}

uint64_t Ntoskrnl::IoCreateSynchronizationEvent(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // NTSTATUS IoCreateSynchronizationEvent(PUNICODE_STRING EventName, PHANDLE EventHandle)
    uint64_t evt_handle = a[1];
    if (evt_handle) {
        int psz = ptr_sz(e);
        auto data = std::vector<uint8_t>(static_cast<size_t>(psz), 0);
        mm(e)->mem_write(evt_handle, data);
    }
    return KERN_STATUS_SUCCESS;
}

uint64_t Ntoskrnl::IoAllocateIrp(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // PIRP IoAllocateIrp(CCHAR StackSize, BOOLEAN ChargeQuota)
    size_t irp_size = 0x100;
    return mm(e)->mem_map(irp_size, 0, common::PERM_MEM_RWX, "api.irp");
}

uint64_t Ntoskrnl::IoFreeIrp(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // VOID IoFreeIrp(PIRP Irp)
    uint64_t irp = a[0];
    if (irp) mm(e)->mem_free(irp);
    return 0;
}

uint64_t Ntoskrnl::IoReuseIrp(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a;
    return 0;
}

uint64_t Ntoskrnl::IoAllocateMdl(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // PMDL IoAllocateMdl(PVOID VirtualAddress, ULONG Length, BOOLEAN SecondaryBuffer, BOOLEAN ChargeQuota, PIRP Irp)
    size_t mdl_size = static_cast<size_t>(ptr_sz(e)) * 8;
    return mm(e)->mem_map(mdl_size, 0, common::PERM_MEM_RWX, "api.mdl");
}

uint64_t Ntoskrnl::IoFreeMdl(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // VOID IoFreeMdl(PMDL Mdl)
    uint64_t mdl = a[0];
    if (mdl) mm(e)->mem_free(mdl);
    return 0;
}

uint64_t Ntoskrnl::IofCallDriver(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // NTSTATUS IofCallDriver(PDEVICE_OBJECT DeviceObject, PIRP Irp)
    (void)e; (void)a;
    return KERN_STATUS_SUCCESS;
}

uint64_t Ntoskrnl::IoSetCompletionRoutineEx(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // NTSTATUS IoSetCompletionRoutineEx(PDEVICE_OBJECT DeviceObject, PIRP Irp, PIO_COMPLETION_ROUTINE ...)
    (void)e; (void)a;
    return KERN_STATUS_SUCCESS;
}

uint64_t Ntoskrnl::IoGetDeviceObjectPointer(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // NTSTATUS IoGetDeviceObjectPointer(PUNICODE_STRING ObjectName, ACCESS_MASK DesiredAccess, ...)
    (void)e; (void)a;
    return KERN_STATUS_SUCCESS;
}

uint64_t Ntoskrnl::IoGetCurrentProcess(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // PEPROCESS IoGetCurrentProcess()
    (void)a;
    // Return current process pointer
    return reinterpret_cast<uint64_t>(we(e)->get_current_process().get());
}

uint64_t Ntoskrnl::IoWMIRegistrationControl(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // NTSTATUS IoWMIRegistrationControl(PDEVICE_OBJECT DeviceObject, ULONG Action)
    (void)e; (void)a;
    return KERN_STATUS_SUCCESS;
}

uint64_t Ntoskrnl::IoRegisterBootDriverReinitialization(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a;
    return KERN_STATUS_SUCCESS;
}

uint64_t Ntoskrnl::IoRegisterShutdownNotification(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a;
    return KERN_STATUS_SUCCESS;
}

uint64_t Ntoskrnl::IoUnregisterShutdownNotification(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a;
    return KERN_STATUS_SUCCESS;
}

//  Ke (Kernel) 

uint64_t Ntoskrnl::KeInitializeMutex(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // VOID KeInitializeMutex(PRKMUTEX Mutex, ULONG Level)
    (void)e; (void)a;
    return 0;
}

uint64_t Ntoskrnl::KeSetEvent(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // LONG KeSetEvent(PKEVENT Event, KPRIORITY Increment, BOOLEAN Wait)
    (void)e; (void)a;
    return 0;
}

uint64_t Ntoskrnl::KeInitializeEvent(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // VOID KeInitializeEvent(PKEVENT Event, EVENT_TYPE Type, BOOLEAN State)
    (void)e; (void)a;
    return 0;
}

uint64_t Ntoskrnl::KeResetEvent(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // LONG KeResetEvent(PKEVENT Event)
    (void)e; (void)a;
    return 0;
}

uint64_t Ntoskrnl::KeClearEvent(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // VOID KeClearEvent(PKEVENT Event)
    (void)e; (void)a;
    return 0;
}

uint64_t Ntoskrnl::KeInitializeTimer(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // VOID KeInitializeTimer(PKTIMER Timer)
    (void)e; (void)a;
    return 0;
}

uint64_t Ntoskrnl::KeSetTimer(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // BOOLEAN KeSetTimer(PKTIMER Timer, LARGE_INTEGER DueTime, PKDPC Dpc)
    (void)e; (void)a;
    return 1; // TRUE
}

uint64_t Ntoskrnl::KeCancelTimer(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // BOOLEAN KeCancelTimer(PKTIMER Timer)
    (void)e; (void)a;
    return 1; // TRUE
}

uint64_t Ntoskrnl::KeDelayExecutionThread(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // NTSTATUS KeDelayExecutionThread(KPROCESSOR_MODE WaitMode, BOOLEAN Alertable, PLARGE_INTEGER Interval)
    (void)e; (void)a;
    return KERN_STATUS_SUCCESS;
}

uint64_t Ntoskrnl::KeWaitForSingleObject(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // NTSTATUS KeWaitForSingleObject(PVOID Object, KWAIT_REASON Reason, KPROCESSOR_MODE WaitMode, ...)
    (void)e; (void)a;
    return KERN_STATUS_SUCCESS;
}

uint64_t Ntoskrnl::KeInitializeApc(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // VOID KeInitializeApc(PRKAPC Apc, PKTHREAD Thread, KAPC_ENVIRONMENT Environment, ...)
    (void)e; (void)a;
    return 0;
}

uint64_t Ntoskrnl::KeInsertQueueApc(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // BOOLEAN KeInsertQueueApc(PRKAPC Apc, PVOID SystemArgument1, PVOID SystemArgument2, KPRIORITY ...)
    (void)e; (void)a;
    return 1; // TRUE
}

uint64_t Ntoskrnl::KeInitializeDpc(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // VOID KeInitializeDpc(PRKDPC Dpc, PKDEFERRED_ROUTINE DeferredRoutine, PVOID DeferredContext)
    (void)e; (void)a;
    return 0;
}

uint64_t Ntoskrnl::KeStackAttachProcess(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // VOID KeStackAttachProcess(PKPROCESS Process, PRKAPC_STATE ApcState)
    (void)e; (void)a;
    return 0;
}

uint64_t Ntoskrnl::KeUnstackDetachProcess(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // VOID KeUnstackDetachProcess(PRKAPC_STATE ApcState)
    (void)e; (void)a;
    return 0;
}

uint64_t Ntoskrnl::KeQuerySystemTime(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // VOID KeQuerySystemTime(PLARGE_INTEGER CurrentTime)
    uint64_t time_out = a[0];
    if (time_out) {
        auto data = std::vector<uint8_t>(8, 0);
        // Write some reasonable system time
        write_le(data, 0, static_cast<uint64_t>(0x01D1000000000000ULL), 8);
        mm(e)->mem_write(time_out, data);
    }
    return 0;
}

uint64_t Ntoskrnl::KeAcquireSpinLockRaiseToDpc(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a;
    return 0; // returns old IRQL
}

uint64_t Ntoskrnl::KeEnterCriticalRegion(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a;
    return 0;
}

uint64_t Ntoskrnl::KeLeaveCriticalRegion(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a;
    return 0;
}

//  Ps (Process) 

uint64_t Ntoskrnl::PsCreateSystemThread(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // NTSTATUS PsCreateSystemThread(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, ...)
    (void)e; (void)a;
    return KERN_STATUS_SUCCESS;
}

uint64_t Ntoskrnl::PsLookupProcessByProcessId(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // NTSTATUS PsLookupProcessByProcessId(HANDLE ProcessId, PEPROCESS *Process)
    uint64_t proc_out = a[1];
    if (proc_out) {
        size_t psz = static_cast<size_t>(ptr_sz(e));
        auto data = std::vector<uint8_t>(psz, 0);
        mm(e)->mem_write(proc_out, data);
    }
    return KERN_STATUS_NOT_FOUND;
}

uint64_t Ntoskrnl::PsLookupThreadByThreadId(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // NTSTATUS PsLookupThreadByThreadId(HANDLE ThreadId, PETHREAD *Thread)
    uint64_t thread_out = a[1];
    if (thread_out) {
        size_t psz = static_cast<size_t>(ptr_sz(e));
        auto data = std::vector<uint8_t>(psz, 0);
        mm(e)->mem_write(thread_out, data);
    }
    return KERN_STATUS_NOT_FOUND;
}

uint64_t Ntoskrnl::PsGetProcessPeb(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // PPEB PsGetProcessPeb(PEPROCESS Process)
    (void)e; (void)a;
    return 0;
}

uint64_t Ntoskrnl::PsTerminateSystemThread(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // NTSTATUS PsTerminateSystemThread(NTSTATUS ExitStatus)
    (void)e; (void)a;
    return KERN_STATUS_SUCCESS;
}

uint64_t Ntoskrnl::PsGetVersion(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // NTSTATUS PsGetVersion(PULONG MajorVersion, PULONG MinorVersion, PULONG BuildNumber, ...)
    uint64_t major = a[0];
    uint64_t minor = a[1];
    uint64_t build = a[2];
    (void)a[3];
    
    if (major) {
        auto data = std::vector<uint8_t>(4);
        write_le(data, 0, static_cast<uint64_t>(10), 4);
        mm(e)->mem_write(major, data);
    }
    if (minor) {
        auto data = std::vector<uint8_t>(4);
        write_le(data, 0, static_cast<uint64_t>(0), 4);
        mm(e)->mem_write(minor, data);
    }
    if (build) {
        auto data = std::vector<uint8_t>(4);
        write_le(data, 0, static_cast<uint64_t>(0x4EA0), 4); // 20000
        mm(e)->mem_write(build, data);
    }
    
    return KERN_STATUS_SUCCESS;
}

uint64_t Ntoskrnl::PsSetCreateProcessNotifyRoutineEx(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // NTSTATUS PsSetCreateProcessNotifyRoutineEx(PCREATE_PROCESS_NOTIFY_ROUTINE_EX NotifyRoutine, BOOLEAN Remove)
    (void)e; (void)a;
    return KERN_STATUS_SUCCESS;
}

uint64_t Ntoskrnl::PsSetLoadImageNotifyRoutine(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a;
    return KERN_STATUS_SUCCESS;
}

uint64_t Ntoskrnl::PsRemoveLoadImageNotifyRoutine(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a;
    return KERN_STATUS_SUCCESS;
}

uint64_t Ntoskrnl::PsSetCreateThreadNotifyRoutine(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a;
    return KERN_STATUS_SUCCESS;
}

uint64_t Ntoskrnl::PsRemoveCreateThreadNotifyRoutine(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a;
    return KERN_STATUS_SUCCESS;
}

//  Zw/Nt system calls 

uint64_t Ntoskrnl::ZwQuerySystemInformation(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // NTSTATUS ZwQuerySystemInformation(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG)
    uint64_t sysclass = a[0];
    uint64_t sysinfo = a[1];
    uint64_t syslen = a[2];
    uint64_t retlen = a[3];
    
    uint64_t size = 0;
    uint64_t nts = KERN_STATUS_INFO_LENGTH_MISMATCH;
    
    if (sysclass == KERN_SYSTEM_MODULE_INFORMATION) {
        // SystemModuleInformation
        auto mods = we(e)->get_peb_modules();  // Simplified
        
        size = 4; // ULONG module count
        for (size_t i = 0; i < mods.size(); i++) {
            (void)mods[i];
            size += 64; // Rough module info size
        }
        
        if (size <= syslen && syslen != 0) {
            uint64_t buf_ptr = sysinfo;
            auto count_data = std::vector<uint8_t>(4);
            write_le(count_data, 0, static_cast<uint64_t>(mods.size()), 4);
            mm(e)->mem_write(buf_ptr, count_data);
            // Simplified - just write module count
            nts = KERN_STATUS_SUCCESS;
        }
    } else if (sysclass == KERN_SYSTEM_TIMEOFDAY_INFORMATION) {
        size = 64;
        if (size <= syslen && syslen != 0 && sysinfo) {
            auto data = std::vector<uint8_t>(static_cast<size_t>(size), 0);
            mm(e)->mem_write(sysinfo, data);
            nts = KERN_STATUS_SUCCESS;
        }
    } else if (sysclass == KERN_SYSTEM_KERNEL_DEBUGGER_INFORMATION) {
        if (sysinfo && syslen >= 2) {
            auto data = std::vector<uint8_t>{0x00, 0x01}; // Debugger not enabled, flags
            mm(e)->mem_write(sysinfo, data);
            nts = KERN_STATUS_SUCCESS;
        }
    } else if (sysclass == KERN_SYSTEM_CODEINTEGRITY_INFORMATION) {
        if (sysinfo && syslen >= 8) {
            auto data = std::vector<uint8_t>(8);
            write_le(data, 0, static_cast<uint64_t>(8), 4); // Length
            write_le(data, 4, static_cast<uint64_t>(1), 4); // Flags = enabled
            mm(e)->mem_write(sysinfo, data);
            nts = KERN_STATUS_SUCCESS;
        }
    }
    
    if (retlen) {
        auto data = std::vector<uint8_t>(4);
        write_le(data, 0, size, 4);
        mm(e)->mem_write(retlen, data);
    }
    
    return nts;
}

uint64_t Ntoskrnl::ZwProtectVirtualMemory(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // NTSTATUS ZwProtectVirtualMemory(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG)
    (void)e; (void)a;
    return KERN_STATUS_SUCCESS;
}

uint64_t Ntoskrnl::ZwWriteVirtualMemory(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // NTSTATUS ZwWriteVirtualMemory(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T)
    uint64_t addr = a[1];
    uint64_t buf = a[2];
    uint64_t len = a[3];
    uint64_t ret = a[4];
    
    auto data = mm(e)->mem_read(buf, static_cast<size_t>(len));
    mm(e)->mem_write(addr, data);
    
    if (ret) {
        auto rdata = std::vector<uint8_t>(static_cast<size_t>(ptr_sz(e)));
        write_le(rdata, 0, len, ptr_sz(e));
        mm(e)->mem_write(ret, rdata);
    }
    
    return KERN_STATUS_SUCCESS;
}

uint64_t Ntoskrnl::ZwAllocateVirtualMemory(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // NTSTATUS ZwAllocateVirtualMemory(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG)
    uint64_t paddr = a[1];
    uint64_t psize = a[3];
    uint64_t size = 0x1000;
    
    if (psize) {
        auto raw = mm(e)->mem_read(psize, static_cast<size_t>(ptr_sz(e)));
        size = read_le(raw, 0, ptr_sz(e));
    }
    
    uint64_t addr = mm(e)->mem_map(static_cast<size_t>(size), 0, common::PERM_MEM_RWX,
                                   "api.virtual");
    
    if (paddr) {
        auto data = std::vector<uint8_t>(static_cast<size_t>(ptr_sz(e)));
        write_le(data, 0, addr, ptr_sz(e));
        mm(e)->mem_write(paddr, data);
    }
    
    if (psize) {
        auto data = std::vector<uint8_t>(static_cast<size_t>(ptr_sz(e)));
        write_le(data, 0, size, ptr_sz(e));
        mm(e)->mem_write(psize, data);
    }
    
    return KERN_STATUS_SUCCESS;
}

uint64_t Ntoskrnl::ZwOpenEvent(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // NTSTATUS ZwOpenEvent(PHANDLE EventHandle, ACCESS_MASK, POBJECT_ATTRIBUTES)
    (void)e; (void)a;
    return KERN_STATUS_SUCCESS;
}

uint64_t Ntoskrnl::ZwCreateEvent(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // NTSTATUS ZwCreateEvent(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, EVENT_TYPE, BOOLEAN)
    (void)e; (void)a;
    return KERN_STATUS_SUCCESS;
}

uint64_t Ntoskrnl::ZwDeviceIoControlFile(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // NTSTATUS ZwDeviceIoControlFile(HANDLE, HANDLE, ..., ULONG IoControlCode, ...)
    (void)e; (void)a;
    return KERN_STATUS_SUCCESS;
}

uint64_t Ntoskrnl::ZwDeleteKey(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // NTSTATUS ZwDeleteKey(HANDLE KeyHandle)
    (void)e; (void)a;
    return KERN_STATUS_SUCCESS;
}

uint64_t Ntoskrnl::ZwQueryInformationProcess(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // NTSTATUS ZwQueryInformationProcess(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG)
    (void)e; (void)a;
    return KERN_STATUS_SUCCESS;
}

uint64_t Ntoskrnl::ZwOpenKey(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // NTSTATUS ZwOpenKey(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES)
    (void)e; (void)a;
    return KERN_STATUS_SUCCESS;
}

uint64_t Ntoskrnl::ZwQueryValueKey(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // NTSTATUS ZwQueryValueKey(HANDLE, PUNICODE_STRING, KEY_VALUE_INFORMATION_CLASS, PVOID, ULONG, PULONG)
    (void)e; (void)a;
    return KERN_STATUS_OBJECT_NAME_NOT_FOUND;
}

uint64_t Ntoskrnl::ZwCreateFile(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // NTSTATUS ZwCreateFile(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, ...)
    (void)e; (void)a;
    return KERN_STATUS_SUCCESS;
}

uint64_t Ntoskrnl::ZwOpenFile(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // NTSTATUS ZwOpenFile(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, ...)
    (void)e; (void)a;
    return KERN_STATUS_SUCCESS;
}

uint64_t Ntoskrnl::ZwQueryInformationFile(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // NTSTATUS ZwQueryInformationFile(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, FILE_INFORMATION_CLASS)
    (void)e; (void)a;
    return KERN_STATUS_SUCCESS;
}

uint64_t Ntoskrnl::ZwWriteFile(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // NTSTATUS ZwWriteFile(HANDLE, HANDLE, ..., PVOID Buffer, ULONG Length, ...)
    (void)e; (void)a;
    return KERN_STATUS_SUCCESS;
}

uint64_t Ntoskrnl::ZwReadFile(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // NTSTATUS ZwReadFile(HANDLE, HANDLE, ..., PVOID Buffer, ULONG Length, ...)
    (void)e; (void)a;
    return KERN_STATUS_SUCCESS;
}

uint64_t Ntoskrnl::ZwCreateSection(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // NTSTATUS ZwCreateSection(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ...)
    (void)e; (void)a;
    return KERN_STATUS_SUCCESS;
}

uint64_t Ntoskrnl::ZwUnmapViewOfSection(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // NTSTATUS ZwUnmapViewOfSection(HANDLE, PVOID BaseAddress)
    (void)e; (void)a;
    return KERN_STATUS_SUCCESS;
}

uint64_t Ntoskrnl::ZwMapViewOfSection(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // NTSTATUS ZwMapViewOfSection(HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, ...)
    (void)e; (void)a;
    return KERN_STATUS_SUCCESS;
}

uint64_t Ntoskrnl::ZwGetContextThread(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // NTSTATUS ZwGetContextThread(HANDLE, PCONTEXT)
    (void)e; (void)a;
    return KERN_STATUS_SUCCESS;
}

uint64_t Ntoskrnl::ZwSetContextThread(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // NTSTATUS ZwSetContextThread(HANDLE, PCONTEXT)
    (void)e; (void)a;
    return KERN_STATUS_SUCCESS;
}

uint64_t Ntoskrnl::NtSetInformationThread(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // NTSTATUS NtSetInformationThread(HANDLE, THREADINFOCLASS, PVOID, ULONG)
    (void)e; (void)a;
    return KERN_STATUS_SUCCESS;
}

//  Mm (Memory Management) 

uint64_t Ntoskrnl::MmProbeAndLockPages(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // VOID MmProbeAndLockPages(PMDL MemoryDescriptorList, KPROCESSOR_MODE AccessMode, ...)
    (void)e; (void)a;
    return 0;
}

//  Ex (Executive) 

uint64_t Ntoskrnl::ExInitializeResourceLite(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // NTSTATUS ExInitializeResourceLite(PRESOURCE_LITE Resource)
    (void)e; (void)a;
    return KERN_STATUS_SUCCESS;
}

uint64_t Ntoskrnl::ExAcquireResourceExclusiveLite(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // BOOLEAN ExAcquireResourceExclusiveLite(PRESOURCE_LITE Resource, BOOLEAN Wait)
    (void)e; (void)a;
    return 1; // TRUE
}

uint64_t Ntoskrnl::ExAcquireResourceSharedLite(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // BOOLEAN ExAcquireResourceSharedLite(PRESOURCE_LITE Resource, BOOLEAN Wait)
    (void)e; (void)a;
    return 1; // TRUE
}

uint64_t Ntoskrnl::ExReleaseResourceLite(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // NTSTATUS ExReleaseResourceLite(PRESOURCE_LITE Resource)
    (void)e; (void)a;
    return KERN_STATUS_SUCCESS;
}

uint64_t Ntoskrnl::ExAcquireFastMutex(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // VOID ExAcquireFastMutex(PFAST_MUTEX FastMutex)
    (void)e; (void)a;
    return 0;
}

uint64_t Ntoskrnl::ExReleaseFastMutex(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // VOID ExReleaseFastMutex(PFAST_MUTEX FastMutex)
    (void)e; (void)a;
    return 0;
}

uint64_t Ntoskrnl::ExQueueWorkItem(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // VOID ExQueueWorkItem(PWORK_QUEUE_ITEM WorkItem, WORK_QUEUE_TYPE QueueType)
    (void)e; (void)a;
    return 0;
}

uint64_t Ntoskrnl::ExSystemTimeToLocalTime(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // VOID ExSystemTimeToLocalTime(PLARGE_INTEGER SystemTime, PLARGE_INTEGER LocalTime)
    uint64_t local_time = a[1];
    if (local_time) {
        auto data = std::vector<uint8_t>(8, 0);
        write_le(data, 0, static_cast<uint64_t>(0x01D1000000000000ULL), 8);
        mm(e)->mem_write(local_time, data);
    }
    return 0;
}

//  Security 

uint64_t Ntoskrnl::RtlLengthRequiredSid(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // ULONG RtlLengthRequiredSid(ULONG SubAuthorityCount)
    uint64_t sub_auth_count = a[0];
    (void)sub_auth_count;
    // SID = 8 bytes fixed header + 4 * sub_auth_count
    return 8 + static_cast<uint64_t>(a[0]) * 4;
}

uint64_t Ntoskrnl::RtlInitializeSid(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // NTSTATUS RtlInitializeSid(PSID Sid, PSID_IDENTIFIER_AUTHORITY IdentifierAuthority, ULONG SubAuthorityCount)
    uint64_t sid = a[0];
    uint64_t auth = a[1];
    uint64_t count = a[2];
    
    if (sid) {
        auto data = std::vector<uint8_t>(8);
        data[0] = 1; // Revision
        data[1] = static_cast<uint8_t>(count & 0xFF); // SubAuthorityCount
        // Copy IdentifierAuthority (6 bytes)
        if (auth) {
            auto auth_data = mm(e)->mem_read(auth, 6);
            for (int i = 0; i < 6; i++) data[2 + i] = auth_data[i];
        }
        mm(e)->mem_write(sid, data);
    }
    
    return KERN_STATUS_SUCCESS;
}

uint64_t Ntoskrnl::RtlSubAuthoritySid(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // PULONG RtlSubAuthoritySid(PSID Sid, ULONG SubAuthority)
    uint64_t sid = a[0];
    uint64_t index = a[1];
    // SID layout: revision(1), count(1), auth(6), subauth0(4), subauth1(4), ...
    uint64_t offset = 8 + index * 4;
    return sid ? (sid + offset) : 0;
}

uint64_t Ntoskrnl::RtlCreateAcl(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // NTSTATUS RtlCreateAcl(PACL Acl, ULONG AclLength, ULONG AceRevision)
    uint64_t acl = a[0];
    uint64_t len = a[1];
    if (acl && len >= 8) {
        auto data = std::vector<uint8_t>(static_cast<size_t>(len), 0);
        data[0] = 2; // Revision
        data[1] = 0; // Sbz1
        write_le(data, 2, static_cast<uint64_t>(len), 2); // AclSize
        data[4] = 0; // AceCount
        data[5] = 0; // Sbz2
        mm(e)->mem_write(acl, data);
    }
    return KERN_STATUS_SUCCESS;
}

uint64_t Ntoskrnl::RtlCreateSecurityDescriptor(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // NTSTATUS RtlCreateSecurityDescriptor(PSECURITY_DESCRIPTOR SecurityDescriptor, ULONG Revision)
    uint64_t sd = a[0];
    if (sd) {
        auto data = std::vector<uint8_t>(static_cast<size_t>(ptr_sz(e)) * 4, 0);
        data[0] = 1; // Revision
        data[1] = 0x84; // SE_SELF_RELATIVE | SE_SACL_PRESENT... actually just SE_SELF_RELATIVE
        mm(e)->mem_write(sd, data);
    }
    return KERN_STATUS_SUCCESS;
}

uint64_t Ntoskrnl::RtlSetDaclSecurityDescriptor(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // NTSTATUS RtlSetDaclSecurityDescriptor(PSECURITY_DESCRIPTOR, BOOLEAN, PACL, BOOLEAN)
    (void)e; (void)a;
    return KERN_STATUS_SUCCESS;
}

uint64_t Ntoskrnl::RtlAddAccessAllowedAce(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // NTSTATUS RtlAddAccessAllowedAce(PACL, ULONG, ACCESS_MASK, PSID)
    (void)e; (void)a;
    return KERN_STATUS_SUCCESS;
}

//  Registry 

uint64_t Ntoskrnl::RtlQueryRegistryValuesEx(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // NTSTATUS RtlQueryRegistryValuesEx(ULONG RelativeTo, PCWSTR Path, PRTL_QUERY_REGISTRY_TABLE, ...)
    (void)e; (void)a;
    return KERN_STATUS_SUCCESS;
}

//  Timer/Power 

uint64_t Ntoskrnl::PoDeletePowerRequest(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a;
    return KERN_STATUS_SUCCESS;
}

//  Kd 

uint64_t Ntoskrnl::KdDisableDebugger(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // NTSTATUS KdDisableDebugger()
    (void)e; (void)a;
    return KERN_STATUS_SUCCESS;
}

uint64_t Ntoskrnl::KdChangeOption(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // NTSTATUS KdChangeOption(ULONG Option, ULONG InValue, PULONG OutValue)
    (void)e; (void)a;
    return KERN_STATUS_SUCCESS;
}

//  Cm (Configuration Manager) 

uint64_t Ntoskrnl::CmRegisterCallbackEx(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // NTSTATUS CmRegisterCallbackEx(...)
    (void)e; (void)a;
    return KERN_STATUS_SUCCESS;
}

uint64_t Ntoskrnl::CmRegisterCallback(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // NTSTATUS CmRegisterCallback(...)
    (void)e; (void)a;
    return KERN_STATUS_SUCCESS;
}

uint64_t Ntoskrnl::CmUnRegisterCallback(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // NTSTATUS CmUnRegisterCallback(...)
    (void)e; (void)a;
    return KERN_STATUS_SUCCESS;
}

//  Etw 

uint64_t Ntoskrnl::EtwRegister(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // NTSTATUS EtwRegister(...)
    (void)e; (void)a;
    return KERN_STATUS_SUCCESS;
}

//  Image 

uint64_t Ntoskrnl::RtlImageDirectoryEntryToData(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // PVOID RtlImageDirectoryEntryToData(PVOID ImageBase, BOOLEAN MappedAsImage, USHORT DirectoryEntry, ...)
    (void)e; (void)a;
    return 0;
}

//  Compression 

uint64_t Ntoskrnl::RtlGetCompressionWorkSpaceSize(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // NTSTATUS RtlGetCompressionWorkSpaceSize(USHORT, PULONG, PULONG)
    (void)e; (void)a;
    return KERN_STATUS_SUCCESS;
}

uint64_t Ntoskrnl::RtlDecompressBuffer(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // NTSTATUS RtlDecompressBuffer(USHORT, PUCHAR, ULONG, PUCHAR, ULONG, PULONG)
    (void)e; (void)a;
    return KERN_STATUS_SUCCESS;
}

//  Misc 

uint64_t Ntoskrnl::RtlTimeToTimeFields(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // VOID RtlTimeToTimeFields(PLARGE_INTEGER Time, PTIME_FIELDS TimeFields)
    uint64_t tf = a[1];
    if (tf) {
        // TIME_FIELDS: { USHORT Year; USHORT Month; USHORT Day; USHORT Hour; USHORT Minute; USHORT Second; ... }
        auto data = std::vector<uint8_t>(16, 0);
        write_le(data, 0, static_cast<uint64_t>(2024), 2); // Year
        write_le(data, 2, static_cast<uint64_t>(1), 2);    // Month
        write_le(data, 4, static_cast<uint64_t>(1), 2);    // Day
        mm(e)->mem_write(tf, data);
    }
    return 0;
}

uint64_t Ntoskrnl::_allshl(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // LONGLONG _allshl(LONGLONG a, LONG b)
    uint64_t val = a[0];
    uint64_t shift = a[1] & 0x3F;
    return val << shift;
}

}}} // namespaces
