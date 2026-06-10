// ntdll.h  ntdll.dll API handler
//
// Maps to: speakeasy/winenv/api/usermode/ntdll.py
//
// Full NT kernel layer API implementation:
//   - Heap: RtlAllocateHeap, RtlFreeHeap, RtlReAllocateHeap, RtlCreateHeap, RtlDestroyHeap
//   - Virtual memory: NtAllocateVirtualMemory, NtFreeVirtualMemory, NtProtectVirtualMemory
//   - File I/O: NtCreateFile, NtOpenFile, NtReadFile, NtWriteFile, NtClose, NtDeviceIoControlFile
//   - Registry: NtCreateKey, NtOpenKey, NtQueryValueKey, NtSetValueKey, NtDeleteKey
//   - Strings: RtlInitUnicodeString, RtlInitString, RtlAnsiStringToUnicodeString, RtlFreeUnicodeString
//   - Info: RtlNtStatusToDosError, CsrGetProcessId, NtQuerySystemInformation,
//           NtQueryInformationProcess, NtSetInformationProcess
//   - Sections: NtCreateSection, NtOpenSection, NtMapViewOfSection, NtUnmapViewOfSection
//   - Volume: NtQueryVolumeInformationFile
//   - Sync: NtCreateEvent, NtOpenEvent, NtCreateMutant, NtOpenMutant,
//            NtWaitForSingleObject, NtDelayExecution
//   - Thread: NtGetContextThread, NtSetContextThread, NtCreateThread,
//             NtOpenThread, TerminateThread
//   - Object: NtQueryObject, NtDuplicateObject

#ifndef SPEAKEASY_NTDLL_H
#define SPEAKEASY_NTDLL_H

#include <string>
#include <vector>
#include "../api.h"

namespace speakeasy {
namespace api {

#ifdef RtlMoveMemory
#undef RtlMoveMemory
#endif
#ifdef RtlZeroMemory
#undef RtlZeroMemory
#endif

class Ntdll : public ApiHandler {
public:
    Ntdll(void* emu);
    std::string get_name() const override { return "ntdll"; }
    const std::vector<ApiEntry>& get_apis() const override { return apis_; }

    // Heap
    static uint64_t RtlAllocateHeap(void*, ArgList&, void* ctx);
    static uint64_t RtlFreeHeap(void*, ArgList&, void* ctx);
    static uint64_t RtlReAllocateHeap(void*, ArgList&, void* ctx);
    static uint64_t RtlCreateHeap(void*, ArgList&, void* ctx);
    static uint64_t RtlDestroyHeap(void*, ArgList&, void* ctx);
    static uint64_t RtlGetProcessHeap(void*, ArgList&, void* ctx);

    // Virtual memory
    static uint64_t NtAllocateVirtualMemory(void*, ArgList&, void* ctx);
    static uint64_t NtFreeVirtualMemory(void*, ArgList&, void* ctx);
    static uint64_t NtProtectVirtualMemory(void*, ArgList&, void* ctx);
    static uint64_t NtQueryVirtualMemory(void*, ArgList&, void* ctx);

    // File I/O
    static uint64_t NtCreateFile(void*, ArgList&, void* ctx);
    static uint64_t NtOpenFile(void*, ArgList&, void* ctx);
    static uint64_t NtReadFile(void*, ArgList&, void* ctx);
    static uint64_t NtWriteFile(void*, ArgList&, void* ctx);
    static uint64_t NtClose(void*, ArgList&, void* ctx);
    static uint64_t NtDeviceIoControlFile(void*, ArgList&, void* ctx);

    // Process / thread
    static uint64_t NtCreateProcess(void*, ArgList&, void* ctx);
    static uint64_t NtCreateThread(void*, ArgList&, void* ctx);
    static uint64_t NtOpenThread(void*, ArgList&, void* ctx);
    static uint64_t NtTerminateProcess(void*, ArgList&, void* ctx);
    static uint64_t NtTerminateThread(void*, ArgList&, void* ctx);
    static uint64_t NtGetContextThread(void*, ArgList&, void* ctx);
    static uint64_t NtSetContextThread(void*, ArgList&, void* ctx);

    // System info
    static uint64_t NtQuerySystemInformation(void*, ArgList&, void* ctx);
    static uint64_t NtQueryInformationProcess(void*, ArgList&, void* ctx);
    static uint64_t NtSetInformationProcess(void*, ArgList&, void* ctx);

    // Registry
    static uint64_t NtCreateKey(void*, ArgList&, void* ctx);
    static uint64_t NtOpenKey(void*, ArgList&, void* ctx);
    static uint64_t NtQueryValueKey(void*, ArgList&, void* ctx);
    static uint64_t NtSetValueKey(void*, ArgList&, void* ctx);
    static uint64_t NtDeleteKey(void*, ArgList&, void* ctx);
    static uint64_t NtDeleteValueKey(void*, ArgList&, void* ctx);

    // Sections (memory-mapped files)
    static uint64_t NtCreateSection(void*, ArgList&, void* ctx);
    static uint64_t NtOpenSection(void*, ArgList&, void* ctx);
    static uint64_t NtMapViewOfSection(void*, ArgList&, void* ctx);
    static uint64_t NtUnmapViewOfSection(void*, ArgList&, void* ctx);

    // Synchronization
    static uint64_t NtCreateEvent(void*, ArgList&, void* ctx);
    static uint64_t NtOpenEvent(void*, ArgList&, void* ctx);
    static uint64_t NtCreateMutant(void*, ArgList&, void* ctx);
    static uint64_t NtOpenMutant(void*, ArgList&, void* ctx);
    static uint64_t NtWaitForSingleObject(void*, ArgList&, void* ctx);
    static uint64_t NtDelayExecution(void*, ArgList&, void* ctx);

    // String / utility
    static uint64_t RtlInitUnicodeString(void*, ArgList&, void* ctx);
    static uint64_t RtlInitString(void*, ArgList&, void* ctx);
    static uint64_t RtlAnsiStringToUnicodeString(void*, ArgList&, void* ctx);
    static uint64_t RtlFreeUnicodeString(void*, ArgList&, void* ctx);
    static uint64_t RtlNtStatusToDosError(void*, ArgList&, void* ctx);
    static uint64_t CsrGetProcessId(void*, ArgList&, void* ctx);

    // Volume / object
    static uint64_t NtQueryVolumeInformationFile(void*, ArgList&, void* ctx);
    static uint64_t NtQueryObject(void*, ArgList&, void* ctx);
    static uint64_t NtDuplicateObject(void*, ArgList&, void* ctx);

    // Additional ntdll APIs (from Python reference)
    static uint64_t RtlGetLastWin32Error(void*, ArgList&, void* ctx);
    static uint64_t RtlFlushSecureMemoryCache(void*, ArgList&, void* ctx);
    static uint64_t RtlAddVectoredExceptionHandler(void*, ArgList&, void* ctx);
    static uint64_t RtlRemoveVectoredExceptionHandler(void*, ArgList&, void* ctx);
    static uint64_t NtYieldExecution(void*, ArgList&, void* ctx);
    static uint64_t LdrLoadDll(void*, ArgList&, void* ctx);
    static uint64_t LdrGetProcedureAddress(void*, ArgList&, void* ctx);
    static uint64_t LdrFindResource_U(void*, ArgList&, void* ctx);
    static uint64_t LdrAccessResource(void*, ArgList&, void* ctx);
    static uint64_t RtlZeroMemory(void*, ArgList&, void* ctx);
    static uint64_t RtlMoveMemory(void*, ArgList&, void* ctx);
    static uint64_t RtlEncodePointer(void*, ArgList&, void* ctx);
    static uint64_t RtlDecodePointer(void*, ArgList&, void* ctx);
    static uint64_t RtlComputeCrc32(void*, ArgList&, void* ctx);
    static uint64_t RtlGetNtVersionNumbers(void*, ArgList&, void* ctx);
    static uint64_t RtlGetCurrentPeb(void*, ArgList&, void* ctx);
    static uint64_t RtlGetVersion(void*, ArgList&, void* ctx);

    // Fallback
    static uint64_t stub_api(void*, ArgList&, void* ctx);

private:
    std::vector<ApiEntry> apis_;
};

} // namespace api
} // namespace speakeasy

#endif // SPEAKEASY_NTDLL_H
