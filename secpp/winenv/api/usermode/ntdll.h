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
    static uint64_t RtlAllocateHeap(void*, std::vector<uint64_t>&, void* ctx);
    static uint64_t RtlFreeHeap(void*, std::vector<uint64_t>&, void* ctx);
    static uint64_t RtlReAllocateHeap(void*, std::vector<uint64_t>&, void* ctx);
    static uint64_t RtlCreateHeap(void*, std::vector<uint64_t>&, void* ctx);
    static uint64_t RtlDestroyHeap(void*, std::vector<uint64_t>&, void* ctx);
    static uint64_t RtlGetProcessHeap(void*, std::vector<uint64_t>&, void* ctx);

    // Virtual memory
    static uint64_t NtAllocateVirtualMemory(void*, std::vector<uint64_t>&, void* ctx);
    static uint64_t NtFreeVirtualMemory(void*, std::vector<uint64_t>&, void* ctx);
    static uint64_t NtProtectVirtualMemory(void*, std::vector<uint64_t>&, void* ctx);
    static uint64_t NtQueryVirtualMemory(void*, std::vector<uint64_t>&, void* ctx);

    // File I/O
    static uint64_t NtCreateFile(void*, std::vector<uint64_t>&, void* ctx);
    static uint64_t NtOpenFile(void*, std::vector<uint64_t>&, void* ctx);
    static uint64_t NtReadFile(void*, std::vector<uint64_t>&, void* ctx);
    static uint64_t NtWriteFile(void*, std::vector<uint64_t>&, void* ctx);
    static uint64_t NtClose(void*, std::vector<uint64_t>&, void* ctx);
    static uint64_t NtDeviceIoControlFile(void*, std::vector<uint64_t>&, void* ctx);

    // Process / thread
    static uint64_t NtCreateProcess(void*, std::vector<uint64_t>&, void* ctx);
    static uint64_t NtCreateThread(void*, std::vector<uint64_t>&, void* ctx);
    static uint64_t NtOpenThread(void*, std::vector<uint64_t>&, void* ctx);
    static uint64_t NtTerminateProcess(void*, std::vector<uint64_t>&, void* ctx);
    static uint64_t NtTerminateThread(void*, std::vector<uint64_t>&, void* ctx);
    static uint64_t NtGetContextThread(void*, std::vector<uint64_t>&, void* ctx);
    static uint64_t NtSetContextThread(void*, std::vector<uint64_t>&, void* ctx);

    // System info
    static uint64_t NtQuerySystemInformation(void*, std::vector<uint64_t>&, void* ctx);
    static uint64_t NtQueryInformationProcess(void*, std::vector<uint64_t>&, void* ctx);
    static uint64_t NtSetInformationProcess(void*, std::vector<uint64_t>&, void* ctx);

    // Registry
    static uint64_t NtCreateKey(void*, std::vector<uint64_t>&, void* ctx);
    static uint64_t NtOpenKey(void*, std::vector<uint64_t>&, void* ctx);
    static uint64_t NtQueryValueKey(void*, std::vector<uint64_t>&, void* ctx);
    static uint64_t NtSetValueKey(void*, std::vector<uint64_t>&, void* ctx);
    static uint64_t NtDeleteKey(void*, std::vector<uint64_t>&, void* ctx);
    static uint64_t NtDeleteValueKey(void*, std::vector<uint64_t>&, void* ctx);

    // Sections (memory-mapped files)
    static uint64_t NtCreateSection(void*, std::vector<uint64_t>&, void* ctx);
    static uint64_t NtOpenSection(void*, std::vector<uint64_t>&, void* ctx);
    static uint64_t NtMapViewOfSection(void*, std::vector<uint64_t>&, void* ctx);
    static uint64_t NtUnmapViewOfSection(void*, std::vector<uint64_t>&, void* ctx);

    // Synchronization
    static uint64_t NtCreateEvent(void*, std::vector<uint64_t>&, void* ctx);
    static uint64_t NtOpenEvent(void*, std::vector<uint64_t>&, void* ctx);
    static uint64_t NtCreateMutant(void*, std::vector<uint64_t>&, void* ctx);
    static uint64_t NtOpenMutant(void*, std::vector<uint64_t>&, void* ctx);
    static uint64_t NtWaitForSingleObject(void*, std::vector<uint64_t>&, void* ctx);
    static uint64_t NtDelayExecution(void*, std::vector<uint64_t>&, void* ctx);

    // String / utility
    static uint64_t RtlInitUnicodeString(void*, std::vector<uint64_t>&, void* ctx);
    static uint64_t RtlInitString(void*, std::vector<uint64_t>&, void* ctx);
    static uint64_t RtlAnsiStringToUnicodeString(void*, std::vector<uint64_t>&, void* ctx);
    static uint64_t RtlFreeUnicodeString(void*, std::vector<uint64_t>&, void* ctx);
    static uint64_t RtlNtStatusToDosError(void*, std::vector<uint64_t>&, void* ctx);
    static uint64_t CsrGetProcessId(void*, std::vector<uint64_t>&, void* ctx);

    // Volume / object
    static uint64_t NtQueryVolumeInformationFile(void*, std::vector<uint64_t>&, void* ctx);
    static uint64_t NtQueryObject(void*, std::vector<uint64_t>&, void* ctx);
    static uint64_t NtDuplicateObject(void*, std::vector<uint64_t>&, void* ctx);

    // Additional ntdll APIs (from Python reference)
    static uint64_t RtlGetLastWin32Error(void*, std::vector<uint64_t>&, void* ctx);
    static uint64_t RtlFlushSecureMemoryCache(void*, std::vector<uint64_t>&, void* ctx);
    static uint64_t RtlAddVectoredExceptionHandler(void*, std::vector<uint64_t>&, void* ctx);
    static uint64_t RtlRemoveVectoredExceptionHandler(void*, std::vector<uint64_t>&, void* ctx);
    static uint64_t NtYieldExecution(void*, std::vector<uint64_t>&, void* ctx);
    static uint64_t LdrLoadDll(void*, std::vector<uint64_t>&, void* ctx);
    static uint64_t LdrGetProcedureAddress(void*, std::vector<uint64_t>&, void* ctx);
    static uint64_t LdrFindResource_U(void*, std::vector<uint64_t>&, void* ctx);
    static uint64_t LdrAccessResource(void*, std::vector<uint64_t>&, void* ctx);
    static uint64_t RtlZeroMemory(void*, std::vector<uint64_t>&, void* ctx);
    static uint64_t RtlMoveMemory(void*, std::vector<uint64_t>&, void* ctx);
    static uint64_t RtlEncodePointer(void*, std::vector<uint64_t>&, void* ctx);
    static uint64_t RtlDecodePointer(void*, std::vector<uint64_t>&, void* ctx);
    static uint64_t RtlComputeCrc32(void*, std::vector<uint64_t>&, void* ctx);
    static uint64_t RtlGetNtVersionNumbers(void*, std::vector<uint64_t>&, void* ctx);
    static uint64_t RtlGetCurrentPeb(void*, std::vector<uint64_t>&, void* ctx);
    static uint64_t RtlGetVersion(void*, std::vector<uint64_t>&, void* ctx);

    // Fallback
    static uint64_t stub_api(void*, std::vector<uint64_t>&, void* ctx);

private:
    std::vector<ApiEntry> apis_;
};

} // namespace api
} // namespace speakeasy

#endif // SPEAKEASY_NTDLL_H
