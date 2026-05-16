// ntdll.h — ntdll.dll API handler
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
#include "api_handler_base.h"

namespace speakeasy {
namespace api {

class Ntdll : public ApiHandler {
public:
    Ntdll();
    std::string get_name() const override { return "ntdll"; }
    const std::vector<ApiEntry>& get_apis() const override { return apis_; }

    // Heap
    static uint64_t RtlAllocateHeap(void*, const std::string&, int, const std::vector<uint64_t>&);
    static uint64_t RtlFreeHeap(void*, const std::string&, int, const std::vector<uint64_t>&);
    static uint64_t RtlReAllocateHeap(void*, const std::string&, int, const std::vector<uint64_t>&);
    static uint64_t RtlCreateHeap(void*, const std::string&, int, const std::vector<uint64_t>&);
    static uint64_t RtlDestroyHeap(void*, const std::string&, int, const std::vector<uint64_t>&);
    static uint64_t RtlGetProcessHeap(void*, const std::string&, int, const std::vector<uint64_t>&);

    // Virtual memory
    static uint64_t NtAllocateVirtualMemory(void*, const std::string&, int, const std::vector<uint64_t>&);
    static uint64_t NtFreeVirtualMemory(void*, const std::string&, int, const std::vector<uint64_t>&);
    static uint64_t NtProtectVirtualMemory(void*, const std::string&, int, const std::vector<uint64_t>&);
    static uint64_t NtQueryVirtualMemory(void*, const std::string&, int, const std::vector<uint64_t>&);

    // File I/O
    static uint64_t NtCreateFile(void*, const std::string&, int, const std::vector<uint64_t>&);
    static uint64_t NtOpenFile(void*, const std::string&, int, const std::vector<uint64_t>&);
    static uint64_t NtReadFile(void*, const std::string&, int, const std::vector<uint64_t>&);
    static uint64_t NtWriteFile(void*, const std::string&, int, const std::vector<uint64_t>&);
    static uint64_t NtClose(void*, const std::string&, int, const std::vector<uint64_t>&);
    static uint64_t NtDeviceIoControlFile(void*, const std::string&, int, const std::vector<uint64_t>&);

    // Process / thread
    static uint64_t NtCreateProcess(void*, const std::string&, int, const std::vector<uint64_t>&);
    static uint64_t NtCreateThread(void*, const std::string&, int, const std::vector<uint64_t>&);
    static uint64_t NtOpenThread(void*, const std::string&, int, const std::vector<uint64_t>&);
    static uint64_t NtTerminateProcess(void*, const std::string&, int, const std::vector<uint64_t>&);
    static uint64_t NtTerminateThread(void*, const std::string&, int, const std::vector<uint64_t>&);
    static uint64_t NtGetContextThread(void*, const std::string&, int, const std::vector<uint64_t>&);
    static uint64_t NtSetContextThread(void*, const std::string&, int, const std::vector<uint64_t>&);

    // System info
    static uint64_t NtQuerySystemInformation(void*, const std::string&, int, const std::vector<uint64_t>&);
    static uint64_t NtQueryInformationProcess(void*, const std::string&, int, const std::vector<uint64_t>&);
    static uint64_t NtSetInformationProcess(void*, const std::string&, int, const std::vector<uint64_t>&);

    // Registry
    static uint64_t NtCreateKey(void*, const std::string&, int, const std::vector<uint64_t>&);
    static uint64_t NtOpenKey(void*, const std::string&, int, const std::vector<uint64_t>&);
    static uint64_t NtQueryValueKey(void*, const std::string&, int, const std::vector<uint64_t>&);
    static uint64_t NtSetValueKey(void*, const std::string&, int, const std::vector<uint64_t>&);
    static uint64_t NtDeleteKey(void*, const std::string&, int, const std::vector<uint64_t>&);
    static uint64_t NtDeleteValueKey(void*, const std::string&, int, const std::vector<uint64_t>&);

    // Sections (memory-mapped files)
    static uint64_t NtCreateSection(void*, const std::string&, int, const std::vector<uint64_t>&);
    static uint64_t NtOpenSection(void*, const std::string&, int, const std::vector<uint64_t>&);
    static uint64_t NtMapViewOfSection(void*, const std::string&, int, const std::vector<uint64_t>&);
    static uint64_t NtUnmapViewOfSection(void*, const std::string&, int, const std::vector<uint64_t>&);

    // Synchronization
    static uint64_t NtCreateEvent(void*, const std::string&, int, const std::vector<uint64_t>&);
    static uint64_t NtOpenEvent(void*, const std::string&, int, const std::vector<uint64_t>&);
    static uint64_t NtCreateMutant(void*, const std::string&, int, const std::vector<uint64_t>&);
    static uint64_t NtOpenMutant(void*, const std::string&, int, const std::vector<uint64_t>&);
    static uint64_t NtWaitForSingleObject(void*, const std::string&, int, const std::vector<uint64_t>&);
    static uint64_t NtDelayExecution(void*, const std::string&, int, const std::vector<uint64_t>&);

    // String / utility
    static uint64_t RtlInitUnicodeString(void*, const std::string&, int, const std::vector<uint64_t>&);
    static uint64_t RtlInitString(void*, const std::string&, int, const std::vector<uint64_t>&);
    static uint64_t RtlAnsiStringToUnicodeString(void*, const std::string&, int, const std::vector<uint64_t>&);
    static uint64_t RtlFreeUnicodeString(void*, const std::string&, int, const std::vector<uint64_t>&);
    static uint64_t RtlNtStatusToDosError(void*, const std::string&, int, const std::vector<uint64_t>&);
    static uint64_t CsrGetProcessId(void*, const std::string&, int, const std::vector<uint64_t>&);

    // Volume / object
    static uint64_t NtQueryVolumeInformationFile(void*, const std::string&, int, const std::vector<uint64_t>&);
    static uint64_t NtQueryObject(void*, const std::string&, int, const std::vector<uint64_t>&);
    static uint64_t NtDuplicateObject(void*, const std::string&, int, const std::vector<uint64_t>&);

    // Additional ntdll APIs (from Python reference)
    static uint64_t RtlGetLastWin32Error(void*, const std::string&, int, const std::vector<uint64_t>&);
    static uint64_t RtlFlushSecureMemoryCache(void*, const std::string&, int, const std::vector<uint64_t>&);
    static uint64_t RtlAddVectoredExceptionHandler(void*, const std::string&, int, const std::vector<uint64_t>&);
    static uint64_t RtlRemoveVectoredExceptionHandler(void*, const std::string&, int, const std::vector<uint64_t>&);
    static uint64_t NtYieldExecution(void*, const std::string&, int, const std::vector<uint64_t>&);
    static uint64_t LdrLoadDll(void*, const std::string&, int, const std::vector<uint64_t>&);
    static uint64_t LdrGetProcedureAddress(void*, const std::string&, int, const std::vector<uint64_t>&);
    static uint64_t LdrFindResource_U(void*, const std::string&, int, const std::vector<uint64_t>&);
    static uint64_t LdrAccessResource(void*, const std::string&, int, const std::vector<uint64_t>&);
    static uint64_t RtlZeroMemory(void*, const std::string&, int, const std::vector<uint64_t>&);
    static uint64_t RtlMoveMemory(void*, const std::string&, int, const std::vector<uint64_t>&);
    static uint64_t RtlEncodePointer(void*, const std::string&, int, const std::vector<uint64_t>&);
    static uint64_t RtlDecodePointer(void*, const std::string&, int, const std::vector<uint64_t>&);
    static uint64_t RtlComputeCrc32(void*, const std::string&, int, const std::vector<uint64_t>&);
    static uint64_t RtlGetNtVersionNumbers(void*, const std::string&, int, const std::vector<uint64_t>&);
    static uint64_t RtlGetCurrentPeb(void*, const std::string&, int, const std::vector<uint64_t>&);
    static uint64_t RtlGetVersion(void*, const std::string&, int, const std::vector<uint64_t>&);

    // Fallback
    static uint64_t stub_api(void*, const std::string&, int, const std::vector<uint64_t>&);

private:
    std::vector<ApiEntry> apis_;
};

} // namespace api
} // namespace speakeasy

#endif // SPEAKEASY_NTDLL_H
