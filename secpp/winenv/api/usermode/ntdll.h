// ntdll.h  ntdll.dll API handler
//
// Maps to: speakeasy/winenv/api/usermode/ntdll.py
//
// Implements exported native functions from ntdll.dll. If a function is not supported
// here, but is supported in the ntoskrnl handler (e.g. NtCreateFile) it will be handled by
// the kernel export handler.
//
// Registered APIs (21, matching Python ntdll.py):
//   RtlGetLastWin32Error, RtlNtStatusToDosError, RtlFlushSecureMemoryCache,
//   RtlAddVectoredExceptionHandler, NtYieldExecution, RtlRemoveVectoredExceptionHandler,
//   LdrLoadDll, LdrGetProcedureAddress, RtlZeroMemory, RtlMoveMemory,
//   NtSetInformationProcess, RtlEncodePointer, RtlDecodePointer,
//   NtWaitForSingleObject, RtlComputeCrc32, LdrFindResource_U,
//   NtUnmapViewOfSection, LdrAccessResource, RtlGetNtVersionNumbers,
//   RtlGetCurrentPeb, RtlGetVersion

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

    // Exactly matches Python ntdll.py's 21 @apihook registrations
    static uint64_t RtlGetLastWin32Error(void*, ArgList&, void* ctx);
    static uint64_t RtlNtStatusToDosError(void*, ArgList&, void* ctx);
    static uint64_t RtlFlushSecureMemoryCache(void*, ArgList&, void* ctx);
    static uint64_t RtlAddVectoredExceptionHandler(void*, ArgList&, void* ctx);
    static uint64_t NtYieldExecution(void*, ArgList&, void* ctx);
    static uint64_t RtlRemoveVectoredExceptionHandler(void*, ArgList&, void* ctx);
    static uint64_t LdrLoadDll(void*, ArgList&, void* ctx);
    static uint64_t LdrGetProcedureAddress(void*, ArgList&, void* ctx);
    static uint64_t RtlZeroMemory(void*, ArgList&, void* ctx);
    static uint64_t RtlMoveMemory(void*, ArgList&, void* ctx);
    static uint64_t NtSetInformationProcess(void*, ArgList&, void* ctx);
    static uint64_t RtlEncodePointer(void*, ArgList&, void* ctx);
    static uint64_t RtlDecodePointer(void*, ArgList&, void* ctx);
    static uint64_t NtWaitForSingleObject(void*, ArgList&, void* ctx);
    static uint64_t RtlComputeCrc32(void*, ArgList&, void* ctx);
    static uint64_t LdrFindResource_U(void*, ArgList&, void* ctx);
    static uint64_t NtUnmapViewOfSection(void*, ArgList&, void* ctx);
    static uint64_t LdrAccessResource(void*, ArgList&, void* ctx);
    static uint64_t RtlGetNtVersionNumbers(void*, ArgList&, void* ctx);
    static uint64_t RtlGetCurrentPeb(void*, ArgList&, void* ctx);
    static uint64_t RtlGetVersion(void*, ArgList&, void* ctx);

    // Fallback for unregistered ntdll exports  handled by ntoskrnl
    static uint64_t stub_api(void*, ArgList&, void* ctx);

private:
    std::vector<ApiEntry> apis_;
};

} // namespace api
} // namespace speakeasy

#endif // SPEAKEASY_NTDLL_H
