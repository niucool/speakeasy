// ntdll.h — ntdll.dll API handler
//
// Maps to: speakeasy/winenv/api/usermode/ntdll.py

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

private:
    std::vector<ApiEntry> apis_;

    static uint64_t NtAllocateVirtualMemory(void*, const std::string&, int, const std::vector<uint64_t>&);
    static uint64_t NtFreeVirtualMemory(void*, const std::string&, int, const std::vector<uint64_t>&);
    static uint64_t NtProtectVirtualMemory(void*, const std::string&, int, const std::vector<uint64_t>&);
    static uint64_t NtQueryVirtualMemory(void*, const std::string&, int, const std::vector<uint64_t>&);
    static uint64_t NtCreateFile(void*, const std::string&, int, const std::vector<uint64_t>&);
    static uint64_t NtReadFile(void*, const std::string&, int, const std::vector<uint64_t>&);
    static uint64_t NtWriteFile(void*, const std::string&, int, const std::vector<uint64_t>&);
    static uint64_t NtClose(void*, const std::string&, int, const std::vector<uint64_t>&);
    static uint64_t NtCreateProcess(void*, const std::string&, int, const std::vector<uint64_t>&);
    static uint64_t NtCreateThread(void*, const std::string&, int, const std::vector<uint64_t>&);
    static uint64_t NtTerminateProcess(void*, const std::string&, int, const std::vector<uint64_t>&);
    static uint64_t NtQuerySystemInformation(void*, const std::string&, int, const std::vector<uint64_t>&);
    static uint64_t NtSetInformationProcess(void*, const std::string&, int, const std::vector<uint64_t>&);
    static uint64_t NtQueryInformationProcess(void*, const std::string&, int, const std::vector<uint64_t>&);
    static uint64_t NtDelayExecution(void*, const std::string&, int, const std::vector<uint64_t>&);
    static uint64_t NtQueryPerformanceCounter(void*, const std::string&, int, const std::vector<uint64_t>&);
    static uint64_t NtOpenKey(void*, const std::string&, int, const std::vector<uint64_t>&);
    static uint64_t NtQueryValueKey(void*, const std::string&, int, const std::vector<uint64_t>&);
    static uint64_t RtlInitUnicodeString(void*, const std::string&, int, const std::vector<uint64_t>&);
    static uint64_t stub_api(void*, const std::string&, int, const std::vector<uint64_t>&);
};

} // namespace api
} // namespace speakeasy

#endif
