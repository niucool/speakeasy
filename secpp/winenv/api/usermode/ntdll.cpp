// ntdll.cpp — ntdll.dll API handler implementation

#include "ntdll.h"

namespace speakeasy {
namespace api {

static uint64_t ok() { return 0; } // STATUS_SUCCESS

#define STUB(name) \
    uint64_t Ntdll::name(void* e, const std::string&, int, const std::vector<uint64_t>& a) { \
        (void)e; (void)a; return ok(); \
    }

Ntdll::Ntdll() {
    apis_ = {
        {"NtAllocateVirtualMemory",    6, NtAllocateVirtualMemory},
        {"NtFreeVirtualMemory",        4, NtFreeVirtualMemory},
        {"NtProtectVirtualMemory",     5, NtProtectVirtualMemory},
        {"NtQueryVirtualMemory",       6, NtQueryVirtualMemory},
        {"NtCreateFile",               11, NtCreateFile},
        {"NtReadFile",                 9, NtReadFile},
        {"NtWriteFile",                9, NtWriteFile},
        {"NtClose",                    1, NtClose},
        {"NtCreateProcess",            8, NtCreateProcess},
        {"NtCreateThread",             8, NtCreateThread},
        {"NtTerminateProcess",         2, NtTerminateProcess},
        {"NtQuerySystemInformation",   4, NtQuerySystemInformation},
        {"NtSetInformationProcess",    4, NtSetInformationProcess},
        {"NtQueryInformationProcess",  5, NtQueryInformationProcess},
        {"NtDelayExecution",           2, NtDelayExecution},
        {"NtQueryPerformanceCounter",  2, NtQueryPerformanceCounter},
        {"NtOpenKey",                  3, NtOpenKey},
        {"NtQueryValueKey",            6, NtQueryValueKey},
        {"RtlInitUnicodeString",       2, RtlInitUnicodeString},
    };
}

STUB(NtAllocateVirtualMemory)
STUB(NtFreeVirtualMemory)
STUB(NtProtectVirtualMemory)
STUB(NtQueryVirtualMemory)
STUB(NtCreateFile)
STUB(NtReadFile)
STUB(NtWriteFile)
STUB(NtClose)
STUB(NtCreateProcess)
STUB(NtCreateThread)
STUB(NtTerminateProcess)
STUB(NtQuerySystemInformation)
STUB(NtSetInformationProcess)
STUB(NtQueryInformationProcess)
STUB(NtDelayExecution)
STUB(NtQueryPerformanceCounter)
STUB(NtOpenKey)
STUB(NtQueryValueKey)
STUB(RtlInitUnicodeString)

uint64_t Ntdll::stub_api(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    (void)e; (void)a; return ok();
}

} // namespace api
} // namespace speakeasy
