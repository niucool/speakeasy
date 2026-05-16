// psapi.cpp — psapi.dll handler (v2 — PSAPI stubs)
#include "psapi.h"

namespace speakeasy { namespace api {

Psapi::Psapi() {
    INIT_API_TABLE(Psapi)
    REG(Psapi, EnumProcesses, 3)        REG(Psapi, EnumProcessModules, 4)
    REG(Psapi, GetModuleBaseName, 4)    REG(Psapi, GetModuleBaseNameA, 4)
    REG(Psapi, GetModuleBaseNameW, 4)   REG(Psapi, GetModuleFileNameEx, 4)
    REG(Psapi, GetModuleFileNameExA, 4) REG(Psapi, GetModuleFileNameExW, 4)
    END_API_TABLE
}

// ── Bulk stubs ──────────────────────────────────────────────

#define PSAPI_STUB(n) STUB(Psapi, n)

PSAPI_STUB(EnumProcesses)
PSAPI_STUB(EnumProcessModules)
PSAPI_STUB(GetModuleBaseName)
PSAPI_STUB(GetModuleBaseNameA)
PSAPI_STUB(GetModuleBaseNameW)
PSAPI_STUB(GetModuleFileNameEx)
PSAPI_STUB(GetModuleFileNameExA)
PSAPI_STUB(GetModuleFileNameExW)

}} // namespaces
