// com_api.cpp — COM API handler (~5 APIs, macro-driven stubs)
#include "com_api.h"

namespace speakeasy { namespace api {

ComApi::ComApi() {
    INIT_API_TABLE(ComApi)
    REG(ComApi, IUnknown_QueryInterface, 3)
    REG(ComApi, IUnknown_AddRef, 1)
    REG(ComApi, IUnknown_Release, 1)
    REG(ComApi, IWbemLocator_ConnectServer, 9)
    REG(ComApi, IWbemServices_ExecQuery, 6)
    END_API_TABLE
}

// ── Bulk stubs ──────────────────────────────────────────────

#define COMAPI_STUB(n) STUB(ComApi, n)

COMAPI_STUB(IUnknown_QueryInterface)
COMAPI_STUB(IUnknown_AddRef)
COMAPI_STUB(IUnknown_Release)
COMAPI_STUB(IWbemLocator_ConnectServer)
COMAPI_STUB(IWbemServices_ExecQuery)

}} // namespaces
