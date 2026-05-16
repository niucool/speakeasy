// ole32.cpp — ole32.dll handler (v2 — OLE32 stubs)
#include "ole32.h"

namespace speakeasy { namespace api {

Ole32::Ole32() {
    INIT_API_TABLE(Ole32)
    REG(Ole32, CoInitialize, 1)         REG(Ole32, CoUninitialize, 0)
    REG(Ole32, CoCreateInstance, 5)     REG(Ole32, CoGetClassObject, 4)
    REG(Ole32, CoTaskMemAlloc, 1)       REG(Ole32, CoTaskMemFree, 1)
    REG(Ole32, CLSIDFromString, 2)      REG(Ole32, StringFromGUID2, 3)
    REG(Ole32, ProgIDFromCLSID, 2)      REG(Ole32, CLSIDFromProgID, 2)
    REG(Ole32, OleInitialize, 1)        REG(Ole32, OleUninitialize, 0)
    REG(Ole32, OleSetClipboard, 1)      REG(Ole32, OleGetClipboard, 1)
    REG(Ole32, OleFlushClipboard, 0)    REG(Ole32, OleIsCurrentClipboard, 1)
    REG(Ole32, CreateBindCtx, 2)        REG(Ole32, BindMoniker, 4)
    REG(Ole32, MkParseDisplayName, 4)
    END_API_TABLE
}

// ── Bulk stubs ──────────────────────────────────────────────

#define OLE32_STUB(n) STUB(Ole32, n)

OLE32_STUB(CoInitialize)
OLE32_STUB(CoUninitialize)
OLE32_STUB(CoCreateInstance)
OLE32_STUB(CoGetClassObject)
OLE32_STUB(CoTaskMemAlloc)
OLE32_STUB(CoTaskMemFree)
OLE32_STUB(CLSIDFromString)
OLE32_STUB(StringFromGUID2)
OLE32_STUB(ProgIDFromCLSID)
OLE32_STUB(CLSIDFromProgID)
OLE32_STUB(OleInitialize)
OLE32_STUB(OleUninitialize)
OLE32_STUB(OleSetClipboard)
OLE32_STUB(OleGetClipboard)
OLE32_STUB(OleFlushClipboard)
OLE32_STUB(OleIsCurrentClipboard)
OLE32_STUB(CreateBindCtx)
OLE32_STUB(BindMoniker)
OLE32_STUB(MkParseDisplayName)

}} // namespaces
