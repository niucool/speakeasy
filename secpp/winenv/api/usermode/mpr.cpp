// mpr.cpp — mpr.dll handler (STUB)
#include "mpr.h"

namespace speakeasy { namespace api {

Mpr::Mpr() {
    INIT_API_TABLE(Mpr)
    REG(Mpr, WNetOpenEnum, 5)
    REG(Mpr, WNetEnumResource, 4)
    REG(Mpr, WNetAddConnection2, 4)
    REG(Mpr, WNetGetConnection, 3)
    END_API_TABLE
}

// ── Bulk stubs ──────────────────────────────────────────────

#define STUB(n) STUB(Mpr, n)

STUB(WNetOpenEnum)
STUB(WNetEnumResource)
STUB(WNetAddConnection2)
STUB(WNetGetConnection)

}} // namespaces
