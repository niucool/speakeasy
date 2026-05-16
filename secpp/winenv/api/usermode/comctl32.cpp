// comctl32.cpp — comctl32.dll handler (STUB)
#include "comctl32.h"

namespace speakeasy { namespace api {

Comctl32::Comctl32() {
    INIT_API_TABLE(Comctl32)
    REG(Comctl32, InitCommonControlsEx, 1)
    REG(Comctl32, InitCommonControls, 0)
    END_API_TABLE
}

// ── Bulk stubs ──────────────────────────────────────────────

#define STUB(n) STUB(Comctl32, n)

STUB(InitCommonControlsEx)
STUB(InitCommonControls)

}} // namespaces
