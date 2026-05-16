// advpack.cpp — advpack.dll handler (STUB)
#include "advpack.h"

namespace speakeasy { namespace api {

Advpack::Advpack() {
    INIT_API_TABLE(Advpack)
    REG(Advpack, IsNTAdmin, 2)
    END_API_TABLE
}

// ── Bulk stubs ──────────────────────────────────────────────

#define ADVP_STUB(n) STUB(Advpack, n)

ADVP_STUB(IsNTAdmin)

}} // namespaces
