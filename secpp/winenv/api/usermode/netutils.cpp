// netutils.cpp — netutils.dll handler (STUB)
#include "netutils.h"

namespace speakeasy { namespace api {

NetUtils::NetUtils() {
    INIT_API_TABLE(NetUtils)
    REG(NetUtils, NetApiBufferFree, 1)
    END_API_TABLE
}

// ── Bulk stubs ──────────────────────────────────────────────

#define STUB(n) STUB(NetUtils, n)

STUB(NetApiBufferFree)

}} // namespaces
