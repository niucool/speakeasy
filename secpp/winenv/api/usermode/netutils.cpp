// netutils.cpp — netutils.dll handler (STUB)
#include "netutils.h"

namespace speakeasy { namespace api {

NetUtils::NetUtils() {
    INIT_API_TABLE(NetUtils)
    REG(NetUtils, NetApiBufferFree, 1)
    END_API_TABLE
}

// ── Bulk stubs ──────────────────────────────────────────────

#define NETU_STUB(n) STUB(NetUtils, n)

NETU_STUB(NetApiBufferFree)

}} // namespaces
