// wtsapi32.cpp — wtsapi32.dll handler (~2 APIs, macro-driven stubs)
#include "wtsapi32.h"

namespace speakeasy { namespace api {

Wtsapi32::Wtsapi32() {
    INIT_API_TABLE(Wtsapi32)
    REG(Wtsapi32, WTSEnumerateSessions, 5)
    REG(Wtsapi32, WTSFreeMemory, 1)
    END_API_TABLE
}

// ── Bulk stubs ──────────────────────────────────────────────

#define WTSAPI32_STUB(n) STUB(Wtsapi32, n)

WTSAPI32_STUB(WTSEnumerateSessions)
WTSAPI32_STUB(WTSFreeMemory)

}} // namespaces
