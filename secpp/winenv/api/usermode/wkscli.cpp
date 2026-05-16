// wkscli.cpp — wkscli.dll handler (STUB)
#include "wkscli.h"

namespace speakeasy { namespace api {

Wkscli::Wkscli() {
    INIT_API_TABLE(Wkscli)
    REG(Wkscli, NetGetJoinInformation, 3)
    END_API_TABLE
}

// ── Bulk stubs ──────────────────────────────────────────────

#define WKS_STUB(n) STUB(Wkscli, n)

WKS_STUB(NetGetJoinInformation)

}} // namespaces
