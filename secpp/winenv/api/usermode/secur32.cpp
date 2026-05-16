// secur32.cpp — secur32.dll handler (~2 APIs, macro-driven stubs)
#include "secur32.h"

namespace speakeasy { namespace api {

Secur32::Secur32() {
    INIT_API_TABLE(Secur32)
    REG(Secur32, GetUserNameEx, 3)
    REG(Secur32, EncryptMessage, 4)
    END_API_TABLE
}

// ── Bulk stubs ──────────────────────────────────────────────

#define SECUR32_STUB(n) STUB(Secur32, n)

SECUR32_STUB(GetUserNameEx)
SECUR32_STUB(EncryptMessage)

}} // namespaces
