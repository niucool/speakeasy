// lz32.cpp — lz32.dll handler (STUB)
#include "lz32.h"

namespace speakeasy { namespace api {

Lz32::Lz32() {
    INIT_API_TABLE(Lz32)
    REG(Lz32, LZSeek, 3)
    END_API_TABLE
}

// ── Bulk stubs ──────────────────────────────────────────────

#define LZ_STUB(n) STUB(Lz32, n)

LZ_STUB(LZSeek)

}} // namespaces
