// ncrypt.cpp — ncrypt.dll handler (~4 APIs, macro-driven stubs)
#include "ncrypt.h"

namespace speakeasy { namespace api {

Ncrypt::Ncrypt() {
    INIT_API_TABLE(Ncrypt)
    REG(Ncrypt, NCryptOpenStorageProvider, 3)
    REG(Ncrypt, NCryptImportKey, 8)
    REG(Ncrypt, NCryptDeleteKey, 2)
    REG(Ncrypt, NCryptFreeObject, 1)
    END_API_TABLE
}

// ── Bulk stubs ──────────────────────────────────────────────

#define NCRYPT_STUB(n) STUB(Ncrypt, n)

NCRYPT_STUB(NCryptOpenStorageProvider)
NCRYPT_STUB(NCryptImportKey)
NCRYPT_STUB(NCryptDeleteKey)
NCRYPT_STUB(NCryptFreeObject)

}} // namespaces
