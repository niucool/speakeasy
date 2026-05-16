// sfc_os.cpp — sfc_os.dll handler (stubs, inherits sfc APIs)
#include "sfc_os.h"

namespace speakeasy { namespace api {

Sfc_os::Sfc_os() : ApiHandler() {
    INIT_API_TABLE(Sfc_os)
    REG(Sfc_os, SfcIsFileProtected, 2)  REG(Sfc_os, SfcTerminateWatcherThread, 0)
    END_API_TABLE
}

// ── Bulk stubs ──────────────────────────────────────────────

#define SFCOS_STUB(n) STUB(Sfc_os, n)

SFCOS_STUB(SfcIsFileProtected)
SFCOS_STUB(SfcTerminateWatcherThread)

}} // namespaces
