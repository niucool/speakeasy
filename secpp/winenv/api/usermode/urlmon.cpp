// urlmon.cpp — urlmon.dll handler (~2 APIs, macro-driven stubs)
#include "urlmon.h"

namespace speakeasy { namespace api {

Urlmon::Urlmon() {
    INIT_API_TABLE(Urlmon)
    REG(Urlmon, URLDownloadToFile, 5)
    REG(Urlmon, URLDownloadToCacheFile, 6)
    END_API_TABLE
}

// ── Bulk stubs ──────────────────────────────────────────────

#define URLMON_STUB(n) STUB(Urlmon, n)

URLMON_STUB(URLDownloadToFile)
URLMON_STUB(URLDownloadToCacheFile)

}} // namespaces
