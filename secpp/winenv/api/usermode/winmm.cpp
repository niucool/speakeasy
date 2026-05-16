// winmm.cpp — winmm.dll handler (~3 APIs, macro-driven stubs)
#include "winmm.h"

namespace speakeasy { namespace api {

Winmm::Winmm() {
    INIT_API_TABLE(Winmm)
    REG(Winmm, timeBeginPeriod, 1)
    REG(Winmm, timeEndPeriod, 1)
    REG(Winmm, timeGetTime, 0)
    END_API_TABLE
}

// ── Bulk stubs ──────────────────────────────────────────────

#define WINMM_STUB(n) STUB(Winmm, n)

WINMM_STUB(timeBeginPeriod)
WINMM_STUB(timeEndPeriod)
WINMM_STUB(timeGetTime)

}} // namespaces
