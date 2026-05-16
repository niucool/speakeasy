// sfc.cpp — sfc.dll handler (stubs)
#include "sfc.h"

namespace speakeasy { namespace api {

Sfc::Sfc() {
    INIT_API_TABLE(Sfc)
    REG(Sfc, SfcIsFileProtected, 2)
    REG(Sfc, SfcTerminateWatcherThread, 0)
    END_API_TABLE
}

#define STUB_SFC(n) STUB(Sfc, n)

STUB_SFC(SfcIsFileProtected)
STUB_SFC(SfcTerminateWatcherThread)

}} // namespaces
