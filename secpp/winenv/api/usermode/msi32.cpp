// msi32.cpp — msi32.dll handler (stubs)
#include "msi32.h"

namespace speakeasy { namespace api {

Msi32::Msi32() {
    INIT_API_TABLE(Msi32)
    REG(Msi32, MsiDatabaseMergeA, 3)
    END_API_TABLE
}

#define STUB_MSI(n) STUB(Msi32, n)

STUB_MSI(MsiDatabaseMergeA)

}} // namespaces
