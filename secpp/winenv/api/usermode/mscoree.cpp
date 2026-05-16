// mscoree.cpp — mscoree.dll handler (stubs)
#include "mscoree.h"

namespace speakeasy { namespace api {

Mscoree::Mscoree() {
    INIT_API_TABLE(Mscoree)
    REG(Mscoree, CorExitProcess, 1)
    END_API_TABLE
}

#define STUB_MSC(n) STUB(Mscoree, n)

STUB_MSC(CorExitProcess)

}} // namespaces
