// msimg32.cpp — msimg32.dll handler (stubs)
#include "msimg32.h"

namespace speakeasy { namespace api {

Msimg32::Msimg32() {
    INIT_API_TABLE(Msimg32)
    REG(Msimg32, TransparentBlt, 11)
    END_API_TABLE
}

#define STUB_MSIMG(n) STUB(Msimg32, n)

STUB_MSIMG(TransparentBlt)

}} // namespaces
