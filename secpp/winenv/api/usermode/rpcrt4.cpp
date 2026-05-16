// rpcrt4.cpp — rpcrt4.dll handler (stubs)
#include "rpcrt4.h"

namespace speakeasy { namespace api {

Rpcrt4::Rpcrt4() {
    INIT_API_TABLE(Rpcrt4)
    REG(Rpcrt4, UuidCreate, 1)
    REG(Rpcrt4, UuidToStringA, 2)
    END_API_TABLE
}

#define STUB_RPC(n) STUB(Rpcrt4, n)

STUB_RPC(UuidCreate)
STUB_RPC(UuidToStringA)

}} // namespaces
