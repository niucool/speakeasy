// bcryptprimitives.cpp — bcryptprimitives.dll handler (stubs)
#include "bcryptprimitives.h"

namespace speakeasy { namespace api {

Bcryptprimitives::Bcryptprimitives() {
    INIT_API_TABLE(Bcryptprimitives)
    REG(Bcryptprimitives, ProcessPrng, 2)
    END_API_TABLE
}

#define STUB_BCRP(n) STUB(Bcryptprimitives, n)

STUB_BCRP(ProcessPrng)

}} // namespaces
