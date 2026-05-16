// netio.cpp — Network I/O handler (STUB)
#include "netio.h"

namespace speakeasy { namespace api { namespace kernelmode {

Netio::Netio() {
    INIT_API_TABLE(Netio)
    REG(Netio, NsiEnumerateObjectsAllParametersEx, 0)
    END_API_TABLE
}

#define NI_STUB(n) KERNEL_STUB(Netio, n)
NI_STUB(NsiEnumerateObjectsAllParametersEx)

}}} // namespaces
