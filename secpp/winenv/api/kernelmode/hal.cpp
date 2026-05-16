// hal.cpp — Hardware Abstraction Layer handler (STUB)
#include "hal.h"

namespace speakeasy { namespace api { namespace kernelmode {

Hal::Hal() {
    INIT_API_TABLE(Hal)
    REG(Hal, KeGetCurrentIrql, 0)
    REG(Hal, ExAcquireFastMutex, 1)
    REG(Hal, ExReleaseFastMutex, 1)
    END_API_TABLE
}

#define H_STUB(n) KERNEL_STUB(Hal, n)
H_STUB(KeGetCurrentIrql)  H_STUB(ExAcquireFastMutex)  H_STUB(ExReleaseFastMutex)

}}} // namespaces
