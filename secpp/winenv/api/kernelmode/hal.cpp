// hal.cpp  Hardware Abstraction Layer handler (implemented)
#include "hal.h"

#include <cstdint>
#include <vector>
#include <string>

#include "memmgr.h"
#include "struct.h"
#include "winenv/arch.h"
#include "windows/winemu.h"

using namespace speakeasy;

namespace speakeasy { namespace api { namespace kernelmode {

//  Typed cast helpers 

Hal::Hal(void* emu) : ApiHandler(emu) {
    INIT_API_TABLE(Hal)
    REG(Hal, KeGetCurrentIrql, 0)
    REG(Hal, ExAcquireFastMutex, 1)
    REG(Hal, ExReleaseFastMutex, 1)
    END_API_TABLE
}

//  Implementations 

uint64_t Hal::KeGetCurrentIrql(void* e, ArgList& a, void* ctx) {
    // NTHALAPI KIRQL KeGetCurrentIrql();
    // Simply return PASSIVE_LEVEL (0) since we don't track IRQL in emulation
    (void)e; (void)a;
    return 0; // PASSIVE_LEVEL
}

uint64_t Hal::ExAcquireFastMutex(void* e, ArgList& a, void* ctx) {
    // VOID ExAcquireFastMutex(PFAST_MUTEX FastMutex);
    // No-op in emulation
    (void)e; (void)a;
    return 0;
}

uint64_t Hal::ExReleaseFastMutex(void* e, ArgList& a, void* ctx) {
    // VOID ExReleaseFastMutex(PFAST_MUTEX FastMutex);
    // No-op in emulation
    (void)e; (void)a;
    return 0;
}

}}} // namespaces
