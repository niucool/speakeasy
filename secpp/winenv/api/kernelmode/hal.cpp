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
static inline WindowsEmulator* we(void* e) { return static_cast<WindowsEmulator*>(e); }
static inline BinaryEmulator* be(void* e) { return static_cast<BinaryEmulator*>(e); }
static inline MemoryManager* mm(void* e) { return static_cast<MemoryManager*>(e); }

Hal::Hal(void* emu) : ApiHandler(emu) {
    INIT_API_TABLE(Hal)
    REG(Hal, KeGetCurrentIrql, 0)
    REG(Hal, ExAcquireFastMutex, 1)
    REG(Hal, ExReleaseFastMutex, 1)
    END_API_TABLE
}

//  Implementations 

uint64_t Hal::KeGetCurrentIrql(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // NTHALAPI KIRQL KeGetCurrentIrql();
    // Simply return PASSIVE_LEVEL (0) since we don't track IRQL in emulation
    (void)e; (void)a;
    return 0; // PASSIVE_LEVEL
}

uint64_t Hal::ExAcquireFastMutex(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // VOID ExAcquireFastMutex(PFAST_MUTEX FastMutex);
    // No-op in emulation
    (void)e; (void)a;
    return 0;
}

uint64_t Hal::ExReleaseFastMutex(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // VOID ExReleaseFastMutex(PFAST_MUTEX FastMutex);
    // No-op in emulation
    (void)e; (void)a;
    return 0;
}

}}} // namespaces
