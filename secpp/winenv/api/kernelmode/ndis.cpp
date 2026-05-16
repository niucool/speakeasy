// ndis.cpp — Network Driver Interface Specification handler (STUB)
#include "ndis.h"

namespace speakeasy { namespace api { namespace kernelmode {

Ndis::Ndis() {
    INIT_API_TABLE(Ndis)
    REG(Ndis, NdisGetVersion, 0)
    REG(Ndis, NdisGetRoutineAddress, 1)
    REG(Ndis, NdisMRegisterMiniportDriver, 5)
    REG(Ndis, NdisInitializeWrapper, 4)
    REG(Ndis, NdisTerminateWrapper, 2)
    REG(Ndis, NdisInitializeReadWriteLock, 1)
    REG(Ndis, NdisMRegisterUnloadHandler, 2)
    REG(Ndis, NdisRegisterProtocol, 4)
    REG(Ndis, NdisIMRegisterLayeredMiniport, 4)
    REG(Ndis, NdisIMAssociateMiniport, 2)
    REG(Ndis, NdisAllocateGenericObject, 3)
    REG(Ndis, NdisAllocateMemoryWithTag, 3)
    REG(Ndis, NdisAllocateNetBufferListPool, 2)
    REG(Ndis, NdisFreeNetBufferListPool, 1)
    REG(Ndis, NdisFreeMemory, 3)
    REG(Ndis, NdisFreeGenericObject, 1)
    END_API_TABLE
}

#define ND_STUB(n) KERNEL_STUB(Ndis, n)
ND_STUB(NdisGetVersion)              ND_STUB(NdisGetRoutineAddress)
ND_STUB(NdisMRegisterMiniportDriver) ND_STUB(NdisInitializeWrapper)
ND_STUB(NdisTerminateWrapper)        ND_STUB(NdisInitializeReadWriteLock)
ND_STUB(NdisMRegisterUnloadHandler)  ND_STUB(NdisRegisterProtocol)
ND_STUB(NdisIMRegisterLayeredMiniport) ND_STUB(NdisIMAssociateMiniport)
ND_STUB(NdisAllocateGenericObject)   ND_STUB(NdisAllocateMemoryWithTag)
ND_STUB(NdisAllocateNetBufferListPool) ND_STUB(NdisFreeNetBufferListPool)
ND_STUB(NdisFreeMemory)              ND_STUB(NdisFreeGenericObject)

}}} // namespaces
