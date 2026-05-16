// ndis.h — Network Driver Interface Specification API handler (STUB)
#ifndef SPEAKEASY_KERNELMODE_NDIS_H
#define SPEAKEASY_KERNELMODE_NDIS_H
#include <string>
#include <vector>
#include "../usermode/api_handler_base.h"

namespace speakeasy { namespace api { namespace kernelmode {

class Ndis : public ApiHandler {
    API_LIST_BEGIN
    API_ENTRY(NdisGetVersion, 0)
    API_ENTRY(NdisGetRoutineAddress, 1)
    API_ENTRY(NdisMRegisterMiniportDriver, 5)
    API_ENTRY(NdisInitializeWrapper, 4)
    API_ENTRY(NdisTerminateWrapper, 2)
    API_ENTRY(NdisInitializeReadWriteLock, 1)
    API_ENTRY(NdisMRegisterUnloadHandler, 2)
    API_ENTRY(NdisRegisterProtocol, 4)
    API_ENTRY(NdisIMRegisterLayeredMiniport, 4)
    API_ENTRY(NdisIMAssociateMiniport, 2)
    API_ENTRY(NdisAllocateGenericObject, 3)
    API_ENTRY(NdisAllocateMemoryWithTag, 3)
    API_ENTRY(NdisAllocateNetBufferListPool, 2)
    API_ENTRY(NdisFreeNetBufferListPool, 1)
    API_ENTRY(NdisFreeMemory, 3)
    API_ENTRY(NdisFreeGenericObject, 1)
    API_LIST_END
public:
    Ndis();
    std::string get_name() const override { return "ndis"; }
    const std::vector<ApiEntry>& get_apis() const override { return apis_; }
};

}}} // namespaces
#endif
