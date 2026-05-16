// fwpkclnt.h — Windows Filtering Platform API handler (STUB)
#ifndef SPEAKEASY_KERNELMODE_FWPKCLNT_H
#define SPEAKEASY_KERNELMODE_FWPKCLNT_H
#include <string>
#include <vector>
#include "../usermode/api_handler_base.h"

namespace speakeasy { namespace api { namespace kernelmode {

class Fwpkclnt : public ApiHandler {
    API_LIST_BEGIN
    API_ENTRY(FwpmEngineOpen0, 5)
    API_ENTRY(FwpmEngineClose0, 1)
    API_ENTRY(FwpmSubLayerAdd0, 3)
    API_ENTRY(FwpmSubLayerDeleteByKey0, 2)
    API_ENTRY(FwpmCalloutAdd0, 4)
    API_ENTRY(FwpmCalloutDeleteById0, 2)
    API_ENTRY(FwpmFilterAdd0, 4)
    API_ENTRY(FwpmFilterDeleteById0, 2)
    API_ENTRY(FwpsCalloutRegister1, 3)
    API_ENTRY(FwpsCalloutUnregisterById0, 1)
    API_ENTRY(FwpsInjectionHandleCreate0, 3)
    API_ENTRY(FwpsInjectionHandleDestroy0, 1)
    API_LIST_END
public:
    Fwpkclnt();
    std::string get_name() const override { return "fwpkclnt"; }
    const std::vector<ApiEntry>& get_apis() const override { return apis_; }
};

}}} // namespaces
#endif
