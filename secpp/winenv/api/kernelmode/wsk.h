// wsk.h — Winsock Kernel API handler (STUB)
#ifndef SPEAKEASY_KERNELMODE_WSK_H
#define SPEAKEASY_KERNELMODE_WSK_H
#include <string>
#include <vector>
#include "../usermode/api_handler_base.h"

namespace speakeasy { namespace api { namespace kernelmode {

class Wsk : public ApiHandler {
    API_LIST_BEGIN
    API_ENTRY(WskRegister, 2)
    API_ENTRY(WskCaptureProviderNPI, 3)
    API_ENTRY(WskReleaseProviderNPI, 1)
    API_ENTRY(WskDeregister, 1)
    API_ENTRY(WskSocket, 11)
    API_ENTRY(WskSocketConnect, 12)
    API_ENTRY(WskControlClient, 8)
    API_ENTRY(WskGetAddressInfo, 10)
    API_ENTRY(WskFreeAddressInfo, 2)
    API_ENTRY(WskGetNameInfo, 9)
    API_ENTRY(WskControlSocket, 10)
    API_ENTRY(WskCloseSocket, 2)
    API_ENTRY(WskBind, 4)
    API_ENTRY(WskSendTo, 7)
    API_ENTRY(WskReceiveFrom, 8)
    API_ENTRY(WskRelease, 2)
    API_ENTRY(WskGetLocalAddress, 2)
    API_LIST_END
public:
    Wsk();
    std::string get_name() const override { return "wsk"; }
    const std::vector<ApiEntry>& get_apis() const override { return apis_; }
};

}}} // namespaces
#endif
