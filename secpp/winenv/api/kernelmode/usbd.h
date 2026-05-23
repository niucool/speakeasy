// usbd.h — USB Driver API handler (STUB)
#ifndef SPEAKEASY_KERNELMODE_USBD_H
#define SPEAKEASY_KERNELMODE_USBD_H
#include <string>
#include <vector>
#include "../api.h"

namespace speakeasy { namespace api { namespace kernelmode {

class Usbd : public ApiHandler {
    API_LIST_BEGIN
    API_ENTRY(USBD_ValidateConfigurationDescriptor, 5)
    API_LIST_END
public:
    Usbd(void* emu);
    std::string get_name() const override { return "usbd"; }
    const std::vector<ApiEntry>& get_apis() const override { return apis_; }
};

}}} // namespaces
#endif
