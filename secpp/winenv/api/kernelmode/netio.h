// netio.h — Network I/O API handler (STUB)
#ifndef SPEAKEASY_KERNELMODE_NETIO_H
#define SPEAKEASY_KERNELMODE_NETIO_H
#include <string>
#include <vector>
#include "../api.h"

namespace speakeasy { namespace api { namespace kernelmode {

class Netio : public ApiHandler {
    API_LIST_BEGIN
    API_ENTRY(NsiEnumerateObjectsAllParametersEx, 0)
    API_LIST_END
public:
    Netio(void* emu);
    std::string get_name() const override { return "netio"; }
    const std::vector<ApiEntry>& get_apis() const override { return apis_; }
};

}}} // namespaces
#endif
