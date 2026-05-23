// hal.h — Hardware Abstraction Layer API handler (STUB)
#ifndef SPEAKEASY_KERNELMODE_HAL_H
#define SPEAKEASY_KERNELMODE_HAL_H
#include <string>
#include <vector>
#include "../api.h"

namespace speakeasy { namespace api { namespace kernelmode {

class Hal : public ApiHandler {
    API_LIST_BEGIN
    API_ENTRY(KeGetCurrentIrql, 0)
    API_ENTRY(ExAcquireFastMutex, 1)
    API_ENTRY(ExReleaseFastMutex, 1)
    API_LIST_END
public:
    Hal(void* emu);
    std::string get_name() const override { return "hal"; }
    const std::vector<ApiEntry>& get_apis() const override { return apis_; }
};

}}} // namespaces
#endif
