// sfc_os.h — sfc_os.dll API handler (same APIs as sfc, separate module name)
#ifndef SPEAKEASY_SFC_OS_H
#define SPEAKEASY_SFC_OS_H
#include <string>
#include <vector>
#include "../api.h"

namespace speakeasy { namespace api {

class Sfc_os : public ApiHandler {
    API_LIST_BEGIN
    API_ENTRY(SfcIsFileProtected, 2)    API_ENTRY(SfcTerminateWatcherThread, 0)
    API_LIST_END
public:
    Sfc_os(void* emu);
    std::string get_name() const override { return "sfc_os"; }
    const std::vector<ApiEntry>& get_apis() const override { return apis_; }
};

}} // namespaces
#endif
