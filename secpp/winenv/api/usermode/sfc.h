// sfc.h  sfc.dll API handler
#ifndef SPEAKEASY_SFC_H
#define SPEAKEASY_SFC_H
#include <string>
#include <vector>
#include "../api.h"

namespace speakeasy { namespace api {

class Sfc : public ApiHandler {
    API_LIST_BEGIN
    API_ENTRY(SfcIsFileProtected, 2)
    API_ENTRY(SfcTerminateWatcherThread, 0)
    API_LIST_END

public:
    Sfc(void* emu);
    std::string get_name() const override { return "sfc"; }
    const std::vector<ApiEntry>& get_apis() const override { return apis_; }
};

}} // namespaces
#endif
