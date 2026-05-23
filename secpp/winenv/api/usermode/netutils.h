// netutils.h — netutils.dll API handler (v2 — macro-based registration)
#ifndef SPEAKEASY_NETUTILS_H
#define SPEAKEASY_NETUTILS_H
#include <string>
#include <vector>
#include "../api.h"

namespace speakeasy { namespace api {

class NetUtils : public ApiHandler {
    API_LIST_BEGIN
    API_ENTRY(NetApiBufferFree, 1)
    API_LIST_END

public:
    NetUtils(void* emu);
    std::string get_name() const override { return "netutils"; }
    const std::vector<ApiEntry>& get_apis() const override { return apis_; }
};

}} // namespaces
#endif
