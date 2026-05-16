// mpr.h — mpr.dll API handler (v2 — macro-based registration)
#ifndef SPEAKEASY_MPR_H
#define SPEAKEASY_MPR_H
#include <string>
#include <vector>
#include "api_handler_base.h"

namespace speakeasy { namespace api {

class Mpr : public ApiHandler {
    API_LIST_BEGIN
    API_ENTRY(WNetOpenEnum, 5)
    API_ENTRY(WNetEnumResource, 4)
    API_ENTRY(WNetAddConnection2, 4)
    API_ENTRY(WNetGetConnection, 3)
    API_LIST_END

public:
    Mpr();
    std::string get_name() const override { return "mpr"; }
    const std::vector<ApiEntry>& get_apis() const override { return apis_; }
};

}} // namespaces
#endif
