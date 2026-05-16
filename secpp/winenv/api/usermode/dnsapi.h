// dnsapi.h — dnsapi.dll API handler (v2 — macro-based registration)
#ifndef SPEAKEASY_DNSAPI_H
#define SPEAKEASY_DNSAPI_H
#include <string>
#include <vector>
#include "api_handler_base.h"

namespace speakeasy { namespace api {

class DnsApi : public ApiHandler {
    API_LIST_BEGIN
    API_ENTRY(DnsQuery_, 6)
    API_LIST_END

public:
    DnsApi();
    std::string get_name() const override { return "dnsapi"; }
    const std::vector<ApiEntry>& get_apis() const override { return apis_; }
};

}} // namespaces
#endif
