// rpcrt4.h — rpcrt4.dll API handler
#ifndef SPEAKEASY_RPCRT4_H
#define SPEAKEASY_RPCRT4_H
#include <string>
#include <vector>
#include "api_handler_base.h"

namespace speakeasy { namespace api {

class Rpcrt4 : public ApiHandler {
    API_LIST_BEGIN
    API_ENTRY(UuidCreate, 1)
    API_ENTRY(UuidToStringA, 2)
    API_LIST_END

public:
    Rpcrt4();
    std::string get_name() const override { return "rpcrt4"; }
    const std::vector<ApiEntry>& get_apis() const override { return apis_; }
};

}} // namespaces
#endif
