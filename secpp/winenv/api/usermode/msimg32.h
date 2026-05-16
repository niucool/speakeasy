// msimg32.h — msimg32.dll API handler
#ifndef SPEAKEASY_MSIMG32_H
#define SPEAKEASY_MSIMG32_H
#include <string>
#include <vector>
#include "api_handler_base.h"

namespace speakeasy { namespace api {

class Msimg32 : public ApiHandler {
    API_LIST_BEGIN
    API_ENTRY(TransparentBlt, 11)
    API_LIST_END

public:
    Msimg32();
    std::string get_name() const override { return "msimg32"; }
    const std::vector<ApiEntry>& get_apis() const override { return apis_; }
};

}} // namespaces
#endif
