// msvfw32.h — msvfw32.dll API handler
#ifndef SPEAKEASY_MSVFW32_H
#define SPEAKEASY_MSVFW32_H
#include <string>
#include <vector>
#include "api_handler_base.h"

namespace speakeasy { namespace api {

class Msvfw32 : public ApiHandler {
    API_LIST_BEGIN
    API_ENTRY(ICOpen, 3)
    API_ENTRY(ICSendMessage, 4)
    API_ENTRY(ICClose, 1)
    API_LIST_END

public:
    Msvfw32();
    std::string get_name() const override { return "msvfw32"; }
    const std::vector<ApiEntry>& get_apis() const override { return apis_; }
};

}} // namespaces
#endif
