// wkscli.h  wkscli.dll API handler (v2  macro-based registration)
#ifndef SPEAKEASY_WKSCLI_H
#define SPEAKEASY_WKSCLI_H
#include <string>
#include <vector>
#include "../api.h"

namespace speakeasy { namespace api {

class Wkscli : public ApiHandler {
    API_LIST_BEGIN
    API_ENTRY(NetGetJoinInformation, 3)
    API_LIST_END

public:
    Wkscli(void* emu);
    std::string get_name() const override { return "wkscli"; }
    const std::vector<ApiEntry>& get_apis() const override { return apis_; }
};

}} // namespaces
#endif
