// wtsapi32.h — wtsapi32.dll API handler (v2 — macro-based registration)
#ifndef SPEAKEASY_WTSAPI32_H
#define SPEAKEASY_WTSAPI32_H
#include <string>
#include <vector>
#include "api_handler_base.h"

namespace speakeasy { namespace api {

class Wtsapi32 : public ApiHandler {
    API_LIST_BEGIN
    API_ENTRY(WTSEnumerateSessions, 5)   API_ENTRY(WTSFreeMemory, 1)
    API_LIST_END

public:
    Wtsapi32();
    std::string get_name() const override { return "wtsapi32"; }
    const std::vector<ApiEntry>& get_apis() const override { return apis_; }
};

}} // namespaces
#endif
