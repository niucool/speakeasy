// comctl32.h  comctl32.dll API handler (v2  macro-based registration)
#ifndef SPEAKEASY_COMCTL32_H
#define SPEAKEASY_COMCTL32_H
#include <string>
#include <vector>
#include "../api.h"

namespace speakeasy { namespace api {

class Comctl32 : public ApiHandler {
    API_LIST_BEGIN
    API_ENTRY(InitCommonControlsEx, 1)
    API_ENTRY(InitCommonControls, 0)
    API_LIST_END

public:
    Comctl32(void* emu);
    std::string get_name() const override { return "comctl32"; }
    const std::vector<ApiEntry>& get_apis() const override { return apis_; }
};

}} // namespaces
#endif
