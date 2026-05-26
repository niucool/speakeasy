// winmm.h  winmm.dll API handler (v2  macro-based registration)
#ifndef SPEAKEASY_WINMM_H
#define SPEAKEASY_WINMM_H
#include <string>
#include <vector>
#include "../api.h"

namespace speakeasy { namespace api {

class Winmm : public ApiHandler {
    API_LIST_BEGIN
    API_ENTRY(timeBeginPeriod, 1)   API_ENTRY(timeEndPeriod, 1)
    API_ENTRY(timeGetTime, 0)
    API_LIST_END

public:
    Winmm(void* emu);
    std::string get_name() const override { return "winmm"; }
    const std::vector<ApiEntry>& get_apis() const override { return apis_; }
};

}} // namespaces
#endif
