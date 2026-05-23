// advpack.h — advpack.dll API handler (v2 — macro-based registration)
#ifndef SPEAKEASY_ADVPACK_H
#define SPEAKEASY_ADVPACK_H
#include <string>
#include <vector>
#include "../api.h"

namespace speakeasy { namespace api {

class Advpack : public ApiHandler {
    API_LIST_BEGIN
    API_ENTRY(IsNTAdmin, 2)
    API_LIST_END

public:
    Advpack(void* emu);
    std::string get_name() const override { return "advpack"; }
    const std::vector<ApiEntry>& get_apis() const override { return apis_; }
};

}} // namespaces
#endif
