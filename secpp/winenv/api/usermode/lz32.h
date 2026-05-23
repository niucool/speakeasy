// lz32.h — lz32.dll API handler (v2 — macro-based registration)
#ifndef SPEAKEASY_LZ32_H
#define SPEAKEASY_LZ32_H
#include <string>
#include <vector>
#include "../api.h"

namespace speakeasy { namespace api {

class Lz32 : public ApiHandler {
    API_LIST_BEGIN
    API_ENTRY(LZSeek, 3)
    API_LIST_END

public:
    Lz32(void* emu);
    std::string get_name() const override { return "lz32"; }
    const std::vector<ApiEntry>& get_apis() const override { return apis_; }
};

}} // namespaces
#endif
