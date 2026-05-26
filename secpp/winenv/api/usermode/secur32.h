// secur32.h  secur32.dll API handler (v2  macro-based registration)
#ifndef SPEAKEASY_SECUR32_H
#define SPEAKEASY_SECUR32_H
#include <string>
#include <vector>
#include "../api.h"

namespace speakeasy { namespace api {

class Secur32 : public ApiHandler {
    API_LIST_BEGIN
    API_ENTRY(GetUserNameEx, 3)   API_ENTRY(EncryptMessage, 4)
    API_LIST_END

public:
    Secur32(void* emu);
    std::string get_name() const override { return "secur32"; }
    const std::vector<ApiEntry>& get_apis() const override { return apis_; }
};

}} // namespaces
#endif
