// oleaut32.h — oleaut32.dll API handler
#ifndef SPEAKEASY_OLEAUT32_H
#define SPEAKEASY_OLEAUT32_H
#include <string>
#include <vector>
#include "api_handler_base.h"

namespace speakeasy { namespace api {

class Oleaut32 : public ApiHandler {
    API_LIST_BEGIN
    API_ENTRY(SysAllocString, 1)
    API_ENTRY(SysAllocStringLen, 2)
    API_ENTRY(SysFreeString, 1)
    API_ENTRY(VariantInit, 1)
    API_LIST_END

public:
    Oleaut32();
    std::string get_name() const override { return "oleaut32"; }
    const std::vector<ApiEntry>& get_apis() const override { return apis_; }
};

}} // namespaces
#endif
