// msi32.h — msi32.dll API handler
#ifndef SPEAKEASY_MSI32_H
#define SPEAKEASY_MSI32_H
#include <string>
#include <vector>
#include "../api.h"

namespace speakeasy { namespace api {

class Msi32 : public ApiHandler {
    API_LIST_BEGIN
    API_ENTRY(MsiDatabaseMergeA, 3)
    API_LIST_END

public:
    Msi32(void* emu);
    std::string get_name() const override { return "msi32"; }
    const std::vector<ApiEntry>& get_apis() const override { return apis_; }
};

}} // namespaces
#endif
