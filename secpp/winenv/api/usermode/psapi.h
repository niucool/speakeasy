// psapi.h  psapi.dll API handler (v2  macro-based registration)
#ifndef SPEAKEASY_PSAPI_H
#define SPEAKEASY_PSAPI_H
#include <string>
#include <vector>
#include "../api.h"

namespace speakeasy { namespace api {

class Psapi : public ApiHandler {
    API_LIST_BEGIN
    API_ENTRY(EnumProcesses, 3)         API_ENTRY(EnumProcessModules, 4)
    API_ENTRY(GetModuleBaseName, 4)     API_ENTRY(GetModuleBaseNameA, 4)
    API_ENTRY(GetModuleBaseNameW, 4)    API_ENTRY(GetModuleFileNameEx, 4)
    API_ENTRY(GetModuleFileNameExA, 4)  API_ENTRY(GetModuleFileNameExW, 4)
    API_LIST_END

public:
    Psapi(void* emu);
    std::string get_name() const override { return "psapi"; }
    const std::vector<ApiEntry>& get_apis() const override { return apis_; }
};

}} // namespaces
#endif
