// com_api.h — COM API handler (v2 — macro-based registration)
#ifndef SPEAKEASY_COM_API_H
#define SPEAKEASY_COM_API_H
#include <string>
#include <vector>
#include "api_handler_base.h"

namespace speakeasy { namespace api {

class ComApi : public ApiHandler {
    API_LIST_BEGIN
    API_ENTRY(IUnknown_QueryInterface, 3)  API_ENTRY(IUnknown_AddRef, 1)
    API_ENTRY(IUnknown_Release, 1)         API_ENTRY(IWbemLocator_ConnectServer, 9)
    API_ENTRY(IWbemServices_ExecQuery, 6)
    API_LIST_END

public:
    ComApi();
    std::string get_name() const override { return "com_api"; }
    const std::vector<ApiEntry>& get_apis() const override { return apis_; }
};

}} // namespaces
#endif
