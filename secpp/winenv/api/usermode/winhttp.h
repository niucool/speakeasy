// winhttp.h  winhttp.dll API handler (v2  macro-based registration)
#ifndef SPEAKEASY_WINHTTP_H
#define SPEAKEASY_WINHTTP_H
#include <string>
#include <vector>
#include "../api.h"

namespace speakeasy { namespace api {

class WinHttp : public ApiHandler {
    API_LIST_BEGIN
    API_ENTRY(WinHttpOpen, 5)
    API_ENTRY(WinHttpConnect, 4)
    API_ENTRY(WinHttpOpenRequest, 7)
    API_ENTRY(WinHttpGetIEProxyConfigForCurrentUser, 1)
    API_ENTRY(WinHttpGetProxyForUrl, 4)
    API_ENTRY(WinHttpSetOption, 4)
    API_ENTRY(WinHttpSendRequest, 7)
    API_ENTRY(WinHttpReceiveResponse, 2)
    API_ENTRY(WinHttpReadData, 4)
    API_ENTRY(WinHttpCrackUrl, 4)
    API_ENTRY(WinHttpAddRequestHeaders, 4)
    API_ENTRY(WinHttpQueryHeaders, 6)
    API_ENTRY(WinHttpCloseHandle, 1)
    API_LIST_END

public:
    WinHttp(void* emu);
    std::string get_name() const override { return "winhttp"; }
    const std::vector<ApiEntry>& get_apis() const override { return apis_; }
};

}} // namespaces
#endif
