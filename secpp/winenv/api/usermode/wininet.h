// wininet.h — wininet.dll API handler
#ifndef SPEAKEASY_WININET_H
#define SPEAKEASY_WININET_H
#include <string>
#include <vector>
#include "api_handler_base.h"

namespace speakeasy { namespace api {

class Wininet : public ApiHandler {
    API_LIST_BEGIN
    API_ENTRY(InternetOpen, 5)
    API_ENTRY(InternetConnect, 8)
    API_ENTRY(HttpOpenRequest, 8)
    API_ENTRY(InternetCrackUrl, 4)
    API_ENTRY(InternetSetOption, 4)
    API_ENTRY(InternetGetConnectedState, 2)
    API_ENTRY(HttpSendRequest, 5)
    API_ENTRY(InternetErrorDlg, 5)
    API_ENTRY(InternetQueryOption, 4)
    API_ENTRY(InternetReadFile, 4)
    API_ENTRY(HttpQueryInfo, 5)
    API_ENTRY(InternetQueryDataAvailable, 4)
    API_ENTRY(InternetCloseHandle, 1)
    API_ENTRY(InternetOpenUrl, 6)
    API_LIST_END

public:
    Wininet();
    std::string get_name() const override { return "wininet"; }
    const std::vector<ApiEntry>& get_apis() const override { return apis_; }
};

}} // namespaces
#endif
