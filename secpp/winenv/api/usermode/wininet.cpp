// wininet.cpp — wininet.dll handler (stubs)
#include "wininet.h"

namespace speakeasy { namespace api {

Wininet::Wininet() {
    INIT_API_TABLE(Wininet)
    REG(Wininet, InternetOpen, 5)
    REG(Wininet, InternetConnect, 8)
    REG(Wininet, HttpOpenRequest, 8)
    REG(Wininet, InternetCrackUrl, 4)
    REG(Wininet, InternetSetOption, 4)
    REG(Wininet, InternetGetConnectedState, 2)
    REG(Wininet, HttpSendRequest, 5)
    REG(Wininet, InternetErrorDlg, 5)
    REG(Wininet, InternetQueryOption, 4)
    REG(Wininet, InternetReadFile, 4)
    REG(Wininet, HttpQueryInfo, 5)
    REG(Wininet, InternetQueryDataAvailable, 4)
    REG(Wininet, InternetCloseHandle, 1)
    REG(Wininet, InternetOpenUrl, 6)
    END_API_TABLE
}

#define STUB_WININET(n) STUB(Wininet, n)

STUB_WININET(InternetOpen)
STUB_WININET(InternetConnect)
STUB_WININET(HttpOpenRequest)
STUB_WININET(InternetCrackUrl)
STUB_WININET(InternetSetOption)
STUB_WININET(InternetGetConnectedState)
STUB_WININET(HttpSendRequest)
STUB_WININET(InternetErrorDlg)
STUB_WININET(InternetQueryOption)
STUB_WININET(InternetReadFile)
STUB_WININET(HttpQueryInfo)
STUB_WININET(InternetQueryDataAvailable)
STUB_WININET(InternetCloseHandle)
STUB_WININET(InternetOpenUrl)

}} // namespaces
