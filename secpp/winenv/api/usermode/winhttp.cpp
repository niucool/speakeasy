// winhttp.cpp — winhttp.dll handler (v2 — all STUB, return 1)
#include "winhttp.h"

namespace speakeasy { namespace api {

WinHttp::WinHttp() {
    INIT_API_TABLE(WinHttp)
    REG(WinHttp, WinHttpOpen, 5)
    REG(WinHttp, WinHttpConnect, 4)
    REG(WinHttp, WinHttpOpenRequest, 7)
    REG(WinHttp, WinHttpGetIEProxyConfigForCurrentUser, 1)
    REG(WinHttp, WinHttpGetProxyForUrl, 4)
    REG(WinHttp, WinHttpSetOption, 4)
    REG(WinHttp, WinHttpSendRequest, 7)
    REG(WinHttp, WinHttpReceiveResponse, 2)
    REG(WinHttp, WinHttpReadData, 4)
    REG(WinHttp, WinHttpCrackUrl, 4)
    REG(WinHttp, WinHttpAddRequestHeaders, 4)
    REG(WinHttp, WinHttpQueryHeaders, 6)
    REG(WinHttp, WinHttpCloseHandle, 1)
    END_API_TABLE
}

// ── All stubs ────────────────────────────────────────────────

#define WH_STUB(n) STUB(WinHttp, n)

WH_STUB(WinHttpOpen)
WH_STUB(WinHttpConnect)
WH_STUB(WinHttpOpenRequest)
WH_STUB(WinHttpGetIEProxyConfigForCurrentUser)
WH_STUB(WinHttpGetProxyForUrl)
WH_STUB(WinHttpSetOption)
WH_STUB(WinHttpSendRequest)
WH_STUB(WinHttpReceiveResponse)
WH_STUB(WinHttpReadData)
WH_STUB(WinHttpCrackUrl)
WH_STUB(WinHttpAddRequestHeaders)
WH_STUB(WinHttpQueryHeaders)
WH_STUB(WinHttpCloseHandle)

}} // namespaces
