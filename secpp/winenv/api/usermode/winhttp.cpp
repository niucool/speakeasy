// winhttp.cpp  winhttp.dll handler (v2  real implementations)
#include "winhttp.h"
#include <cstring>
#include <cstdint>
#include <string>
#include <vector>
#include <map>
#include "windows/winemu.h"
#include "struct.h"

using namespace speakeasy;

namespace speakeasy { namespace api {

static inline WindowsEmulator* we(void* e) { return static_cast<WindowsEmulator*>(e); }
static inline BinaryEmulator* be(void* e) { return static_cast<BinaryEmulator*>(e); }

//  Handle management 
static uint64_t next_handle() {
    static uint64_t h = 0x2000;
    return ++h;
}

//  Internal HTTP state tracking 
struct WinHttpRequest {
    uint64_t hnd;
    std::string verb;
    std::string path;
    std::string version;
    std::string referrer;
    std::string headers;
    std::string server;
    int port;
    bool secure;
    std::vector<uint8_t> response_data;

    WinHttpRequest() : hnd(0), port(0), secure(false) {}
};

static std::map<uint64_t, WinHttpRequest>& requests() {
    static std::map<uint64_t, WinHttpRequest> r;
    return r;
}

// 
// API implementations
// 

//  WinHttpOpen 
// HINTERNET WinHttpOpen(LPCWSTR pszAgentW, DWORD dwAccessType,
//                       LPCWSTR pszProxyW, LPCWSTR pszProxyBypassW, DWORD dwFlags);
uint64_t WinHttp::WinHttpOpen(void* e, ArgList& a, void* ctx) {
    if (a.size() < 5) return 0;
    uint64_t ua_ptr = a[0];
    uint64_t proxy_ptr = a[2];
    uint64_t bypass_ptr = a[3];

    if (ua_ptr) {
        std::string ua = be(e)->read_mem_string(ua_ptr, 2);
        (void)ua;
    }
    if (proxy_ptr) {
        be(e)->read_mem_string(proxy_ptr, 2);
    }
    if (bypass_ptr) {
        be(e)->read_mem_string(bypass_ptr, 2);
    }

    uint64_t hnd = next_handle();
    WinHttpRequest req;
    req.hnd = hnd;
    requests()[hnd] = req;
    return hnd;
}

//  WinHttpConnect 
// HINTERNET WinHttpConnect(HINTERNET hSession, LPCWSTR pswzServerName,
//                          INTERNET_PORT nServerPort, DWORD dwReserved);
uint64_t WinHttp::WinHttpConnect(void* e, ArgList& a, void* ctx) {
    if (a.size() < 4) return 0;
    uint64_t hSession = a[0]; (void)hSession;
    // TODO: session handle not yet wired  HTTP session tracking incomplete
    uint64_t server_ptr = a[1];
    uint64_t nServerPort = a[2];

    std::string server;
    if (server_ptr) {
        server = be(e)->read_mem_string(server_ptr, 2);
    }

    uint64_t hnd = next_handle();
    WinHttpRequest req;
    req.hnd = hnd;
    req.server = server;
    req.port = static_cast<int>(nServerPort & 0xFFFF);
    req.secure = (nServerPort == 443);
    requests()[hnd] = req;
    return hnd;
}

//  WinHttpOpenRequest 
// HINTERNET WinHttpOpenRequest(HINTERNET hConnect, LPCWSTR pwszVerb,
//                              LPCWSTR pwszObjectName, LPCWSTR pwszVersion, ...);
uint64_t WinHttp::WinHttpOpenRequest(void* e, ArgList& a, void* ctx) {
    if (a.size() < 7) return 0;
    uint64_t hConnect = a[0];
    uint64_t verb_ptr = a[1];
    uint64_t obj_ptr = a[2];
    uint64_t ver_ptr = a[3];
    uint64_t ref_ptr = a[4];
    uint64_t accepts_ptr = a[5];
    uint64_t flags = a[6];
    (void)flags; (void)accepts_ptr;

    std::string verb = "GET";
    if (verb_ptr) verb = be(e)->read_mem_string(verb_ptr, 2);

    std::string objname = "/";
    if (obj_ptr) objname = be(e)->read_mem_string(obj_ptr, 2);

    std::string version;
    if (ver_ptr) version = be(e)->read_mem_string(ver_ptr, 2);

    std::string referrer;
    if (ref_ptr) referrer = be(e)->read_mem_string(ref_ptr, 2);

    // Copy server info from connect handle
    std::string server;
    int port = 0;
    bool secure = false;
    auto it = requests().find(hConnect);
    if (it != requests().end()) {
        server = it->second.server;
        port = it->second.port;
        secure = it->second.secure;
    }

    uint64_t hnd = next_handle();
    WinHttpRequest req;
    req.hnd = hnd;
    req.verb = verb;
    req.path = objname;
    req.version = version;
    req.referrer = referrer;
    req.server = server;
    req.port = port;
    req.secure = secure;
    requests()[hnd] = req;
    return hnd;
}

//  WinHttpGetIEProxyConfigForCurrentUser 
uint64_t WinHttp::WinHttpGetIEProxyConfigForCurrentUser(void* e, ArgList& a, void* ctx) {
    if (a.size() < 1) return 0;
    uint64_t proxy_config = a[0];
    if (proxy_config) {
        // Write WINHTTP_CURRENT_USER_IE_PROXY_CONFIG { BOOL fAutoDetect; ... }
        std::vector<uint8_t> buf(we(e)->get_ptr_size() * 4 + 4, 0);
        write_le(buf, 0, 1, 4); // fAutoDetect = TRUE
        we(e)->mem_write(proxy_config, buf);
    }
    return 1; // TRUE
}

//  WinHttpGetProxyForUrl 
uint64_t WinHttp::WinHttpGetProxyForUrl(void* e, ArgList& a, void* ctx) {
    (void)e;
    if (a.size() < 1) return 0;
    return 1; // TRUE (no proxy)
}

//  WinHttpSetOption 
uint64_t WinHttp::WinHttpSetOption(void* e, ArgList& a, void* ctx) {
    (void)e; (void)a;
    return 1; // TRUE
}

//  WinHttpSendRequest 
uint64_t WinHttp::WinHttpSendRequest(void* e, ArgList& a, void* ctx) {
    if (a.size() < 7) return 0;
    uint64_t hRequest = a[0];
    uint64_t headers_ptr = a[1];
    uint64_t hdrlen = a[2];
    uint64_t lpOptional = a[3];
    uint64_t dwOptionalLength = a[4];
    uint64_t totlen = a[5];
    uint64_t context = a[6];
    (void)hdrlen; (void)totlen; (void)context;

    auto it = requests().find(hRequest);
    if (it == requests().end()) return 0;
    WinHttpRequest& req = it->second;

    if (headers_ptr) {
        std::string hdrs = be(e)->read_mem_string(headers_ptr, 2);
        if (!req.headers.empty()) req.headers += "\r\n";
        req.headers += hdrs;
    }

    std::vector<uint8_t> body;
    if (lpOptional && dwOptionalLength) {
        body = we(e)->mem_read(lpOptional, static_cast<size_t>(dwOptionalLength));
    }

    // Build HTTP request string for logging
    std::string req_str = req.verb + " " + req.path + " HTTP/" + (req.version.empty() ? "1.1" : req.version) + "\r\n";
    if (!req.headers.empty()) {
        req_str += req.headers + "\r\n";
    }
    req_str += "\r\n";

    // Log DNS lookup if server is a hostname
    if (!req.server.empty() && req.server.find('.') != std::string::npos) {
        auto prof = be(e)->get_profiler();
        if (prof) {
            auto run = std::static_pointer_cast<Run>(we(e)->get_current_run());
            prof->log_dns(run, req.server, "");
        }
    }

    // Log HTTP event
    auto prof = be(e)->get_profiler();
    if (prof) {
        auto run = std::static_pointer_cast<Run>(we(e)->get_current_run());
        prof->log_http(run, req.server, req.port, "http", req_str, body, req.secure);
    }

    return 1; // TRUE
}

//  WinHttpReceiveResponse 
uint64_t WinHttp::WinHttpReceiveResponse(void* e, ArgList& a, void* ctx) {
    (void)e; (void)a;
    return 1; // TRUE
}

//  WinHttpReadData 
uint64_t WinHttp::WinHttpReadData(void* e, ArgList& a, void* ctx) {
    if (a.size() < 4) return 0;
    uint64_t hRequest = a[0];
    uint64_t buf = a[1];
    uint64_t size = a[2]; (void)size;
    // TODO: size not yet used  response buffer size validation incomplete
    uint64_t bytes_read = a[3];
    (void)hRequest;

    // Return an empty HTTP response
    std::vector<uint8_t> empty;

    if (buf) {
        we(e)->mem_write(buf, empty);
    }
    if (bytes_read) {
        std::vector<uint8_t> sz(4, 0);
        write_le(sz, 0, 0, 4);
        we(e)->mem_write(bytes_read, sz);
    }
    return 1; // TRUE
}

//  WinHttpCrackUrl 
uint64_t WinHttp::WinHttpCrackUrl(void* e, ArgList& a, void* ctx) {
    if (a.size() < 4) return 0;
    uint64_t pwszUrl = a[0];
    uint64_t dwUrlLength = a[1];
    uint64_t dwFlags = a[2];
    uint64_t lpUrlComponents = a[3];
    (void)dwUrlLength; (void)dwFlags;

    if (!pwszUrl || !lpUrlComponents) return 0;

    std::string url = be(e)->read_mem_string(pwszUrl, 2);

    // Parse URL components  we just set nScheme based on prefix
    uint64_t scheme = 1; // INTERNET_SCHEME_HTTP = 1
    if (url.find("https") == 0 || url.find("HTTPS") == 0) {
        scheme = 2; // INTERNET_SCHEME_HTTPS = 2
    }

    // URL_COMPONENTS layout (32-bit ptr): dwords at 0,4,8,12,16,20, ptr at 24, dword at 32, ptr at 36...
    // We'll just write nScheme at the appropriate offset
    // Offset of nScheme depends on ptr_size and structure layout
    // INTERNET_SCHEME: after all DWORDS and pointers; typically at offset 20 on x86
    int ptr_sz = we(e)->get_ptr_size();
    size_t scheme_offset = 4 + (ptr_sz * 4); // approximate
    if (ptr_sz == 8) scheme_offset = 4 + 8 * 4; // x64

    auto raw = we(e)->mem_read(lpUrlComponents, scheme_offset + 8);
    if (raw.size() < scheme_offset + 8) raw.resize(scheme_offset + 8, 0);
    write_le(raw, scheme_offset, scheme, 4); // nScheme
    we(e)->mem_write(lpUrlComponents, raw);

    return 1; // TRUE
}

//  WinHttpAddRequestHeaders 
uint64_t WinHttp::WinHttpAddRequestHeaders(void* e, ArgList& a, void* ctx) {
    if (a.size() < 4) return 0;
    uint64_t hRequest = a[0];
    uint64_t headers_ptr = a[1];
    uint64_t dwHeaderlen = a[2];
    uint64_t dwModifier = a[3];
    (void)dwModifier;

    if (headers_ptr) {
        std::string hdrs = be(e)->read_mem_string(headers_ptr, 2, static_cast<int>(dwHeaderlen));
        auto it = requests().find(hRequest);
        if (it != requests().end()) {
            if (!it->second.headers.empty()) it->second.headers += "\r\n";
            it->second.headers += hdrs;
        }
    }
    return 1; // TRUE
}

//  WinHttpQueryHeaders 
uint64_t WinHttp::WinHttpQueryHeaders(void* e, ArgList& a, void* ctx) {
    if (a.size() < 6) return 0;
    uint64_t hRequest = a[0];
    uint64_t dwInfoLevel = a[1];
    uint64_t name_ptr = a[2];
    uint64_t buffer = a[3];
    uint64_t bufferLen = a[4];
    uint64_t index = a[5];
    (void)hRequest; (void)name_ptr; (void)index;

    // WINHTTP_QUERY_STATUS_CODE = 0x00000019
    if (dwInfoLevel == 0x00000019 || (dwInfoLevel & 0xFFFF) == 0x0019) {
        if (buffer) {
            // Write "200" as wide string
            std::vector<uint8_t> status(8, 0);
            status[0] = 0x32; status[1] = 0x00; // '2'
            status[2] = 0x30; status[3] = 0x00; // '0'
            status[4] = 0x30; status[5] = 0x00; // '0'
            status[6] = 0x00; status[7] = 0x00; // NUL
            we(e)->mem_write(buffer, status);
        }
        if (bufferLen) {
            std::vector<uint8_t> sz(4, 0);
            write_le(sz, 0, 8, 4);
            we(e)->mem_write(bufferLen, sz);
        }
        return 1; // TRUE
    }

    // For other queries, return TRUE with empty data
    if (buffer == 0) {
        return 1; // Would normally set ERROR_INSUFFICIENT_BUFFER
    }
    return 1;
}

//  WinHttpCloseHandle 
uint64_t WinHttp::WinHttpCloseHandle(void* e, ArgList& a, void* ctx) {
    if (a.size() < 1) return 0;
    uint64_t hnd = a[0];
    requests().erase(hnd);
    return 1; // TRUE
}

WinHttp::WinHttp(void* emu) : ApiHandler(emu) {
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

}} // namespaces
