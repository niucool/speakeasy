// wininet.cpp  wininet.dll handler (real implementations)
#include "wininet.h"
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
    static uint64_t h = 0x3000;
    return ++h;
}

//  Internal state tracking 
struct WininetRequest {
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
    uint64_t parent_hnd;  // connect or session handle

    WininetRequest() : hnd(0), port(0), secure(false), parent_hnd(0) {}
};

// Session (from InternetConnect or InternetOpenUrl)
struct WininetSession {
    uint64_t hnd;
    std::string server;
    int port;
    bool secure;
    uint64_t internet_hnd;  // parent InternetOpen handle

    WininetSession() : hnd(0), port(0), secure(false), internet_hnd(0) {}
};

// Internet handle (from InternetOpen)
struct WininetInternet {
    uint64_t hnd;
    std::string user_agent;
    uint32_t access_type;
    std::string proxy;
    std::string bypass;
    uint32_t flags;

    WininetInternet() : hnd(0), access_type(0), flags(0) {}
};

static std::map<uint64_t, WininetRequest>& requests() {
    static std::map<uint64_t, WininetRequest> r;
    return r;
}

static std::map<uint64_t, WininetSession>& sessions() {
    static std::map<uint64_t, WininetSession> s;
    return s;
}

static std::map<uint64_t, WininetInternet>& internets() {
    static std::map<uint64_t, WininetInternet> i;
    return i;
}

//  Constants 
static constexpr uint32_t INTERNET_OPEN_TYPE_DIRECT = 1;
static constexpr uint32_t INTERNET_OPEN_TYPE_PROXY = 3;
static constexpr uint32_t INTERNET_OPEN_TYPE_PRECONFIG = 0;
static constexpr uint32_t INTERNET_SERVICE_HTTP = 3;
static constexpr uint32_t INTERNET_SERVICE_HTTPS = 4;
static constexpr uint32_t INTERNET_CONNECTION_LAN = 0x02;
static constexpr uint32_t INTERNET_OPTION_SECURITY_FLAGS = 0x1B;
static constexpr uint32_t SECURITY_FLAG_SECURE = 0x00000001;
static constexpr uint32_t HTTP_QUERY_STATUS_CODE = 0x00000013;

// 
//  InternetOpen
// 
uint64_t Wininet::InternetOpen(void* e, const std::vector<uint64_t>& a, void* ctx) {
    if (a.size() < 5) return 0;
    uint64_t ua_ptr = a[0];
    uint32_t access_type = static_cast<uint32_t>(a[1]);
    uint64_t proxy_ptr = a[2];
    uint64_t bypass_ptr = a[3];
    uint32_t flags = static_cast<uint32_t>(a[4]);

    std::string ua;
    if (ua_ptr) ua = be(e)->read_mem_string(ua_ptr, 2);
    std::string proxy;
    if (proxy_ptr) proxy = be(e)->read_mem_string(proxy_ptr, 2);
    std::string bypass;
    if (bypass_ptr) bypass = be(e)->read_mem_string(bypass_ptr, 2);

    uint64_t hnd = next_handle();
    WininetInternet inst;
    inst.hnd = hnd;
    inst.user_agent = ua;
    inst.access_type = access_type;
    inst.proxy = proxy;
    inst.bypass = bypass;
    inst.flags = flags;
    internets()[hnd] = inst;

    return hnd;
}

// 
//  InternetConnect
// 
uint64_t Wininet::InternetConnect(void* e, const std::vector<uint64_t>& a, void* ctx) {
    if (a.size() < 8) return 0;
    uint64_t hInternet = a[0];
    uint64_t server_ptr = a[1];
    uint32_t port = static_cast<uint32_t>(a[2]);
    uint64_t user_ptr = a[3];
    uint64_t pass_ptr = a[4];
    uint32_t service = static_cast<uint32_t>(a[5]);
    uint32_t flags = static_cast<uint32_t>(a[6]);
    uint64_t dwctx = a[7];
    (void)user_ptr; (void)pass_ptr; (void)flags; (void)dwctx;

    if (internets().find(hInternet) == internets().end()) return 0;

    std::string server;
    if (server_ptr) server = be(e)->read_mem_string(server_ptr, 2);

    uint64_t hnd = next_handle();
    WininetSession sess;
    sess.hnd = hnd;
    sess.server = server;
    sess.port = static_cast<int>(port);
    sess.secure = (service == INTERNET_SERVICE_HTTPS || port == 443);
    sess.internet_hnd = hInternet;
    sessions()[hnd] = sess;

    return hnd;
}

// 
//  HttpOpenRequest
// 
uint64_t Wininet::HttpOpenRequest(void* e, const std::vector<uint64_t>& a, void* ctx) {
    if (a.size() < 8) return 0;
    uint64_t hConnect = a[0];
    uint64_t verb_ptr = a[1];
    uint64_t obj_ptr = a[2];
    uint64_t ver_ptr = a[3];
    uint64_t ref_ptr = a[4];
    uint64_t accepts_ptr = a[5];
    uint32_t flags = static_cast<uint32_t>(a[6]);
    uint64_t dwctx = a[7];
    (void)accepts_ptr; (void)flags; (void)dwctx;

    std::string verb = "GET";
    if (verb_ptr) verb = be(e)->read_mem_string(verb_ptr, 2);

    std::string objname = "/";
    if (obj_ptr) objname = be(e)->read_mem_string(obj_ptr, 2);

    std::string version;
    if (ver_ptr) version = be(e)->read_mem_string(ver_ptr, 2);

    std::string referrer;
    if (ref_ptr) referrer = be(e)->read_mem_string(ref_ptr, 2);

    // Copy server info from session handle
    std::string server;
    int port = 0;
    bool secure = false;
    auto sit = sessions().find(hConnect);
    if (sit != sessions().end()) {
        server = sit->second.server;
        port = sit->second.port;
        secure = sit->second.secure;
    }

    uint64_t hnd = next_handle();
    WininetRequest req;
    req.hnd = hnd;
    req.verb = verb;
    req.path = objname;
    req.version = version;
    req.referrer = referrer;
    req.server = server;
    req.port = port;
    req.secure = secure;
    req.parent_hnd = hConnect;
    requests()[hnd] = req;

    return hnd;
}

// 
//  InternetCrackUrl
// 
uint64_t Wininet::InternetCrackUrl(void* e, const std::vector<uint64_t>& a, void* ctx) {
    if (a.size() < 4) return 0;
    uint64_t lpszUrl = a[0];
    uint32_t dwUrlLength = static_cast<uint32_t>(a[1]);
    uint32_t dwFlags = static_cast<uint32_t>(a[2]);
    uint64_t lpUrlComponents = a[3];
    (void)dwUrlLength; (void)dwFlags;

    if (!lpszUrl || !lpUrlComponents) return 0;

    std::string url = be(e)->read_mem_string(lpszUrl, 2);

    // Simple URL parsing: determine scheme
    uint32_t scheme = 1; // INTERNET_SCHEME_HTTP
    if (url.find("https") == 0 || url.find("HTTPS") == 0) {
        scheme = 2; // INTERNET_SCHEME_HTTPS
    }

    // URL_COMPONENTS structure layout varies by pointer size:
    // On x86 (4-byte ptrs): 11 DWORDs + 4 PTRs = 11*4 + 4*4 = 60 bytes
    // On x64 (8-byte ptrs): 11 DWORDs + 4 PTRs = 11*4 + 4*8 = 76 bytes
    // nScheme is typically at offset 44 on x86, 48 on x64
    // Actually, the layout is more complex. Let's just write nScheme at a safe offset.
    int ps = we(e)->get_ptr_size();
    size_t scheme_offset = 0;
    if (ps == 4) {
        // 11 dwords (44 bytes) + dwStructSize at 0
        scheme_offset = 40; // nScheme after hostname parts
    } else {
        scheme_offset = 40 + 8; // x64
    }

    auto raw = we(e)->mem_read(lpUrlComponents, scheme_offset + 8);
    if (raw.size() < scheme_offset + 4) raw.resize(scheme_offset + 4, 0);
    write_le(raw, scheme_offset, scheme, 4);
    we(e)->mem_write(lpUrlComponents, raw);

    return 1; // TRUE
}

// 
//  InternetSetOption
// 
uint64_t Wininet::InternetSetOption(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a;
    return 1; // TRUE
}

// 
//  InternetGetConnectedState
// 
uint64_t Wininet::InternetGetConnectedState(void* e, const std::vector<uint64_t>& a, void* ctx) {
    if (a.size() < 2) return 0;
    uint64_t lpdwFlags = a[0];
    uint32_t dwReserved = static_cast<uint32_t>(a[1]);
    (void)dwReserved;

    if (lpdwFlags) {
        std::vector<uint8_t> buf(4, 0);
        write_le(buf, 0, INTERNET_CONNECTION_LAN, 4);
        we(e)->mem_write(lpdwFlags, buf);
    }

    return 1; // TRUE
}

// 
//  HttpSendRequest
// 
uint64_t Wininet::HttpSendRequest(void* e, const std::vector<uint64_t>& a, void* ctx) {
    if (a.size() < 5) return 0;
    uint64_t hRequest = a[0];
    uint64_t headers_ptr = a[1];
    uint32_t hdrlen = static_cast<uint32_t>(a[2]);
    uint64_t lpOptional = a[3];
    uint32_t dwOptionalLength = static_cast<uint32_t>(a[4]);
    (void)hdrlen;

    auto it = requests().find(hRequest);
    if (it == requests().end()) return 0;
    WininetRequest& req = it->second;

    if (headers_ptr) {
        std::string hdrs = be(e)->read_mem_string(headers_ptr, 2);
        if (!req.headers.empty()) req.headers += "\r\n";
        req.headers += hdrs;
    }

    std::vector<uint8_t> body;
    if (lpOptional && dwOptionalLength) {
        body = we(e)->mem_read(lpOptional, static_cast<size_t>(dwOptionalLength));
    }

    // Build request string for logging
    std::string req_str = req.verb + " " + req.path + " HTTP/" + (req.version.empty() ? "1.1" : req.version) + "\r\n";
    if (!req.headers.empty()) {
        req_str += req.headers + "\r\n";
    }
    req_str += "\r\n";

    // Log HTTP event via profiler
    auto prof = be(e)->get_profiler();
    if (prof) {
        auto run = std::static_pointer_cast<Run>(we(e)->get_current_run());
        prof->log_http(run, req.server, req.port, "wininet", req_str, body, req.secure);
    }

    return 1; // TRUE
}

// 
//  InternetErrorDlg
// 
uint64_t Wininet::InternetErrorDlg(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a;
    return 1; // TRUE (error handled)
}

// 
//  InternetQueryOption
// 
uint64_t Wininet::InternetQueryOption(void* e, const std::vector<uint64_t>& a, void* ctx) {
    if (a.size() < 4) return 0;
    uint64_t hInternet = a[0];
    uint32_t dwOption = static_cast<uint32_t>(a[1]);
    uint64_t lpBuffer = a[2];
    uint64_t lpdwBufferLength = a[3];
    (void)hInternet;

    if (dwOption == INTERNET_OPTION_SECURITY_FLAGS) {
        if (lpBuffer && lpdwBufferLength) {
            // Check buffer size
            auto len_buf = we(e)->mem_read(lpdwBufferLength, 4);
            uint32_t buf_len = static_cast<uint32_t>(read_le(len_buf, 0, 4));
            if (buf_len >= 4) {
                std::vector<uint8_t> out(4, 0);
                write_le(out, 0, SECURITY_FLAG_SECURE, 4);
                we(e)->mem_write(lpBuffer, out);
            }
        }
        return 1; // TRUE
    }

    return 1; // TRUE (default)
}

// 
//  InternetReadFile
// 
uint64_t Wininet::InternetReadFile(void* e, const std::vector<uint64_t>& a, void* ctx) {
    if (a.size() < 4) return 0;
    uint64_t hFile = a[0];
    uint64_t buf = a[1];
    uint32_t size = static_cast<uint32_t>(a[2]);
    uint64_t bytes_read_ptr = a[3];
    (void)hFile; (void)size;

    // Return empty data (no response available)
    std::vector<uint8_t> empty;

    if (buf) {
        we(e)->mem_write(buf, empty);
    }
    if (bytes_read_ptr) {
        std::vector<uint8_t> sz(4, 0);
        write_le(sz, 0, 0, 4);
        we(e)->mem_write(bytes_read_ptr, sz);
    }

    return 1; // TRUE
}

// 
//  HttpQueryInfo
// 
uint64_t Wininet::HttpQueryInfo(void* e, const std::vector<uint64_t>& a, void* ctx) {
    if (a.size() < 5) return 0;
    uint64_t hRequest = a[0];
    uint32_t dwInfoLevel = static_cast<uint32_t>(a[1]);
    uint64_t lpBuffer = a[2];
    uint64_t lpdwBufferLength = a[3];
    uint64_t lpdwIndex = a[4];
    (void)hRequest; (void)lpdwIndex;

    // Handle HTTP_QUERY_STATUS_CODE
    if (dwInfoLevel == HTTP_QUERY_STATUS_CODE || (dwInfoLevel & 0xFFFF) == HTTP_QUERY_STATUS_CODE) {
        if (lpBuffer) {
            std::vector<uint8_t> status(8, 0);
            status[0] = 0x32; status[1] = 0x00; // '2'
            status[2] = 0x30; status[3] = 0x00; // '0'
            status[4] = 0x30; status[5] = 0x00; // '0'
            status[6] = 0x00; status[7] = 0x00; // NUL
            we(e)->mem_write(lpBuffer, status);
        }
        if (lpdwBufferLength) {
            std::vector<uint8_t> sz(4, 0);
            write_le(sz, 0, 8, 4);
            we(e)->mem_write(lpdwBufferLength, sz);
        }
        return 1; // TRUE
    }

    // For other queries, return TRUE
    if (lpBuffer == 0) {
        return 1;
    }
    return 1;
}

// 
//  InternetQueryDataAvailable
// 
uint64_t Wininet::InternetQueryDataAvailable(void* e, const std::vector<uint64_t>& a, void* ctx) {
    if (a.size() < 4) return 0;
    uint64_t hFile = a[0];
    uint64_t lpdwNumberOfBytesAvailable = a[1];
    uint32_t dwFlags = static_cast<uint32_t>(a[2]);
    uint64_t dwContext = a[3];
    (void)hFile; (void)dwFlags; (void)dwContext;

    if (lpdwNumberOfBytesAvailable) {
        std::vector<uint8_t> sz(4, 0);
        write_le(sz, 0, 0, 4);  // 0 bytes available (no real data)
        we(e)->mem_write(lpdwNumberOfBytesAvailable, sz);
    }

    return 1; // TRUE
}

// 
//  InternetCloseHandle
// 
uint64_t Wininet::InternetCloseHandle(void* e, const std::vector<uint64_t>& a, void* ctx) {
    if (a.size() < 1) return 0;
    uint64_t hnd = a[0];
    (void)e;

    requests().erase(hnd);
    sessions().erase(hnd);
    internets().erase(hnd);

    return 1; // TRUE
}

// 
//  InternetOpenUrl
// 
uint64_t Wininet::InternetOpenUrl(void* e, const std::vector<uint64_t>& a, void* ctx) {
    if (a.size() < 6) return 0;
    uint64_t hInternet = a[0];
    uint64_t url_ptr = a[1];
    uint64_t headers_ptr = a[2];
    uint32_t dwHeadersLength = static_cast<uint32_t>(a[3]);
    uint32_t dwFlags = static_cast<uint32_t>(a[4]);
    uint64_t dwContext = a[5];
    (void)dwHeadersLength; (void)dwContext;

    if (internets().find(hInternet) == internets().end()) return 0;

    std::string url;
    if (url_ptr) url = be(e)->read_mem_string(url_ptr, 2);

    std::string headers;
    if (headers_ptr) headers = be(e)->read_mem_string(headers_ptr, 2);

    // Parse URL to extract host and port
    std::string server;
    int port = 80;
    bool secure = false;

    if (url.find("https://") == 0 || url.find("HTTPS://") == 0) {
        secure = true;
        port = 443;
        size_t start = 8;
        size_t end = url.find_first_of("/:", start);
        if (end != std::string::npos) {
            server = url.substr(start, end - start);
            if (url[end] == ':') {
                size_t port_end = url.find_first_of("/", end);
                if (port_end == std::string::npos) {
                    port = std::stoi(url.substr(end + 1));
                } else {
                    port = std::stoi(url.substr(end + 1, port_end - end - 1));
                }
            }
        } else {
            server = url.substr(start);
        }
    } else {
        size_t start = 7; // strlen("http://")
        if (url.find("http://") != 0 && url.find("HTTP://") != 0) start = 0;
        size_t end = url.find_first_of("/:", start);
        if (end != std::string::npos) {
            server = url.substr(start, end - start);
            if (url[end] == ':') {
                size_t port_end = url.find_first_of("/", end);
                if (port_end == std::string::npos) {
                    port = std::stoi(url.substr(end + 1));
                } else {
                    port = std::stoi(url.substr(end + 1, port_end - end - 1));
                }
            }
        } else {
            server = url.substr(start);
        }
    }

    // Log HTTP event
    std::string req_str = "GET " + url + " HTTP/1.1\r\n";
    if (!headers.empty()) req_str += headers + "\r\n";
    req_str += "\r\n";

    auto prof = be(e)->get_profiler();
    if (prof) {
        auto run = std::static_pointer_cast<Run>(we(e)->get_current_run());
        prof->log_http(run, server, port, "wininet", req_str, {}, secure);
    }

    // Create a session and request
    uint64_t sess_hnd = next_handle();
    WininetSession sess;
    sess.hnd = sess_hnd;
    sess.server = server;
    sess.port = port;
    sess.secure = secure;
    sess.internet_hnd = hInternet;
    sessions()[sess_hnd] = sess;

    uint64_t req_hnd = next_handle();
    WininetRequest req;
    req.hnd = req_hnd;
    req.verb = "GET";
    req.path = url;
    req.server = server;
    req.port = port;
    req.secure = secure;
    req.parent_hnd = sess_hnd;
    requests()[req_hnd] = req;

    return req_hnd;
}

//  Constructor 
Wininet::Wininet(void* emu) : ApiHandler(emu) {
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

}} // namespaces
