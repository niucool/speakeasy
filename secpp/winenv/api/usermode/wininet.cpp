// wininet.cpp  wininet.dll handler, follows Python wininet.py logic.
// Uses ApiContext for char width, reads strings correctly per A/W, updates
// argv with resolved strings and flag names, delegates to NetworkManager.
#include "wininet.h"
#include <cstring>
#include <cstdint>
#include <string>
#include <vector>
#include <map>
#include "windows/winemu.h"
#include "struct.h"
#include "windows/netman.h"

using namespace speakeasy;

namespace speakeasy { namespace api {

static uint32_t INTERNET_CONNECTION_LAN = 0x02;

//  InternetOpen 
// Python: reads ua/proxy/bypass with char width, updates argv, uses netman
uint64_t Wininet::InternetOpen(void* e, ArgList& a, void* ctx) {
    if (a.size() < 5) return 0;
    ApiContext* actx = (ApiContext*)ctx;
    int cw = get_char_width(actx);
    if (a[0]) { a[0] = be(e)->read_mem_string(a[0], cw); }
    if (a[2]) { a[2] = be(e)->read_mem_string(a[2], cw); }
    if (a[3]) { a[3] = be(e)->read_mem_string(a[3], cw); }
    auto nm = we(e)->get_network_manager();
    auto conn = nm->new_wininet_inst(
        a[0].is_uint64() ? "" : a[0].as_string(),
        static_cast<uint32_t>(a[1]),
        a[2].is_uint64() ? "" : a[2].as_string(),
        a[3].is_uint64() ? "" : a[3].as_string(),
        static_cast<uint32_t>(a[4]));
    return conn->get_handle();
}

//  InternetConnect 
uint64_t Wininet::InternetConnect(void* e, ArgList& a, void* ctx) {
    if (a.size() < 8) return 0;
    ApiContext* actx = (ApiContext*)ctx;
    int cw = get_char_width(actx);
    if (a[1]) { a[1] = be(e)->read_mem_string(a[1], cw); }
    if (a[3]) { a[3] = be(e)->read_mem_string(a[3], cw); }
    if (a[4]) { a[4] = be(e)->read_mem_string(a[4], cw); }
    auto nm = we(e)->get_network_manager();
    auto wini = nm->get_wininet_object(static_cast<uint32_t>(a[0]));
    if (!wini) return 0;
    auto* winst = static_cast<WininetInstance*>(wini);
    auto sess = winst->new_session(
        a[1].is_uint64() ? "" : a[1].as_string(),
        static_cast<int>(a[2]),
        a[3].is_uint64() ? "" : a[3].as_string(),
        a[4].is_uint64() ? "" : a[4].as_string(),
        static_cast<uint32_t>(a[5]),
        std::vector<std::string>{},
        static_cast<uint32_t>(a[7]));
    return sess ? sess->get_handle() : 0;
}

//  HttpOpenRequest 
uint64_t Wininet::HttpOpenRequest(void* e, ArgList& a, void* ctx) {
    if (a.size() < 8) return 0;
    ApiContext* actx = (ApiContext*)ctx;
    int cw = get_char_width(actx);
    if (a[1]) { a[1] = be(e)->read_mem_string(a[1], cw); }
    if (a[2]) { a[2] = be(e)->read_mem_string(a[2], cw); }
    if (a[3]) { a[3] = be(e)->read_mem_string(a[3], cw); }
    if (a[4]) { a[4] = be(e)->read_mem_string(a[4], cw); }
    // Python: argv[6] = " | ".join(defs)
    std::string flag_str = "0x" + std::to_string(static_cast<uint64_t>(a[6]));
    auto nm = we(e)->get_network_manager();
    auto* sess = static_cast<WininetSession*>(nm->get_wininet_object(static_cast<uint32_t>(a[0])));
    if (!sess) return 0;
    auto req = sess->new_request(
        a[1].is_uint64() ? "GET" : a[1].as_string(),
        a[2].is_uint64() ? "/" : a[2].as_string(),
        a[3].is_uint64() ? "" : a[3].as_string(),
        a[4].is_uint64() ? "" : a[4].as_string(),
        {}, {flag_str}, static_cast<uint32_t>(a[7]));
    return req ? req->get_handle() : 0;
}

//  InternetCrackUrl 
uint64_t Wininet::InternetCrackUrl(void* e, ArgList& a, void* ctx) {
    if (a.size() < 4) return 0;
    if (!a[0] || !a[3]) return 0;
    ApiContext* actx = (ApiContext*)ctx;
    int cw = get_char_width(actx);
    std::string url = be(e)->read_mem_string(a[0], cw);
    a[0] = url;
    // Parse scheme: INTERNET_SCHEME_HTTPS=2, INTERNET_SCHEME_HTTP=1
    uint32_t scheme = 1;
    bool is_https = (url.find("https://") == 0 || url.find("HTTPS://") == 0);
    if (is_https) scheme = 2;
    int ps = we(e)->get_ptr_size();
    size_t scheme_off = (ps == 4) ? 40 : 48;
    auto raw = we(e)->mem_read(a[3], scheme_off + 4);
    if (raw.size() < scheme_off + 4) raw.resize(scheme_off + 4, 0);
    write_le(raw, scheme_off, scheme, 4);
    we(e)->mem_write(a[3], raw);
    return 1;
}

//  InternetSetOption 
uint64_t Wininet::InternetSetOption(void* e, ArgList& a, void* ctx) {
    (void)e; (void)a; (void)ctx; return 1;
}

//  InternetGetConnectedState 
uint64_t Wininet::InternetGetConnectedState(void* e, ArgList& a, void* ctx) {
    if (a.size() < 2) return 0;
    if (a[0]) {
        std::vector<uint8_t> buf(4, 0);
        write_le(buf, 0, INTERNET_CONNECTION_LAN, 4);
        we(e)->mem_write(a[0], buf);
        a[0] = "INTERNET_CONNECTION_LAN";
    }
    (void)a[1]; (void)ctx; return 1;
}

//  HttpSendRequest 
uint64_t Wininet::HttpSendRequest(void* e, ArgList& a, void* ctx) {
    if (a.size() < 5) return 0;
    ApiContext* actx = (ApiContext*)ctx;
    int cw = get_char_width(actx);
    if (a[1]) { a[1] = be(e)->read_mem_string(a[1], cw); }
    std::vector<uint8_t> body;
    if (a[3]) body = we(e)->mem_read(a[3], static_cast<size_t>(a[4]));
    auto nm = we(e)->get_network_manager();
    auto* req = static_cast<WininetRequest*>(nm->get_wininet_object(static_cast<uint32_t>(a[0])));
    if (!req) return 0;
    std::string srv = req->get_server();
    int port = req->get_port();
    // Python: if not is_ip_address(srv): self.record_dns_event(srv)
    if (!srv.empty() && srv.find_first_not_of("0123456789.") != std::string::npos) {
        auto prof = be(e)->get_profiler();
        if (prof) {
            auto run = std::static_pointer_cast<Run>(we(e)->get_current_run());
            prof->record_dns_event(run, srv, "");
        }
    }
    std::string req_str = req->format_http_request(
        a[1].is_uint64() ? "" : a[1].as_string());
    auto prof = be(e)->get_profiler();
    if (prof) {
        auto run = std::static_pointer_cast<Run>(we(e)->get_current_run());
        prof->record_http_event(run, srv, port, "wininet", req_str, body, req->is_secure());
    }
    return 1;
}

//  InternetErrorDlg 
uint64_t Wininet::InternetErrorDlg(void* e, ArgList& a, void* ctx) {
    (void)e; (void)a; (void)ctx; return 0;
}

//  InternetQueryOption 
uint64_t Wininet::InternetQueryOption(void* e, ArgList& a, void* ctx) {
    if (a.size() < 4) return 0;
    uint32_t opt = static_cast<uint32_t>(a[1]);
    // Python: opt = windefs.get_option_define(dwOption); argv[1] = opt
    if (opt == 0x1B) a[1] = "INTERNET_OPTION_SECURITY_FLAGS";
    if (opt == 0x1B && a[2]) {
        std::vector<uint8_t> buf(4,0); write_le(buf,0,1,4); // SECURITY_FLAG_SECURE
        we(e)->mem_write(a[2], buf);
    }
    (void)a[0]; (void)a[3]; (void)ctx; return 1;
}

//  InternetReadFile 
uint64_t Wininet::InternetReadFile(void* e, ArgList& a, void* ctx) {
    if (a.size() < 4) return 0;
    auto nm = we(e)->get_network_manager();
    auto* req = static_cast<WininetRequest*>(nm->get_wininet_object(static_cast<uint32_t>(a[0])));
    std::vector<uint8_t> data;
    if (req) {
        auto resp = req->get_response();
        if (resp) { std::string s = resp->str(); data.assign(s.begin(), s.end()); }
    }
    if (a[1]) we(e)->mem_write(a[1], data);
    if (a[3]) {
        std::vector<uint8_t> sz(4,0); write_le(sz,0,(uint32_t)data.size(),4);
        we(e)->mem_write(a[3], sz);
    }
    (void)a[2]; (void)ctx; return 1;
}

//  HttpQueryInfo 
uint64_t Wininet::HttpQueryInfo(void* e, ArgList& a, void* ctx) {
    if (a.size() < 5) return 0;
    ApiContext* actx = (ApiContext*)ctx;
    int cw = get_char_width(actx);
    uint32_t info = static_cast<uint32_t>(a[1]);
    // Python: info_str = windefs.get_header_query(dwInfoLevel); argv[1] = info_str
    if (info == 0x13) a[1] = "HTTP_QUERY_STATUS_CODE";
    if (!a[2]) return 0; // ERROR_INSUFFICIENT_BUFFER
    if ((info & 0xFFFF) == 0x13 || info == 0x13) {
        std::string status = "200";
        if (cw == 2) {
            std::vector<uint8_t> out;
            for (char ch : status) { out.push_back((uint8_t)ch); out.push_back(0); }
            out.push_back(0); out.push_back(0);
            we(e)->mem_write(a[2], out);
        } else {
            we(e)->mem_write(a[2], {(uint8_t)'2',(uint8_t)'0',(uint8_t)'0',0});
        }
        if (a[3]) { std::vector<uint8_t> sz(4,0); write_le(sz,0,cw==2?8u:4u,4); we(e)->mem_write(a[3],sz); }
    }
    (void)a[4]; return 1;
}

//  InternetQueryDataAvailable 
uint64_t Wininet::InternetQueryDataAvailable(void* e, ArgList& a, void* ctx) {
    if (a.size() < 2) return 0;
    auto nm = we(e)->get_network_manager();
    auto* req = static_cast<WininetRequest*>(nm->get_wininet_object(static_cast<uint32_t>(a[0])));
    size_t avail = req ? req->get_response_size() : 0;
    if (a[1]) { std::vector<uint8_t> sz(4,0); write_le(sz,0,(uint32_t)avail,4); we(e)->mem_write(a[1],sz); }
    (void)a[2]; (void)a[3]; (void)ctx; return avail > 0 ? 1 : 0;
}

//  InternetCloseHandle 
uint64_t Wininet::InternetCloseHandle(void* e, ArgList& a, void* ctx) {
    if (a.size() < 1) return 0;
    auto nm = we(e)->get_network_manager();
    nm->close_wininet_object(static_cast<uint32_t>(a[0]));
    (void)e; (void)ctx; return 1;
}

//  InternetOpenUrl 
// Python reference implementation; uses ApiContext, netman, urlparse-style parsing
uint64_t Wininet::InternetOpenUrl(void* e, ArgList& a, void* ctx) {
    if (a.size() < 6) return 0;
    ApiContext* actx = (ApiContext*)ctx;
    int cw = get_char_width(actx);
    if (a[1]) { a[1] = be(e)->read_mem_string(a[1], cw); }
    if (a[2]) { a[2] = be(e)->read_mem_string(a[2], cw); }
    // Python: defs = windefs.get_flag_defines(dwFlags); argv[4] = " | ".join(defs)
    std::string flag_str = "0x" + std::to_string(static_cast<uint64_t>(a[4]));
    (void)flag_str;

    auto nm = we(e)->get_network_manager();
    auto* wini = static_cast<WininetInstance*>(nm->get_wininet_object(static_cast<uint32_t>(a[0])));
    if (!wini) return 0;

    std::string url = a[1].is_uint64() ? "" : a[1].as_string();
    // Parse URL for scheme/host/port
    std::string host; int port = 80; bool secure = false;
    bool is_https = (url.find("https://") == 0 || url.find("HTTPS://") == 0);
    bool is_http  = (url.find("http://") == 0 || url.find("HTTP://") == 0);
    size_t scheme_end = is_https ? 8 : (is_http ? 7 : 0);
    if (is_https) { secure = true; port = 443; }
    size_t host_end = url.find_first_of("/:", scheme_end);
    if (host_end != std::string::npos) {
        host = url.substr(scheme_end, host_end - scheme_end);
        if (url[host_end] == ':') {
            size_t pe = url.find('/', host_end);
            std::string ps = (pe != std::string::npos) ? url.substr(host_end+1, pe-host_end-1) : url.substr(host_end+1);
            try { port = std::stoi(ps); } catch (...) {}
        }
    } else if (scheme_end > 0) {
        host = url.substr(scheme_end);
    }

    // Log HTTP event (Python: self.record_http_event(crack.netloc, port, ...))
    auto prof = be(e)->get_profiler();
    if (prof) {
        auto run = std::static_pointer_cast<Run>(we(e)->get_current_run());
        prof->record_http_event(run, host, port, "wininet",
            "GET " + url + " HTTP/1.1\r\n\r\n", {}, secure);
    }

    // Create session + request via netman (Python: wini.new_session + sess.new_request)
    std::string headers = a[2].is_uint64() ? "" : a[2].as_string();
    auto sess = wini->new_session(host, port, "", "", 0, {flag_str}, static_cast<uint32_t>(a[5]));
    if (!sess) return 0;
    auto req = sess->new_request("GET", url, "", "", {}, {flag_str}, static_cast<uint32_t>(a[5]));
    return req ? req->get_handle() : 0;
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
