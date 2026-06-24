// urlmon.cpp  urlmon.dll handler (real implementations)
#include "urlmon.h"
#include <cstdint>
#include <string>
#include <vector>
#include "windows/winemu.h"

//  Windows SDK macro conflict protection 
#ifdef _WIN32
#pragma push_macro("S_OK")
#pragma push_macro("ERROR_SUCCESS")
#pragma push_macro("ERROR_INSUFFICIENT_BUFFER")
#undef S_OK
#undef ERROR_SUCCESS
#undef ERROR_INSUFFICIENT_BUFFER
#endif

using namespace speakeasy;

namespace speakeasy { namespace api {


// Local error code constants (avoids dependency on windows.h SDK macros)
static constexpr uint32_t URLMON_S_OK = 0;
static constexpr uint32_t URLMON_ERROR_SUCCESS = 0;
static constexpr uint32_t URLMON_ERROR_INSUFFICIENT_BUFFER = 122;

std::string get_netloc(const std::string& url) {
    if (url.empty()) {
        return "";
    }

    // Find the position of the scheme separator "://"
    size_t scheme_end = url.find("://");
    size_t start = 0;

    if (scheme_end != std::string::npos) {
        // Skip past "://"
        start = scheme_end + 3;
    }
    else {
        // Handle URLs that start with "//" (protocol-relative)
        if (url.rfind("//", 0) == 0) {
            start = 2;
        }
    }

    // Find where the netloc ends (at the next '/', '?', or '#')
    size_t end = url.find_first_of("/?#", start);

    if (end == std::string::npos) {
        return url.substr(start);
    }

    return url.substr(start, end - start);
}

Urlmon::Urlmon(void* emu) : ApiHandler(emu) {
    INIT_API_TABLE(Urlmon)
    REG(Urlmon, URLDownloadToFile, 5)
    REG(Urlmon, URLDownloadToCacheFile, 6)
    END_API_TABLE
}

// 
//  URLDownloadToFile
// 
uint64_t Urlmon::URLDownloadToFile(void* e, ArgList& a, void* ctx) {
    // HRESULT URLDownloadToFile(
    //     LPUNKNOWN            pCaller,    // a[0]
    //     LPCTSTR              szURL,      // a[1]
    //     LPCTSTR              szFileName, // a[2]
    //     DWORD                dwReserved, // a[3]
    //     LPBINDSTATUSCALLBACK lpfnCB      // a[4]
    // );
    uint64_t pCaller = a[0];
    uint64_t szURL = a[1];
    uint64_t szFileName = a[2];
    uint64_t dwReserved = a[3];
    uint64_t lpfnCB = a[4];
    (void)pCaller; (void)dwReserved; (void)lpfnCB;

    int cw = get_char_width(static_cast<ApiContext*>(ctx));
 
    if (szURL) {
        std::string url = be(e)->read_mem_string(szURL, cw);
        auto prof = be(e)->get_profiler();
        if (prof) {
            auto run = std::static_pointer_cast<Run>(we(e)->get_current_run());
            prof->record_dns_event(run, url, 0);
            prof->record_network_event(run, url, 80, "http", "tcp");
        }
    }

    if (szFileName) {
        std::string name = be(e)->read_mem_string(szFileName, cw);
        auto prof = be(e)->get_profiler();
        if (prof) {
            auto run = std::static_pointer_cast<Run>(we(e)->get_current_run());
            prof->record_file_access_event(run, name, "CREATE");
            prof->record_file_access_event(run, name, "WRITE");
        }
    }

    return URLMON_ERROR_SUCCESS;
}

// 
//  URLDownloadToCacheFile
// 
uint64_t Urlmon::URLDownloadToCacheFile(void* e, ArgList& a, void* ctx) {
    // HRESULT URLDownloadToCacheFile(
    //     LPUNKNOWN            pCaller,      // a[0]
    //     LPCSTR               szURL,        // a[1]
    //     LPSTR                szFileName,   // a[2]
    //     DWORD                cchFileName,  // a[3]
    //     DWORD                dwReserved,   // a[4]
    //     LPBINDSTATUSCALLBACK lpfnCB        // a[5]
    // );
    uint64_t pCaller = a[0];
    uint64_t szURL = a[1];
    uint64_t szFileName = a[2];
    uint64_t cchFileName = a[3];
    uint64_t dwReserved = a[4];
    uint64_t lpfnCB = a[5];
    (void)pCaller; (void)dwReserved; (void)lpfnCB;

    uint32_t rv = URLMON_ERROR_SUCCESS;

    int cw = get_char_width(static_cast<ApiContext*>(ctx));

    // Default cache path
    std::string cache_name = "C:\\Windows\\Temp\\urlcache.bin";
    auto prof = be(e)->get_profiler();
    auto run = we(e)->get_current_run();

    if (szURL) {
        std::string url = be(e)->read_mem_string(szURL, cw);
		a[1] = url; // Update the argument with the actual URL string
        if (prof) {
            prof->record_dns_event(run, get_netloc(url));
            //prof->record_network_event(run, url, 80, "http", "tcp");
        }
        // Try to extract filename from URL
        size_t last_slash = url.rfind('/');
        if (last_slash != std::string::npos) {
            std::string tail = url.substr(last_slash + 1);
            if (!tail.empty()) {
                cache_name = "C:\\Windows\\Temp\\" + tail;
            }
        }
    }

    if (szFileName) {
        uint32_t required = static_cast<uint32_t>(cache_name.size() + 1);
		a[2] = cache_name; // Update the argument with the actual cache filename
		a[3] = cchFileName; // Update the argument with the actual buffer size
        if (cchFileName >= required) {
            be(e)->write_mem_string(cache_name, szFileName, cw);
            if (prof) {
                prof->record_file_access_event(run, cache_name, speakeasy::events::FILE_CREATE);
                prof->record_file_access_event(run, cache_name, speakeasy::events::FILE_WRITE);
                //prof->record_network_event(run, url, 80, "http", "tcp");
            }
        } else {
            rv = URLMON_ERROR_INSUFFICIENT_BUFFER;
        }
    }

    return rv;
}

}} // namespaces

//  Pop SDK macros 
#ifdef _WIN32
#pragma pop_macro("ERROR_INSUFFICIENT_BUFFER")
#pragma pop_macro("ERROR_SUCCESS")
#pragma pop_macro("S_OK")
#endif
