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

static inline WindowsEmulator* we(void* e) { return static_cast<WindowsEmulator*>(e); }
static inline BinaryEmulator* be(void* e) { return static_cast<BinaryEmulator*>(e); }

// Local error code constants (avoids dependency on windows.h SDK macros)
static constexpr uint32_t URLMON_S_OK = 0;
static constexpr uint32_t URLMON_ERROR_SUCCESS = 0;
static constexpr uint32_t URLMON_ERROR_INSUFFICIENT_BUFFER = 122;

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

    if (szURL) {
        std::string url = be(e)->read_mem_string(szURL, 1);
        auto prof = be(e)->get_profiler();
        if (prof) {
            auto run = std::static_pointer_cast<Run>(we(e)->get_current_run());
            prof->log_dns(run, url, 0);
            prof->log_network(run, url, 80, "http", "tcp");
        }
    }

    if (szFileName) {
        std::string name = be(e)->read_mem_string(szFileName, 1);
        auto prof = be(e)->get_profiler();
        if (prof) {
            auto run = std::static_pointer_cast<Run>(we(e)->get_current_run());
            prof->log_file_access(run, name, "CREATE");
            prof->log_file_access(run, name, "WRITE");
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

    // Default cache path
    std::string cache_name = "C:\\Windows\\Temp\\urlcache.bin";

    if (szURL) {
        std::string url = be(e)->read_mem_string(szURL, 1);
        auto prof = be(e)->get_profiler();
        if (prof) {
            auto run = std::static_pointer_cast<Run>(we(e)->get_current_run());
            prof->log_dns(run, url, 0);
            prof->log_network(run, url, 80, "http", "tcp");
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
        if (cchFileName >= required) {
            be(e)->write_mem_string(cache_name, szFileName, 1);
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
