// sfc_os.cpp  sfc_os.dll handler (real implementations, inherits sfc APIs)
#include "sfc_os.h"
#include <cstring>
#include <cstdint>
#include <string>
#include <vector>
#include "windows/winemu.h"

using namespace speakeasy;

namespace speakeasy { namespace api {

static inline WindowsEmulator* we(void* e) { return static_cast<WindowsEmulator*>(e); }
static inline BinaryEmulator* be(void* e) { return static_cast<BinaryEmulator*>(e); }

static constexpr uint32_t SFC_SUCCESS = 1;
static constexpr uint32_t SFC_ERROR = 0;

Sfc_os::Sfc_os(void* emu) : ApiHandler(emu) {
    INIT_API_TABLE(Sfc_os)
    REG(Sfc_os, SfcIsFileProtected, 2)  REG(Sfc_os, SfcTerminateWatcherThread, 0)
    END_API_TABLE
}

// 
//  SfcIsFileProtected  check if a file is protected by WFP
// 
uint64_t Sfc_os::SfcIsFileProtected(void* e, const std::vector<uint64_t>& a, void* ctx) {
    uint64_t hRpc = a[0];
    uint64_t pszProtFileName = a[1];
    (void)hRpc;

    if (pszProtFileName) {
        std::string path = be(e)->read_mem_string(pszProtFileName, 2);
        // Log file access
        auto prof = be(e)->get_profiler();
        if (prof && !path.empty()) {
            auto run = std::static_pointer_cast<Run>(we(e)->get_current_run());
            prof->log_file_access(run, path, "ACCESS");
        }
    }
    return SFC_ERROR;  // Return FALSE (not protected) to let operations proceed
}

// 
//  SfcTerminateWatcherThread  terminate the WFP watcher thread
// 
uint64_t Sfc_os::SfcTerminateWatcherThread(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a;
    return SFC_SUCCESS;
}

}} // namespaces
