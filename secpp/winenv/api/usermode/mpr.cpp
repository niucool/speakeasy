// mpr.cpp  mpr.dll handler (real implementations)
#include "mpr.h"
#include <cstring>
#include <cstdint>
#include <string>
#include <vector>
#include "windows/winemu.h"
#include "winenv/deffs/windows/mpr.h"

// Suppress Windows SDK macro pollution (WNetOpenEnum -> WNetOpenEnumA, etc.)
#ifdef _WIN32
#pragma push_macro("WNetOpenEnum")
#pragma push_macro("WNetEnumResource")
#pragma push_macro("WNetAddConnection2")
#pragma push_macro("WNetGetConnection")
#undef WNetOpenEnum
#undef WNetEnumResource
#undef WNetAddConnection2
#undef WNetGetConnection
#endif

using namespace speakeasy;

namespace speakeasy { namespace api {

static inline WindowsEmulator* we(void* e) { return static_cast<WindowsEmulator*>(e); }
static inline BinaryEmulator* be(void* e) { return static_cast<BinaryEmulator*>(e); }
static inline int ptr_sz(void* e) { return (be(e)->get_arch() == speakeasy::arch::ARCH_AMD64) ? 8 : 4; }

namespace mpr_defs = speakeasy::defs::new_structs;

Mpr::Mpr(void* emu) : ApiHandler(emu) {
    INIT_API_TABLE(Mpr)
    REG(Mpr, WNetOpenEnum, 5)
    REG(Mpr, WNetEnumResource, 4)
    REG(Mpr, WNetAddConnection2, 4)
    REG(Mpr, WNetGetConnection, 3)
    END_API_TABLE
}

// 
//  WNetOpenEnum  start network resource enumeration
// 
uint64_t Mpr::WNetOpenEnum(void* e, const std::vector<uint64_t>& a, void* ctx) {
    uint64_t dwScope = a[0];
    uint64_t dwType = a[1];
    uint64_t dwUsage = a[2];
    uint64_t lpNetResource = a[3];
    uint64_t lphEnum = a[4];
    (void)lpNetResource;

    // Map scope constants for logging
    uint32_t scope = static_cast<uint32_t>(dwScope);
    uint32_t type = static_cast<uint32_t>(dwType);
    uint32_t usage = static_cast<uint32_t>(dwUsage);
    (void)scope; (void)type; (void)usage;

    // Return a fake enum handle if requested
    if (lphEnum) {
        uint64_t fake_handle = 0x1234;
        std::vector<uint8_t> hbuf(ptr_sz(e), 0);
        speakeasy::write_le(hbuf, 0, fake_handle, ptr_sz(e));
        we(e)->mem_write(lphEnum, hbuf);
    }

    return mpr_defs::ERROR_NO_NETWORK;
}

// 
//  WNetEnumResource  continue network resource enumeration
// 
uint64_t Mpr::WNetEnumResource(void* e, const std::vector<uint64_t>& a, void* ctx) {
    uint64_t hEnum = a[0];
    uint64_t lpcCount = a[1];
    uint64_t lpBuffer = a[2];
    uint64_t lpBufferSize = a[3];
    (void)hEnum; (void)lpcCount; (void)lpBuffer; (void)lpBufferSize;

    return mpr_defs::ERROR_NO_NETWORK;
}

// 
//  WNetAddConnection2  add a network connection
// 
uint64_t Mpr::WNetAddConnection2(void* e, const std::vector<uint64_t>& a, void* ctx) {
    uint64_t lpNetResource = a[0];
    uint64_t lpPassword = a[1];
    uint64_t lpUserName = a[2];
    uint64_t dwFlags = a[3];
    (void)lpPassword; (void)lpUserName; (void)dwFlags;

    // Log the remote resource if provided
    if (lpNetResource) {
        auto prof = be(e)->get_profiler();
        if (prof) {
            auto run = std::static_pointer_cast<Run>(we(e)->get_current_run());
            prof->log_network(run, "", 0, "connect", "smb");
        }
    }

    return mpr_defs::ERROR_NO_NETWORK;
}

// 
//  WNetGetConnection  get remote name for redirected local device
// 
uint64_t Mpr::WNetGetConnection(void* e, const std::vector<uint64_t>& a, void* ctx) {
    uint64_t lpLocalName = a[0];
    uint64_t lpRemoteName = a[1];
    uint64_t lpnLength = a[2];
    (void)lpRemoteName; (void)lpnLength;

    if (lpLocalName) {
        std::string local_name = be(e)->read_mem_string(lpLocalName, 2);
        if (local_name.empty()) local_name = be(e)->read_mem_string(lpLocalName, 1);
        (void)local_name;
    }

    return mpr_defs::ERROR_NO_NETWORK;
}

}} // namespaces
