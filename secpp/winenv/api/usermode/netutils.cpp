// netutils.cpp  netutils.dll handler (real implementations)
#include "netutils.h"
#include <cstdint>
#include <string>
#include <vector>
#include "windows/winemu.h"
#include "struct.h"
#include "../../deffs/windows/netapi32.h"

using namespace speakeasy;

namespace speakeasy { namespace api {

static inline WindowsEmulator* we(void* e) { return static_cast<WindowsEmulator*>(e); }
static inline BinaryEmulator* be(void* e) { return static_cast<BinaryEmulator*>(e); }

// 
//  NetApiBufferFree
// 
uint64_t NetUtils::NetApiBufferFree(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a;
    return deffs::windows::NERR_Success;
}

//  Constructor 
NetUtils::NetUtils(void* emu) : ApiHandler(emu) {
    INIT_API_TABLE(NetUtils)
    REG(NetUtils, NetApiBufferFree, 1)
    END_API_TABLE
}

}} // namespaces
