// wkscli.cpp  wkscli.dll handler (real implementations)
#include "wkscli.h"
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
//  NetGetJoinInformation
// 
uint64_t Wkscli::NetGetJoinInformation(void* e, ArgList& a, void* ctx) {
    if (a.size() < 3) return 87;  // ERROR_INVALID_PARAMETER
    uint64_t lpServer = a[0];
    uint64_t lpNameBuffer = a[1];
    uint64_t BufferType = a[2];

    if (!lpNameBuffer || !BufferType) return 87;

    // Read server string (if provided)
    if (lpServer) {
        std::string server = be(e)->read_mem_string(lpServer, 2);
        (void)server;
    }

    // Get domain name from config
    std::string domain = be(e)->get_domain();
    if (domain.empty()) {
        domain = "WORKGROUP";
    }

    // Allocate memory for the name buffer
    int ps = we(e)->get_ptr_size();
    size_t str_size = domain.size() * 2 + 2;  // wide string
    uint64_t namebuf = we(e)->mem_map(str_size, 0, 3, "api.wkscli.NetGetJoinInformation.name");
    be(e)->write_mem_string(domain, namebuf, 2);

    // Write the pointer to the output buffer
    std::vector<uint8_t> ptr_buf(static_cast<size_t>(ps), 0);
    write_le(ptr_buf, 0, namebuf, ps);
    we(e)->mem_write(lpNameBuffer, ptr_buf);

    // Write the join status
    std::vector<uint8_t> status_buf(4, 0);
    write_le(status_buf, 0, static_cast<uint64_t>(deffs::windows::NetSetupDomainName), 4);
    we(e)->mem_write(BufferType, status_buf);

    return deffs::windows::NERR_Success;
}

//  Constructor 
Wkscli::Wkscli(void* emu) : ApiHandler(emu) {
    INIT_API_TABLE(Wkscli)
    REG(Wkscli, NetGetJoinInformation, 3)
    END_API_TABLE
}

}} // namespaces
