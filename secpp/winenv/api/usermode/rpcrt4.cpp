// rpcrt4.cpp  rpcrt4.dll handler (real implementations)
#include "rpcrt4.h"
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include "windows/winemu.h"
#include "struct.h"

using namespace speakeasy;

namespace speakeasy { namespace api {

static inline WindowsEmulator* we(void* e) { return static_cast<WindowsEmulator*>(e); }
static inline BinaryEmulator* be(void* e) { return static_cast<BinaryEmulator*>(e); }

// 
//  UuidCreate
// 
uint64_t Rpcrt4::UuidCreate(void* e, ArgList& a, void* ctx) {
    if (a.size() < 1) return 1;
    uint64_t uuidp = a[0];

    if (!uuidp) return 1;  // RPC_S_INVALID_ARG

    // Build a 16-byte UUID (GUID)
    std::vector<uint8_t> buf(16);
    // Data1 (4 bytes, LE)
    uint32_t data1 = static_cast<uint32_t>(rand() & 0xFFFFFFFF);
    write_le(buf, 0, data1, 4);
    // Data2 (2 bytes, LE)
    uint16_t data2 = static_cast<uint16_t>(rand() & 0xFFFF);
    write_le(buf, 4, data2, 2);
    // Data3 (2 bytes, LE)
    uint16_t data3 = static_cast<uint16_t>(rand() & 0xFFFF);
    write_le(buf, 6, data3, 2);
    // Data4 (8 bytes)
    for (int i = 0; i < 8; i++) {
        buf[8 + i] = static_cast<uint8_t>(rand() & 0xFF);
    }

    we(e)->mem_write(uuidp, buf);
    return 0;  // RPC_S_OK
}

// 
//  UuidToStringA
// 
uint64_t Rpcrt4::UuidToStringA(void* e, ArgList& a, void* ctx) {
    if (a.size() < 2) return 1;
    uint64_t uuidp = a[0];
    uint64_t stringp = a[1];

    if (!uuidp || !stringp) return 1;  // RPC_S_INVALID_ARG

    // Read 16-byte UUID from memory
    std::vector<uint8_t> uuid_bytes = we(e)->mem_read(uuidp, 16);
    if (uuid_bytes.size() < 16) return 1;

    // Extract GUID fields
    uint32_t data1 = read_le(uuid_bytes, 0, 4);
    uint16_t data2 = static_cast<uint16_t>(read_le(uuid_bytes, 4, 2));
    uint16_t data3 = static_cast<uint16_t>(read_le(uuid_bytes, 6, 2));

    // Format as standard UUID string: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
    std::ostringstream oss;
    oss << std::hex << std::setfill('0')
        << std::setw(8) << data1 << '-'
        << std::setw(4) << data2 << '-'
        << std::setw(4) << data3 << '-';
    for (int i = 0; i < 2; i++)
        oss << std::setw(2) << static_cast<int>(uuid_bytes[8 + i]);
    oss << '-';
    for (int i = 2; i < 8; i++)
        oss << std::setw(2) << static_cast<int>(uuid_bytes[8 + i]);

    std::string result = oss.str();

    // Allocate memory for the result string and write pointer
    int ps = we(e)->get_ptr_size();
    size_t str_size = result.size() + 1;  // include null terminator
    uint64_t str_addr = we(e)->mem_map(str_size, 0, 3, "api.rpcrt4.UuidString");
    be(e)->write_mem_string(result, str_addr, 1);

    std::vector<uint8_t> ptr_buf(static_cast<size_t>(ps), 0);
    write_le(ptr_buf, 0, str_addr, ps);
    we(e)->mem_write(stringp, ptr_buf);

    return 0;  // RPC_S_OK
}

//  Constructor 
Rpcrt4::Rpcrt4(void* emu) : ApiHandler(emu) {
    INIT_API_TABLE(Rpcrt4)
    REG(Rpcrt4, UuidCreate, 1)
    REG(Rpcrt4, UuidToStringA, 2)
    END_API_TABLE
}

}} // namespaces
