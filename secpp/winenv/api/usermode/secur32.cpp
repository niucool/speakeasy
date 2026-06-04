// secur32.cpp  secur32.dll handler (real implementations)
#include "secur32.h"
#include <cstring>
#include <cstdint>
#include <string>
#include <vector>
#include "windows/winemu.h"
#include "struct.h"

using namespace speakeasy;

namespace speakeasy { namespace api {

static inline WindowsEmulator* we(void* e) { return static_cast<WindowsEmulator*>(e); }
static inline BinaryEmulator* be(void* e) { return static_cast<BinaryEmulator*>(e); }

//  Constants (S32_ prefix to avoid Windows macro conflicts) 
static constexpr uint32_t S32_SEC_E_INVALID_HANDLE = 0x80090301;

// 
//  GetUserNameEx
// 
uint64_t Secur32::GetUserNameEx(void* e, const std::vector<uint64_t>& a, void* ctx) {
    if (a.size() < 3) return 0;
    uint32_t NameFormat = static_cast<uint32_t>(a[0]);
    uint64_t lpNameBuffer = a[1];
    uint64_t nSize = a[2];
    (void)NameFormat;

    if (!nSize) return 0;

    std::string user_name = "EmulatedUser";

    int cw = 1;  // ANSI

    size_t needed_size = (user_name.size() + 1) * cw;

    auto len_raw = we(e)->mem_read(nSize, 4);
    uint32_t buf_size = static_cast<uint32_t>(read_le(len_raw, 0, 4));

    if (!lpNameBuffer || buf_size < needed_size) {
        std::vector<uint8_t> sz(4, 0);
        write_le(sz, 0, static_cast<uint64_t>(needed_size), 4);
        we(e)->mem_write(nSize, sz);
        return 0; // FALSE
    }

    // Write the username to the buffer (ANSI)
    std::vector<uint8_t> buf(needed_size, 0);
    memcpy(buf.data(), user_name.c_str(), user_name.size());
    we(e)->mem_write(lpNameBuffer, buf);

    std::vector<uint8_t> sz(4, 0);
    write_le(sz, 0, static_cast<uint64_t>(needed_size), 4);
    we(e)->mem_write(nSize, sz);

    return 1; // TRUE
}

// 
//  EncryptMessage
// 
uint64_t Secur32::EncryptMessage(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a;
    return S32_SEC_E_INVALID_HANDLE;
}

//  Constructor 
Secur32::Secur32(void* emu) : ApiHandler(emu) {
    INIT_API_TABLE(Secur32)
    REG(Secur32, GetUserNameEx, 3)
    REG(Secur32, EncryptMessage, 4)
    END_API_TABLE
}

}} // namespaces
