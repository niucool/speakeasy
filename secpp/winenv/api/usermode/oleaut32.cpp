// oleaut32.cpp  oleaut32.dll handler (~4 APIs, real implementations)
#include "oleaut32.h"

#include <cstring>
#include <vector>
#include <string>

#include "memmgr.h"
#include "struct.h"
#include "winenv/arch.h"
#include "windows/winemu.h"

using namespace speakeasy;

namespace speakeasy { namespace api {

//  Typed cast helpers 
static inline WindowsEmulator* we(void* e) {
    return static_cast<WindowsEmulator*>(e);
}
static inline BinaryEmulator* be(void* e) {
    return static_cast<BinaryEmulator*>(e);
}
static inline int ptr_sz(void* e) {
    return (be(e)->get_arch() == speakeasy::arch::ARCH_AMD64) ? 8 : 4;
}

//  Constructor 

Oleaut32::Oleaut32(void* emu) : ApiHandler(emu) {
    INIT_API_TABLE(Oleaut32)
    REG(Oleaut32, SysAllocString, 1)
    REG(Oleaut32, SysAllocStringLen, 2)
    REG(Oleaut32, SysFreeString, 1)
    REG(Oleaut32, VariantInit, 1)
    END_API_TABLE
}

//  API implementations 

uint64_t Oleaut32::SysAllocString(void* e, std::vector<uint64_t>& a, void* ctx) {
    uint64_t psz = a[0];
    if (!psz) return 0;

    std::string ws = be(e)->read_mem_string(psz, 2);
    if (ws.empty()) return 0;

    ws.push_back('\0');
    std::vector<uint8_t> wide_str;
    for (size_t i = 0; i < ws.size(); i++) {
        wide_str.push_back(static_cast<uint8_t>(ws[i]));
        wide_str.push_back(0);
    }

    uint32_t bstr_len = static_cast<uint32_t>(wide_str.size()) - 2;
    size_t total_size = 4 + wide_str.size();
    uint64_t bstr = static_cast<MemoryManager*>(we(e))->mem_map(total_size, 0, PERM_MEM_RWX, "oleaut32.SysAllocString");

    std::vector<uint8_t> len_bytes(4);
    write_le(len_bytes, 0, bstr_len, 4);
    be(e)->mem_write(bstr, len_bytes);
    be(e)->mem_write(bstr + 4, wide_str);

    return bstr + 4;
}

uint64_t Oleaut32::SysAllocStringLen(void* e, std::vector<uint64_t>& a, void* ctx) {
    uint64_t strin = a[0], ui = a[1];

    size_t ws_len = static_cast<size_t>(ui + 1) * 2;
    size_t total_size = 4 + ws_len;
    uint64_t bstr = static_cast<MemoryManager*>(we(e))->mem_map(total_size, 0, PERM_MEM_RWX, "oleaut32.SysAllocStringLen");

    uint32_t bstr_len = static_cast<uint32_t>(ui * 2);
    std::vector<uint8_t> len_bytes(4);
    write_le(len_bytes, 0, bstr_len, 4);
    be(e)->mem_write(bstr, len_bytes);

    if (strin) {
        std::string ws = be(e)->read_mem_string(strin, 2);
        if (!ws.empty()) {
            if (ws.size() > static_cast<size_t>(ui))
                ws.resize(static_cast<size_t>(ui));
            ws.push_back('\0');
            std::vector<uint8_t> wide_str;
            for (size_t i = 0; i < ws.size(); i++) {
                wide_str.push_back(static_cast<uint8_t>(ws[i]));
                wide_str.push_back(0);
            }
            be(e)->mem_write(bstr + 4, wide_str);
        } else {
            std::vector<uint8_t> zeros(ws_len, 0);
            be(e)->mem_write(bstr + 4, zeros);
        }
    } else {
        std::vector<uint8_t> zeros(ws_len, 0);
        be(e)->mem_write(bstr + 4, zeros);
    }
    return bstr + 4;
}

uint64_t Oleaut32::SysFreeString(void* e, std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a;
    return 0;
}

uint64_t Oleaut32::VariantInit(void* e, std::vector<uint64_t>& a, void* ctx) {
    uint64_t pvarg = a[0];
    if (pvarg) {
        size_t var_size = (ptr_sz(e) == 8) ? 0x18 : 0x10;
        std::vector<uint8_t> zeros(var_size, 0);
        be(e)->mem_write(pvarg, zeros);
    }
    return 0;
}

}} // namespaces
