// dnsapi.cpp  dnsapi.dll handler (real implementation)
#include "dnsapi.h"
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

//  DNS constants (DNS_ prefix to avoid Windows macro conflicts) 
static constexpr uint32_t DNS_TEXT = 0x0010;
static constexpr uint32_t DNS_A = 0x0001;
static constexpr uint32_t DNS_OK = 0;

// 
//  DnsQuery_
// 
uint64_t DnsApi::DnsQuery_(void* e, std::vector<uint64_t>& a, void* ctx) {
    if (a.size() < 6) return 87; // ERROR_INVALID_PARAMETER
    uint64_t pszName = a[0];
    uint16_t wType = static_cast<uint16_t>(a[1] & 0xFFFF);
    uint32_t Options = static_cast<uint32_t>(a[2]);
    uint64_t pExtra = a[3];
    uint64_t ppQueryResults = a[4];
    uint64_t pReserved = a[5];
    (void)Options; (void)pExtra; (void)pReserved;

    if (!pszName) return 123; // ERROR_INVALID_NAME

    // Read the hostname (try wide first, then narrow)
    std::string name = be(e)->read_mem_string(pszName, 2);
    if (name.empty()) {
        name = be(e)->read_mem_string(pszName, 1);
    }

    if (name.empty()) return 123; // ERROR_INVALID_NAME

    // Log DNS lookup via profiler
    auto prof = be(e)->get_profiler();
    if (prof) {
        auto run = std::static_pointer_cast<Run>(we(e)->get_current_run());
        prof->log_dns(run, name, "");
    }

    if (!ppQueryResults) return 87; // ERROR_INVALID_PARAMETER

    int ps = we(e)->get_ptr_size();

    // DNS_RECORD structure layout (simplified):
    //   pNext          ptr    0
    //   pName          ptr    ps
    //   wType          WORD   ps*2
    //   wDataLength    WORD   ps*2 + 2
    //   Flags          DWORD  ps*2 + 4
    //   dwTtl          DWORD  ps*2 + 8
    //   dwReserved     DWORD  ps*2 + 12
    //   Data (union)          ps*2 + 16

    size_t hdr_size = static_cast<size_t>(ps * 2) + 16;
    size_t data_size = 4;  // default for A record (IP address)

    if (wType == DNS_TEXT) {
        std::string txt = "v=spf1 include:_spf.google.com ~all";
        data_size = 4 + static_cast<size_t>(ps) + 1 + txt.size();
    }

    size_t record_size = hdr_size + data_size;

    // Allocate memory for the record
    uint64_t rec_addr = we(e)->mem_map(record_size, 0, PERM_MEM_READ | PERM_MEM_WRITE, "api.dnsapi.DnsRecord");
    std::vector<uint8_t> buf(record_size, 0);

    // pNext = 0 (NULL)
    write_le(buf, 0, 0, ps);
    write_le(buf, ps, pszName, ps);
    write_le(buf, ps * 2, wType, 2);
    write_le(buf, ps * 2 + 2, 0, 2);      // wDataLength (filled below)
    write_le(buf, ps * 2 + 4, 0, 4);       // Flags
    write_le(buf, ps * 2 + 8, 300, 4);     // dwTtl = 300
    write_le(buf, ps * 2 + 12, 0, 4);      // dwReserved

    if (wType == DNS_A) {
        // IP4 address: 8.8.8.8 = 0x08080808
        write_le(buf, hdr_size, 0x08080808, 4);
        write_le(buf, ps * 2 + 2, 4, 2);   // wDataLength = 4
    } else if (wType == DNS_TEXT) {
        write_le(buf, hdr_size, 1, 4);       // dwStringCount = 1
        uint64_t str_arr_off = rec_addr + hdr_size + 4 + static_cast<size_t>(ps);
        write_le(buf, hdr_size + 4, str_arr_off, ps); // pStringArray
        std::string txt = "v=spf1 include:_spf.google.com ~all";
        write_le(buf, hdr_size + 4 + static_cast<size_t>(ps), static_cast<uint64_t>(txt.size()), 1);
        for (size_t i = 0; i < txt.size(); i++) {
            write_le(buf, hdr_size + 4 + static_cast<size_t>(ps) + 1 + i, static_cast<uint8_t>(txt[i]), 1);
        }
        uint16_t txt_data_size = static_cast<uint16_t>(4 + ps + 1 + txt.size());
        write_le(buf, ps * 2 + 2, txt_data_size, 2);
    } else {
        write_le(buf, hdr_size, 0, 4);
        write_le(buf, ps * 2 + 2, 0, 2);
    }

    we(e)->mem_write(rec_addr, buf);

    // Write pointer to result
    std::vector<uint8_t> ptr_buf(ps, 0);
    write_le(ptr_buf, 0, rec_addr, ps);
    we(e)->mem_write(ppQueryResults, ptr_buf);

    return DNS_OK;
}

//  Constructor 
DnsApi::DnsApi(void* emu) : ApiHandler(emu) {
    INIT_API_TABLE(DnsApi)
    REG(DnsApi, DnsQuery_, 6)
    END_API_TABLE
}

}} // namespaces
