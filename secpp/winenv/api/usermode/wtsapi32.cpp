// wtsapi32.cpp  wtsapi32.dll handler (real implementations)
#include "wtsapi32.h"
#include <cstring>
#include <cstdint>
#include <string>
#include <vector>
#include "windows/winemu.h"

using namespace speakeasy;

namespace speakeasy { namespace api {

static inline int ptr_sz(void* e) { return (be(e)->get_arch() == speakeasy::arch::ARCH_AMD64) ? 8 : 4; }

// WTS_SESSION_INFO structure layout:
//   SessionId         DWORD   0
//   pWinStationName   PTR     ptr_sz bytes (after padding)
//   State             DWORD   (after pointer)
static constexpr uint32_t WTS_CURRENT_SERVER = 0;
static constexpr uint32_t WTSActive = 0;

Wtsapi32::Wtsapi32(void* emu) : ApiHandler(emu) {
    INIT_API_TABLE(Wtsapi32)
    REG(Wtsapi32, WTSEnumerateSessions, 5)
    REG(Wtsapi32, WTSFreeMemory, 1)
    END_API_TABLE
}

// 
//  WTSEnumerateSessions  enumerate terminal server sessions
// 
uint64_t Wtsapi32::WTSEnumerateSessions(void* e, ArgList& a, void* ctx) {
    uint64_t hServer = a[0];
    uint64_t Reserved = a[1];
    uint64_t Version = a[2];
    uint64_t ppSessionInfo = a[3];
    uint64_t pCount = a[4];
    (void)hServer; (void)Reserved; (void)Version;

    int ps = ptr_sz(e);

    // Build a fake session: "RDP-Tcp#1"
    std::string winstat_name = "RDP-Tcp#1";
    std::string winstat_name_wide = winstat_name + '\0';
    std::vector<uint8_t> sn_bytes(winstat_name_wide.begin(), winstat_name_wide.end());

    // Calculate structure size:
    // SessionId (4) + padding (ps == 8 ? 4 : 0) + pWinStationName (ps) + State (4)
    uint32_t struct_size = 4;
    if (ps == 8) struct_size += 4; // padding for alignment
    struct_size += static_cast<uint32_t>(ps);
    struct_size += 4;

    uint32_t total_size = struct_size + static_cast<uint32_t>(sn_bytes.size());
    // Allocate buffer via mem_map
    uint64_t buf = static_cast<MemoryManager*>(we(e))->mem_map(total_size, 0, common::PERM_MEM_RWX, "api.WTSEnumerateSessions");

    // Write SessionId = 1
    {
        std::vector<uint8_t> sid(4, 0);
        speakeasy::write_le(sid, 0, static_cast<uint64_t>(1), 4);
        we(e)->mem_write(buf, sid);
    }

    // Write pWinStationName pointer (points to after the structure)
    uint64_t name_ptr = buf + struct_size;
    {
        std::vector<uint8_t> ptr_buf(ps, 0);
        speakeasy::write_le(ptr_buf, 0, name_ptr, ps);
        uint64_t ptr_offset = buf + 4;
        if (ps == 8) ptr_offset = buf + 8; // after padding on x64
        we(e)->mem_write(ptr_offset, ptr_buf);
    }

    // Write State = WTSActive (0)
    {
        uint64_t state_offset = buf + 4 + (ps == 8 ? 4 : 0) + ps;
        std::vector<uint8_t> s(4, 0);
        speakeasy::write_le(s, 0, static_cast<uint64_t>(WTSActive), 4);
        we(e)->mem_write(state_offset, s);
    }

    // Write the station name string
    we(e)->mem_write(name_ptr, sn_bytes);

    // Write pCount = 1
    if (pCount) {
        std::vector<uint8_t> cnt(4, 0);
        speakeasy::write_le(cnt, 0, static_cast<uint64_t>(1), 4);
        we(e)->mem_write(pCount, cnt);
    }

    // Write ppSessionInfo = buf address
    if (ppSessionInfo) {
        std::vector<uint8_t> ptr_ps(ps, 0);
        speakeasy::write_le(ptr_ps, 0, buf, ps);
        we(e)->mem_write(ppSessionInfo, ptr_ps);
    }

    return 1; // TRUE
}

// 
//  WTSFreeMemory  free memory allocated by WTS APIs
// 
uint64_t Wtsapi32::WTSFreeMemory(void* e, ArgList& a, void* ctx) {
    uint64_t pMemory = a[0];

    if (pMemory) {
        static_cast<MemoryManager*>(we(e))->mem_free(pMemory);
    }

    return 1; // TRUE
}

}} // namespaces
