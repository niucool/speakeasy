// iphlpapi.cpp  iphlpapi.dll handler (real implementations)
#include "iphlpapi.h"
#include <cstring>
#include <cstdint>
#include <string>
#include <vector>
#include <map>
#include "windows/winemu.h"
#include "struct.h"

using namespace speakeasy;

namespace speakeasy { namespace api {

static inline int ptr_sz(void* e) { return we(e)->get_ptr_size(); }

//  Error constants (IPH_ prefix to avoid Windows macro conflicts) 
static constexpr uint32_t IPH_OK = 0;
static constexpr uint32_t IPH_BUF_OVERFLOW = 111;
static constexpr uint32_t IPH_INVALID_PARAM = 87;
static constexpr uint32_t IPH_NOT_SUPPORTED = 50;

//  Type constants 
static constexpr uint32_t MIB_IF_ETHERNET = 6;

// Fake default MAC
static std::vector<uint8_t> default_mac() {
    return {0x00, 0x0C, 0x29, 0xAB, 0xCD, 0xEF};
}

static uint32_t ip_to_int(const std::string& ip) {
    unsigned int b[4] = {192, 168, 1, 100};
    sscanf(ip.c_str(), "%u.%u.%u.%u", &b[0], &b[1], &b[2], &b[3]);
    return (b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3];
}

static uint32_t mask_to_int(const std::string& mask) {
    unsigned int b[4] = {255, 255, 255, 0};
    sscanf(mask.c_str(), "%u.%u.%u.%u", &b[0], &b[1], &b[2], &b[3]);
    return (b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3];
}

// 
//  GetAdaptersInfo
// 
uint64_t Iphlpapi::GetAdaptersInfo(void* e, ArgList& a, void* ctx) {
    if (a.size() < 2) return IPH_INVALID_PARAM;
    uint64_t pAdapterInfo = a[0];
    uint64_t pOutBufLen = a[1];
    if (!pOutBufLen) return IPH_INVALID_PARAM;

    int ps = ptr_sz(e);
    size_t struct_size = (ps == 8) ? 664 : 640;
    size_t ias_size = static_cast<size_t>(ps) + 16 + 16 + 4;

    auto len_raw = we(e)->mem_read(pOutBufLen, 4);
    uint32_t out_buf_len = static_cast<uint32_t>(read_le(len_raw, 0, 4));

    if (!pAdapterInfo || out_buf_len < struct_size) {
        std::vector<uint8_t> sz(4, 0);
        write_le(sz, 0, static_cast<uint64_t>(struct_size), 4);
        we(e)->mem_write(pOutBufLen, sz);
        return IPH_BUF_OVERFLOW;
    }

    std::vector<uint8_t> buf(struct_size, 0);
    speakeasy::write_string(buf, static_cast<size_t>(ps), "{DEFAULT-ADAPTER}", false);
    speakeasy::write_string(buf, static_cast<size_t>(ps) + 260, "Emulated Ethernet Adapter", false);
    write_le(buf, static_cast<size_t>(ps) + 260 + 132, 6, 4); // AddressLength
    auto mac = default_mac();
    for (size_t i = 0; i < mac.size() && i < 8; i++)
        write_le(buf, static_cast<size_t>(ps) + 260 + 132 + 4 + i, mac[i], 1);
    write_le(buf, static_cast<size_t>(ps) + 260 + 132 + 4 + 8, 1, 4);  // Index = 1
    write_le(buf, static_cast<size_t>(ps) + 260 + 132 + 4 + 12, 6, 4); // Type
    write_le(buf, static_cast<size_t>(ps) + 260 + 132 + 4 + 16, 1, 4); // DhcpEnabled = 1

    // IpAddressList at offset
    size_t ias_off = static_cast<size_t>(ps);
    ias_off += 260 + 132 + 4 + 8;  // after Name, Desc, AddrLen, Addr
    ias_off += 4 + 4 + static_cast<size_t>(ps); // Index, Type, CurrentIpAddress
    write_le(buf, ias_off, 0, ps);
    speakeasy::write_string(buf, ias_off + static_cast<size_t>(ps), "192.168.1.100", false);
    speakeasy::write_string(buf, ias_off + static_cast<size_t>(ps) + 16, "255.255.255.0", false);

    // GatewayList
    size_t gw_off = ias_off + ias_size;
    write_le(buf, gw_off, 0, ps);
    speakeasy::write_string(buf, gw_off + static_cast<size_t>(ps), "192.168.1.1", false);
    speakeasy::write_string(buf, gw_off + static_cast<size_t>(ps) + 16, "0.0.0.0", false);

    size_t dhcp_off = gw_off + ias_size;
    write_le(buf, dhcp_off, 0, ps);
    speakeasy::write_string(buf, dhcp_off + static_cast<size_t>(ps), "192.168.1.1", false);
    speakeasy::write_string(buf, dhcp_off + static_cast<size_t>(ps) + 16, "0.0.0.0", false);

    we(e)->mem_write(pAdapterInfo, buf);

    std::vector<uint8_t> sz(4, 0);
    write_le(sz, 0, static_cast<uint64_t>(struct_size), 4);
    we(e)->mem_write(pOutBufLen, sz);
    return IPH_OK;
}

// 
//  GetAdaptersAddresses
// 
uint64_t Iphlpapi::GetAdaptersAddresses(void* e, ArgList& a, void* ctx) {
    if (a.size() < 5) return IPH_INVALID_PARAM;
    uint64_t pAdapterAddresses = a[3];
    uint64_t pOutBufLen = a[4];
    if (!pOutBufLen) return IPH_INVALID_PARAM;

    int ps = ptr_sz(e);
    size_t struct_size = (ps == 8) ? 536 : 512;

    auto len_raw = we(e)->mem_read(pOutBufLen, 4);
    uint32_t out_buf_len = static_cast<uint32_t>(read_le(len_raw, 0, 4));

    if (!pAdapterAddresses || out_buf_len < struct_size) {
        std::vector<uint8_t> sz(4, 0);
        write_le(sz, 0, static_cast<uint64_t>(struct_size), 4);
        we(e)->mem_write(pOutBufLen, sz);
        return IPH_BUF_OVERFLOW;
    }

    std::vector<uint8_t> buf(struct_size, 0);
    write_le(buf, 0, static_cast<uint64_t>(struct_size), 4);
    write_le(buf, 4, 1, 4);  // IfIndex = 1
    we(e)->mem_write(pAdapterAddresses, buf);

    std::vector<uint8_t> sz(4, 0);
    write_le(sz, 0, static_cast<uint64_t>(struct_size), 4);
    we(e)->mem_write(pOutBufLen, sz);
    return IPH_OK;
}

// 
//  GetNetworkParams
// 
uint64_t Iphlpapi::GetNetworkParams(void* e, ArgList& a, void* ctx) {
    if (a.size() < 2) return IPH_INVALID_PARAM;
    uint64_t pFixedInfo = a[0];
    uint64_t pOutBufLen = a[1];
    if (!pOutBufLen) return IPH_INVALID_PARAM;

    size_t struct_size = 1024;
    auto len_raw = we(e)->mem_read(pOutBufLen, 4);
    uint32_t out_buf_len = static_cast<uint32_t>(read_le(len_raw, 0, 4));

    if (!pFixedInfo || out_buf_len < struct_size) {
        std::vector<uint8_t> sz(4, 0);
        write_le(sz, 0, static_cast<uint64_t>(struct_size), 4);
        we(e)->mem_write(pOutBufLen, sz);
        return IPH_BUF_OVERFLOW;
    }

    std::vector<uint8_t> buf(struct_size, 0);
    speakeasy::write_string(buf, 0, "DESKTOP-EMULATED", false);
    speakeasy::write_string(buf, 132, "workgroup.local", false);
    we(e)->mem_write(pFixedInfo, buf);

    std::vector<uint8_t> sz(4, 0);
    write_le(sz, 0, static_cast<uint64_t>(struct_size), 4);
    we(e)->mem_write(pOutBufLen, sz);
    return IPH_OK;
}

// 
//  GetIfEntry
// 
uint64_t Iphlpapi::GetIfEntry(void* e, ArgList& a, void* ctx) {
    if (a.size() < 1) return IPH_INVALID_PARAM;
    uint64_t pIfRow = a[0];
    if (!pIfRow) return IPH_INVALID_PARAM;

    std::vector<uint8_t> buf(600, 0);
    write_le(buf, 512, 1, 4);
    write_le(buf, 516, MIB_IF_ETHERNET, 4);
    write_le(buf, 520, 1500, 4);
    write_le(buf, 524, 100000000, 4);
    write_le(buf, 528, 6, 4);
    auto mac = default_mac();
    for (size_t i = 0; i < mac.size(); i++) write_le(buf, 532 + i, mac[i], 1);
    write_le(buf, 540, 1, 4);
    write_le(buf, 544, 1, 4);
    we(e)->mem_write(pIfRow, buf);
    return IPH_OK;
}

// 
//  GetIfTable
// 
uint64_t Iphlpapi::GetIfTable(void* e, ArgList& a, void* ctx) {
    if (a.size() < 3) return IPH_INVALID_PARAM;
    uint64_t pIfTable = a[0];
    uint64_t pOutBufLen = a[1];
    if (!pOutBufLen) return IPH_INVALID_PARAM;

    size_t ifrow_size = 600;
    size_t struct_size = 4 + ifrow_size;

    auto len_raw = we(e)->mem_read(pOutBufLen, 4);
    uint32_t out_buf_len = static_cast<uint32_t>(read_le(len_raw, 0, 4));

    if (!pIfTable || out_buf_len < struct_size) {
        std::vector<uint8_t> sz(4, 0);
        write_le(sz, 0, static_cast<uint64_t>(struct_size), 4);
        we(e)->mem_write(pOutBufLen, sz);
        return IPH_BUF_OVERFLOW;
    }

    std::vector<uint8_t> buf(struct_size, 0);
    write_le(buf, 0, 1, 4);
    write_le(buf, 4 + 512, 1, 4);
    write_le(buf, 4 + 516, MIB_IF_ETHERNET, 4);
    write_le(buf, 4 + 520, 1500, 4);
    write_le(buf, 4 + 524, 100000000, 4);
    write_le(buf, 4 + 528, 6, 4);
    auto mac = default_mac();
    for (size_t i = 0; i < mac.size(); i++) write_le(buf, 4 + 532 + i, mac[i], 1);
    we(e)->mem_write(pIfTable, buf);

    std::vector<uint8_t> sz(4, 0);
    write_le(sz, 0, static_cast<uint64_t>(struct_size), 4);
    we(e)->mem_write(pOutBufLen, sz);
    return IPH_OK;
}

// 
//  GetExtendedTcpTable / GetExtendedUdpTable
// 
static uint64_t get_extended_table_impl(void* e, const ArgList& a) {
    if (a.size() < 6) return IPH_INVALID_PARAM;
    uint64_t pTcpTable = a[0];
    uint64_t pOutBufLen = a[1];
    if (!pOutBufLen) return IPH_INVALID_PARAM;

    size_t struct_size = 4;
    auto len_raw = we(e)->mem_read(pOutBufLen, 4);
    uint32_t out_buf_len = static_cast<uint32_t>(read_le(len_raw, 0, 4));

    if (!pTcpTable || out_buf_len < struct_size) {
        std::vector<uint8_t> sz(4, 0);
        write_le(sz, 0, static_cast<uint64_t>(struct_size), 4);
        we(e)->mem_write(pOutBufLen, sz);
        return IPH_BUF_OVERFLOW;
    }

    std::vector<uint8_t> buf(4, 0);
    write_le(buf, 0, 0, 4);
    we(e)->mem_write(pTcpTable, buf);

    std::vector<uint8_t> sz(4, 0);
    write_le(sz, 0, static_cast<uint64_t>(struct_size), 4);
    we(e)->mem_write(pOutBufLen, sz);
    return IPH_OK;
}

uint64_t Iphlpapi::GetExtendedTcpTable(void* e, ArgList& a, void* ctx) {
    return get_extended_table_impl(e, a);
}
uint64_t Iphlpapi::GetExtendedUdpTable(void* e, ArgList& a, void* ctx) {
    return get_extended_table_impl(e, a);
}

// 
//  GetBestInterface
// 
uint64_t Iphlpapi::GetBestInterface(void* e, ArgList& a, void* ctx) {
    if (a.size() < 2) return IPH_INVALID_PARAM;
    uint64_t pBestIndex = a[1];
    if (pBestIndex) {
        std::vector<uint8_t> buf(4, 0);
        write_le(buf, 0, 1, 4);
        we(e)->mem_write(pBestIndex, buf);
    }
    return IPH_OK;
}

// 
//  GetBestRoute
// 
uint64_t Iphlpapi::GetBestRoute(void* e, ArgList& a, void* ctx) {
    if (a.size() < 3) return IPH_INVALID_PARAM;
    uint64_t pBestRoute = a[2];
    if (!pBestRoute) return IPH_INVALID_PARAM;

    std::vector<uint8_t> buf(64, 0);
    write_le(buf, 0, ip_to_int("0.0.0.0"), 4);
    write_le(buf, 4, mask_to_int("0.0.0.0"), 4);
    write_le(buf, 8, 1, 4);
    write_le(buf, 12, ip_to_int("192.168.1.1"), 4);
    write_le(buf, 16, 1, 4);
    write_le(buf, 20, 3, 4);
    write_le(buf, 24, 4, 4);
    write_le(buf, 28, 0, 4);
    write_le(buf, 32, 1, 4);
    we(e)->mem_write(pBestRoute, buf);
    return IPH_OK;
}

// 
//  GetRTTAndHopCount
// 
uint64_t Iphlpapi::GetRTTAndHopCount(void* e, ArgList& a, void* ctx) {
    if (a.size() < 4) return 0;
    uint64_t pHopCount = a[1];
    uint64_t pRTT = a[3];
    if (pHopCount) {
        std::vector<uint8_t> buf(4, 0);
        write_le(buf, 0, 5, 4);
        we(e)->mem_write(pHopCount, buf);
    }
    if (pRTT) {
        std::vector<uint8_t> buf(8, 0);
        write_le(buf, 0, 50, 8);
        we(e)->mem_write(pRTT, buf);
    }
    return 1;
}

// 
//  GetFriendlyIfIndex
// 
uint64_t Iphlpapi::GetFriendlyIfIndex(void* e, ArgList& a, void* ctx) {
    if (a.size() < 1) return 0;
    uint32_t ifIndex = static_cast<uint32_t>(a[0]);
    (void)e;
    return ifIndex;
}

// 
//  NotifyAddrChange / NotifyRouteChange
// 
uint64_t Iphlpapi::NotifyAddrChange(void* e, ArgList& a, void* ctx) {
    (void)e; (void)a;
    return IPH_NOT_SUPPORTED;
}
uint64_t Iphlpapi::NotifyRouteChange(void* e, ArgList& a, void* ctx) {
    (void)e; (void)a;
    return IPH_NOT_SUPPORTED;
}

// 
//  CancelIPChangeNotify
// 
uint64_t Iphlpapi::CancelIPChangeNotify(void* e, ArgList& a, void* ctx) {
    (void)e; (void)a;
    return IPH_OK;
}

// 
//  FlushIpNetTable / FlushIpPathTable
// 
uint64_t Iphlpapi::FlushIpNetTable(void* e, ArgList& a, void* ctx) {
    (void)e; (void)a; return IPH_OK;
}
uint64_t Iphlpapi::FlushIpPathTable(void* e, ArgList& a, void* ctx) {
    (void)e; (void)a; return IPH_OK;
}

// 
//  GetIpAddrTable
// 
uint64_t Iphlpapi::GetIpAddrTable(void* e, ArgList& a, void* ctx) {
    if (a.size() < 3) return IPH_INVALID_PARAM;
    uint64_t pIpAddrTable = a[0];
    uint64_t pOutBufLen = a[1];
    if (!pOutBufLen) return IPH_INVALID_PARAM;

    size_t row_size = 24;
    size_t struct_size = 4 + row_size;
    auto len_raw = we(e)->mem_read(pOutBufLen, 4);
    uint32_t out_buf_len = static_cast<uint32_t>(read_le(len_raw, 0, 4));

    if (!pIpAddrTable || out_buf_len < struct_size) {
        std::vector<uint8_t> sz(4, 0);
        write_le(sz, 0, static_cast<uint64_t>(struct_size), 4);
        we(e)->mem_write(pOutBufLen, sz);
        return IPH_BUF_OVERFLOW;
    }

    std::vector<uint8_t> buf(struct_size, 0);
    write_le(buf, 0, 1, 4);
    write_le(buf, 4, 1, 4);
    write_le(buf, 8, ip_to_int("192.168.1.100"), 4);
    write_le(buf, 12, mask_to_int("255.255.255.0"), 4);
    write_le(buf, 16, ip_to_int("192.168.1.255"), 4);
    write_le(buf, 20, 0, 4);
    write_le(buf, 24, 0, 4);
    write_le(buf, 28, 1, 2);
    we(e)->mem_write(pIpAddrTable, buf);

    std::vector<uint8_t> sz(4, 0);
    write_le(sz, 0, static_cast<uint64_t>(struct_size), 4);
    we(e)->mem_write(pOutBufLen, sz);
    return IPH_OK;
}

// 
//  GetIpForwardTable
// 
uint64_t Iphlpapi::GetIpForwardTable(void* e, ArgList& a, void* ctx) {
    if (a.size() < 3) return IPH_INVALID_PARAM;
    uint64_t pIpForwardTable = a[0];
    uint64_t pOutBufLen = a[1];
    if (!pOutBufLen) return IPH_INVALID_PARAM;

    size_t row_size = 36;
    size_t struct_size = 4 + row_size;
    auto len_raw = we(e)->mem_read(pOutBufLen, 4);
    uint32_t out_buf_len = static_cast<uint32_t>(read_le(len_raw, 0, 4));

    if (!pIpForwardTable || out_buf_len < struct_size) {
        std::vector<uint8_t> sz(4, 0);
        write_le(sz, 0, static_cast<uint64_t>(struct_size), 4);
        we(e)->mem_write(pOutBufLen, sz);
        return IPH_BUF_OVERFLOW;
    }

    std::vector<uint8_t> buf(struct_size, 0);
    write_le(buf, 0, 1, 4);
    write_le(buf, 4, ip_to_int("0.0.0.0"), 4);
    write_le(buf, 8, mask_to_int("0.0.0.0"), 4);
    write_le(buf, 12, 1, 4);
    write_le(buf, 16, ip_to_int("192.168.1.1"), 4);
    write_le(buf, 20, 1, 4);
    write_le(buf, 24, 3, 4);
    write_le(buf, 28, 4, 4);
    write_le(buf, 32, 0, 4);
    write_le(buf, 36, 1, 4);
    we(e)->mem_write(pIpForwardTable, buf);

    std::vector<uint8_t> sz(4, 0);
    write_le(sz, 0, static_cast<uint64_t>(struct_size), 4);
    we(e)->mem_write(pOutBufLen, sz);
    return IPH_OK;
}

// 
//  GetIpNetTable
// 
uint64_t Iphlpapi::GetIpNetTable(void* e, ArgList& a, void* ctx) {
    if (a.size() < 3) return IPH_INVALID_PARAM;
    uint64_t pIpNetTable = a[0];
    uint64_t pOutBufLen = a[1];
    if (!pOutBufLen) return IPH_INVALID_PARAM;

    size_t row_size = 24;
    size_t struct_size = 4 + row_size;
    auto len_raw = we(e)->mem_read(pOutBufLen, 4);
    uint32_t out_buf_len = static_cast<uint32_t>(read_le(len_raw, 0, 4));

    if (!pIpNetTable || out_buf_len < struct_size) {
        std::vector<uint8_t> sz(4, 0);
        write_le(sz, 0, static_cast<uint64_t>(struct_size), 4);
        we(e)->mem_write(pOutBufLen, sz);
        return IPH_BUF_OVERFLOW;
    }

    std::vector<uint8_t> buf(struct_size, 0);
    write_le(buf, 0, 1, 4);
    write_le(buf, 4, 1, 4);
    write_le(buf, 8, 6, 4);
    auto mac = default_mac();
    for (size_t i = 0; i < mac.size(); i++) write_le(buf, 12 + i, mac[i], 1);
    write_le(buf, 20, ip_to_int("192.168.1.1"), 4);
    write_le(buf, 24, 3, 4);
    we(e)->mem_write(pIpNetTable, buf);

    std::vector<uint8_t> sz(4, 0);
    write_le(sz, 0, static_cast<uint64_t>(struct_size), 4);
    we(e)->mem_write(pOutBufLen, sz);
    return IPH_OK;
}

// 
//  GetIpStatistics / GetIpStatisticsEx
// 
uint64_t Iphlpapi::GetIpStatistics(void* e, ArgList& a, void* ctx) {
    if (a.size() < 1) return IPH_INVALID_PARAM;
    uint64_t pStats = a[0];
    if (!pStats) return IPH_INVALID_PARAM;

    std::vector<uint8_t> buf(100, 0);
    write_le(buf, 0, 1, 4); write_le(buf, 4, 128, 4);
    for (int i = 8; i < 64; i += 4) write_le(buf, i, 0, 4);
    we(e)->mem_write(pStats, buf);
    return IPH_OK;
}
uint64_t Iphlpapi::GetIpStatisticsEx(void* e, ArgList& a, void* ctx) {
    return GetIpStatistics(e, a, ctx);
}

// 
//  GetTcpStatistics / GetTcpStatisticsEx
// 
uint64_t Iphlpapi::GetTcpStatistics(void* e, ArgList& a, void* ctx) {
    if (a.size() < 1) return IPH_INVALID_PARAM;
    uint64_t pStats = a[0];
    if (!pStats) return IPH_INVALID_PARAM;

    std::vector<uint8_t> buf(60, 0);
    write_le(buf, 0, 0, 4); write_le(buf, 4, 3000, 4); write_le(buf, 8, 30000, 4);
    for (int i = 12; i < 56; i += 4) write_le(buf, i, 0, 4);
    we(e)->mem_write(pStats, buf);
    return IPH_OK;
}
uint64_t Iphlpapi::GetTcpStatisticsEx(void* e, ArgList& a, void* ctx) {
    return GetTcpStatistics(e, a, ctx);
}

// 
//  GetUdpStatistics / GetUdpStatisticsEx
// 
uint64_t Iphlpapi::GetUdpStatistics(void* e, ArgList& a, void* ctx) {
    if (a.size() < 1) return IPH_INVALID_PARAM;
    uint64_t pStats = a[0];
    if (!pStats) return IPH_INVALID_PARAM;

    std::vector<uint8_t> buf(20, 0);
    write_le(buf, 0, 0, 4); write_le(buf, 4, 0, 4);
    write_le(buf, 8, 0, 4); write_le(buf, 12, 0, 4); write_le(buf, 16, 0, 4);
    we(e)->mem_write(pStats, buf);
    return IPH_OK;
}
uint64_t Iphlpapi::GetUdpStatisticsEx(void* e, ArgList& a, void* ctx) {
    return GetUdpStatistics(e, a, ctx);
}

// 
//  SetIpStatistics / SetIpTTL
// 
uint64_t Iphlpapi::SetIpStatistics(void* e, ArgList& a, void* ctx) {
    (void)e; (void)a; return IPH_OK;
}
uint64_t Iphlpapi::SetIpTTL(void* e, ArgList& a, void* ctx) {
    (void)e; (void)a; return IPH_OK;
}

// 
//  AllocateAndGet*TableFromStack
// 
static uint64_t alloc_and_get_table_impl(void* e, const ArgList& a, size_t row_size, int ps) {
    if (a.size() < 4) return IPH_INVALID_PARAM;
    uint64_t ppTable = a[0];
    uint64_t pTableSize = a[2];
    if (!ppTable) return IPH_INVALID_PARAM;

    size_t struct_size = 4 + row_size;
    uint64_t table_addr = we(e)->mem_map(struct_size, 0, PERM_MEM_READ | PERM_MEM_WRITE, "api.iphlpapi.table");

    std::vector<uint8_t> buf(struct_size, 0);
    write_le(buf, 0, 1, 4);
    write_le(buf, 4, 1, 4);
    we(e)->mem_write(table_addr, buf);

    std::vector<uint8_t> ptr_buf(ps, 0);
    write_le(ptr_buf, 0, table_addr, ps);
    we(e)->mem_write(ppTable, ptr_buf);

    if (pTableSize) {
        std::vector<uint8_t> sz(4, 0);
        write_le(sz, 0, static_cast<uint64_t>(struct_size), 4);
        we(e)->mem_write(pTableSize, sz);
    }
    return IPH_OK;
}

uint64_t Iphlpapi::AllocateAndGetIpAddrTableFromStack(void* e, ArgList& a, void* ctx) {
    return alloc_and_get_table_impl(e, a, 24, ptr_sz(e));
}
uint64_t Iphlpapi::AllocateAndGetIpNetTableFromStack(void* e, ArgList& a, void* ctx) {
    return alloc_and_get_table_impl(e, a, 24, ptr_sz(e));
}
uint64_t Iphlpapi::AllocateAndGetTcpTableFromStack(void* e, ArgList& a, void* ctx) {
    return alloc_and_get_table_impl(e, a, 24, ptr_sz(e));
}
uint64_t Iphlpapi::AllocateAndGetUdpTableFromStack(void* e, ArgList& a, void* ctx) {
    return alloc_and_get_table_impl(e, a, 20, ptr_sz(e));
}

// 
//  GetInterfaceInfo
// 
uint64_t Iphlpapi::GetInterfaceInfo(void* e, ArgList& a, void* ctx) {
    if (a.size() < 2) return IPH_INVALID_PARAM;
    uint64_t pIfTable = a[0];
    uint64_t pOutBufLen = a[1];
    if (!pOutBufLen) return IPH_INVALID_PARAM;

    size_t struct_size = 4 + 4 + 256 * 2;
    auto len_raw = we(e)->mem_read(pOutBufLen, 4);
    uint32_t out_buf_len = static_cast<uint32_t>(read_le(len_raw, 0, 4));

    if (!pIfTable || out_buf_len < struct_size) {
        std::vector<uint8_t> sz(4, 0);
        write_le(sz, 0, static_cast<uint64_t>(struct_size), 4);
        we(e)->mem_write(pOutBufLen, sz);
        return IPH_BUF_OVERFLOW;
    }

    std::vector<uint8_t> buf(struct_size, 0);
    write_le(buf, 0, 1, 4);
    write_le(buf, 4, 1, 4);
    std::wstring name = L"{DEFAULT-ADAPTER}";
    for (size_t i = 0; i < name.size() && i < 256; i++) {
        write_le(buf, 8 + i * 2, static_cast<uint16_t>(name[i]), 2);
    }
    we(e)->mem_write(pIfTable, buf);

    std::vector<uint8_t> sz(4, 0);
    write_le(sz, 0, static_cast<uint64_t>(struct_size), 4);
    we(e)->mem_write(pOutBufLen, sz);
    return IPH_OK;
}

// 
//  GetNumberOfInterfaces
// 
uint64_t Iphlpapi::GetNumberOfInterfaces(void* e, ArgList& a, void* ctx) {
    if (a.size() < 1) return IPH_INVALID_PARAM;
    uint64_t pCount = a[0];
    if (pCount) {
        std::vector<uint8_t> buf(4, 0);
        write_le(buf, 0, 1, 4);
        we(e)->mem_write(pCount, buf);
    }
    return IPH_OK;
}

// 
//  DhcpRequestParams
// 
uint64_t Iphlpapi::DhcpRequestParams(void* e, ArgList& a, void* ctx) {
    (void)e; (void)a; return IPH_OK;
}

// 
//  EnableRouter / UnenableRouter
// 
uint64_t Iphlpapi::EnableRouter(void* e, ArgList& a, void* ctx) {
    if (a.size() < 3) return IPH_INVALID_PARAM;
    uint64_t pHandle = a[0];
    if (pHandle) {
        std::vector<uint8_t> buf(4, 0);
        write_le(buf, 0, 1, 4);
        we(e)->mem_write(pHandle, buf);
    }
    return IPH_OK;
}
uint64_t Iphlpapi::UnenableRouter(void* e, ArgList& a, void* ctx) {
    (void)e; (void)a; return IPH_OK;
}

// 
//  IpReleaseAddress / IpRenewAddress
// 
uint64_t Iphlpapi::IpReleaseAddress(void* e, ArgList& a, void* ctx) {
    (void)e; (void)a; return IPH_OK;
}
uint64_t Iphlpapi::IpRenewAddress(void* e, ArgList& a, void* ctx) {
    (void)e; (void)a; return IPH_OK;
}

// 
//  SendARP
// 
uint64_t Iphlpapi::SendARP(void* e, ArgList& a, void* ctx) {
    if (a.size() < 4) return IPH_INVALID_PARAM;
    uint64_t pMacAddr = a[2];
    uint64_t phyAddrLen = a[3];

    if (pMacAddr && phyAddrLen) {
        auto mac = default_mac();
        auto len_buf = we(e)->mem_read(phyAddrLen, 4);
        uint32_t buf_len = static_cast<uint32_t>(read_le(len_buf, 0, 4));
        size_t copy_len = (mac.size() < buf_len) ? mac.size() : buf_len;
        std::vector<uint8_t> mac_out(copy_len);
        for (size_t i = 0; i < copy_len; i++) mac_out[i] = mac[i];
        we(e)->mem_write(pMacAddr, mac_out);

        std::vector<uint8_t> sz(4, 0);
        write_le(sz, 0, static_cast<uint64_t>(mac.size()), 4);
        we(e)->mem_write(phyAddrLen, sz);
    }
    return IPH_OK;
}

// 
//  Ping / PingEx / CancelIPInfoChange / SetAdapterIpAddress
// 
uint64_t Iphlpapi::Ping(void* e, ArgList& a, void* ctx) {
    (void)e; (void)a; return IPH_OK;
}
uint64_t Iphlpapi::PingEx(void* e, ArgList& a, void* ctx) {
    (void)e; (void)a; return IPH_OK;
}
uint64_t Iphlpapi::CancelIPInfoChange(void* e, ArgList& a, void* ctx) {
    (void)e; (void)a; return IPH_OK;
}
uint64_t Iphlpapi::SetAdapterIpAddress(void* e, ArgList& a, void* ctx) {
    (void)e; (void)a; return IPH_OK;
}

// 
//  AddIPAddress / DeleteIPAddress
// 
uint64_t Iphlpapi::AddIPAddress(void* e, ArgList& a, void* ctx) {
    if (a.size() < 5) return IPH_INVALID_PARAM;
    uint64_t pNTEContext = a[3];
    uint64_t pNTEInstance = a[4];
    if (pNTEContext) {
        std::vector<uint8_t> buf(4, 0);
        write_le(buf, 0, 1, 4);
        we(e)->mem_write(pNTEContext, buf);
    }
    if (pNTEInstance) {
        std::vector<uint8_t> buf(4, 0);
        write_le(buf, 0, 1, 4);
        we(e)->mem_write(pNTEInstance, buf);
    }
    return IPH_OK;
}
uint64_t Iphlpapi::DeleteIPAddress(void* e, ArgList& a, void* ctx) {
    (void)e; (void)a; return IPH_OK;
}

//  Constructor 
Iphlpapi::Iphlpapi(void* emu) : ApiHandler(emu) {
    INIT_API_TABLE(Iphlpapi)
    REG(Iphlpapi, GetAdaptersInfo, 2)
    REG(Iphlpapi, GetAdaptersAddresses, 5)
    REG(Iphlpapi, GetIfEntry, 2)
    REG(Iphlpapi, GetIfTable, 3)
    REG(Iphlpapi, GetExtendedTcpTable, 6)
    REG(Iphlpapi, GetExtendedUdpTable, 6)
    REG(Iphlpapi, GetNetworkParams, 2)
    REG(Iphlpapi, GetBestInterface, 2)
    REG(Iphlpapi, GetBestRoute, 3)
    REG(Iphlpapi, GetRTTAndHopCount, 4)
    REG(Iphlpapi, GetFriendlyIfIndex, 1)
    REG(Iphlpapi, NotifyAddrChange, 2)
    REG(Iphlpapi, NotifyRouteChange, 2)
    REG(Iphlpapi, CancelIPChangeNotify, 1)
    REG(Iphlpapi, FlushIpNetTable, 2)
    REG(Iphlpapi, FlushIpPathTable, 1)
    REG(Iphlpapi, GetIpAddrTable, 3)
    REG(Iphlpapi, GetIpForwardTable, 3)
    REG(Iphlpapi, GetIpNetTable, 3)
    REG(Iphlpapi, GetIpStatistics, 1)
    REG(Iphlpapi, GetIpStatisticsEx, 2)
    REG(Iphlpapi, GetTcpStatistics, 1)
    REG(Iphlpapi, GetTcpStatisticsEx, 2)
    REG(Iphlpapi, GetUdpStatistics, 1)
    REG(Iphlpapi, GetUdpStatisticsEx, 2)
    REG(Iphlpapi, SetIpStatistics, 1)
    REG(Iphlpapi, SetIpTTL, 1)
    REG(Iphlpapi, AllocateAndGetIpAddrTableFromStack, 4)
    REG(Iphlpapi, AllocateAndGetIpNetTableFromStack, 4)
    REG(Iphlpapi, AllocateAndGetTcpTableFromStack, 4)
    REG(Iphlpapi, AllocateAndGetUdpTableFromStack, 4)
    REG(Iphlpapi, GetInterfaceInfo, 2)
    REG(Iphlpapi, GetNumberOfInterfaces, 1)
    REG(Iphlpapi, DhcpRequestParams, 7)
    REG(Iphlpapi, EnableRouter, 3)
    REG(Iphlpapi, UnenableRouter, 2)
    REG(Iphlpapi, IpReleaseAddress, 2)
    REG(Iphlpapi, IpRenewAddress, 2)
    REG(Iphlpapi, SendARP, 4)
    REG(Iphlpapi, Ping, 6)
    REG(Iphlpapi, PingEx, 7)
    REG(Iphlpapi, CancelIPInfoChange, 1)
    REG(Iphlpapi, SetAdapterIpAddress, 3)
    REG(Iphlpapi, AddIPAddress, 5)
    REG(Iphlpapi, DeleteIPAddress, 2)
    END_API_TABLE
}

}} // namespaces
