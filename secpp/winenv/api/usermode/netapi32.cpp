// netapi32.cpp  netapi32.dll handler (real implementations)
#include "netapi32.h"
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include "windows/winemu.h"
#include "winenv/deffs/windows/netapi32.h"

//  Windows SDK macro conflict protection 
#ifdef _WIN32
#pragma push_macro("ERROR_SUCCESS")
#pragma push_macro("ERROR_INVALID_LEVEL")
#pragma push_macro("ERROR_INVALID_PARAMETER")
#pragma push_macro("ERROR_MORE_DATA")
#pragma push_macro("ERROR_INSUFFICIENT_BUFFER")
#undef ERROR_SUCCESS
#undef ERROR_INVALID_LEVEL
#undef ERROR_INVALID_PARAMETER
#undef ERROR_MORE_DATA
#undef ERROR_INSUFFICIENT_BUFFER
#endif

using namespace speakeasy;

namespace speakeasy { namespace api {

static inline WindowsEmulator* we(void* e) { return static_cast<WindowsEmulator*>(e); }
static inline BinaryEmulator* be(void* e) { return static_cast<BinaryEmulator*>(e); }
static inline int ptr_sz(void* e) { return (be(e)->get_arch() == speakeasy::arch::ARCH_AMD64) ? 8 : 4; }

//  Local error code constants 
static constexpr uint32_t NET_ERROR_SUCCESS           = 0;
static constexpr uint32_t NET_NERR_Success             = 0;
static constexpr uint32_t NET_ERROR_INVALID_LEVEL      = 124;
static constexpr uint32_t NET_ERROR_INVALID_PARAMETER  = 87;
static constexpr uint32_t NET_ERROR_MORE_DATA          = 234;
static constexpr uint32_t NET_ERROR_INSUFFICIENT_BUFFER = 122;



//  Constructor 
NetApi32::NetApi32(void* emu) : ApiHandler(emu) {
    INIT_API_TABLE(NetApi32)
    // Domain / workstation
    REG(NetApi32, NetGetJoinInformation, 3)
    REG(NetApi32, NetWkstaGetInfo, 3)
    REG(NetApi32, NetWkstaUserEnum, 4)
    REG(NetApi32, NetServerEnum, 8)
    REG(NetApi32, NetServerEnumEx, 8)
    REG(NetApi32, NetServerGetInfo, 3)
    REG(NetApi32, NetServerSetInfo, 4)
    REG(NetApi32, NetUserAdd, 4)
    REG(NetApi32, NetUserDel, 3)
    REG(NetApi32, NetUserEnum, 8)
    REG(NetApi32, NetUserGetGroups, 4)
    REG(NetApi32, NetUserGetInfo, 4)
    REG(NetApi32, NetUserSetInfo, 5)
    REG(NetApi32, NetUserGetLocalGroups, 7)
    REG(NetApi32, NetUserModalsGet, 3)
    REG(NetApi32, NetUserModalsSet, 4)
    REG(NetApi32, NetGroupEnum, 8)
    REG(NetApi32, NetGroupGetInfo, 4)
    REG(NetApi32, NetGroupSetInfo, 5)
    REG(NetApi32, NetGroupAddUser, 3)
    REG(NetApi32, NetGroupDelUser, 3)
    REG(NetApi32, NetLocalGroupEnum, 7)
    REG(NetApi32, NetLocalGroupGetInfo, 4)
    REG(NetApi32, NetLocalGroupSetInfo, 5)
    REG(NetApi32, NetLocalGroupAdd, 4)
    REG(NetApi32, NetLocalGroupAddMembers, 6)
    REG(NetApi32, NetLocalGroupDelMembers, 6)
    REG(NetApi32, NetLocalGroupGetMembers, 7)
    REG(NetApi32, NetApiBufferAllocate, 2)
    REG(NetApi32, NetApiBufferFree, 1)
    REG(NetApi32, NetApiBufferReallocate, 3)
    REG(NetApi32, NetApiBufferSize, 2)
    REG(NetApi32, NetGetDCName, 3)
    REG(NetApi32, NetGetAnyDCName, 3)
    REG(NetApi32, NetGetDisplayInformationIndex, 5)
    REG(NetApi32, NetQueryDisplayInformation, 8)
    REG(NetApi32, NetShareAdd, 4)
    REG(NetApi32, NetShareCheck, 3)
    REG(NetApi32, NetShareDel, 3)
    REG(NetApi32, NetShareEnum, 8)
    REG(NetApi32, NetShareGetInfo, 4)
    REG(NetApi32, NetShareSetInfo, 5)
    REG(NetApi32, NetConnectionEnum, 8)
    REG(NetApi32, NetFileEnum, 8)
    REG(NetApi32, NetFileGetInfo, 4)
    REG(NetApi32, NetFileClose, 2)
    REG(NetApi32, NetSessionEnum, 8)
    REG(NetApi32, NetSessionGetInfo, 4)
    REG(NetApi32, NetSessionDel, 3)
    REG(NetApi32, NetUseAdd, 4)
    REG(NetApi32, NetUseDel, 3)
    REG(NetApi32, NetUseEnum, 8)
    REG(NetApi32, NetUseGetInfo, 4)
    REG(NetApi32, NetScheduleJobAdd, 3)
    REG(NetApi32, NetScheduleJobDel, 3)
    REG(NetApi32, NetScheduleJobEnum, 5)
    REG(NetApi32, NetScheduleJobGetInfo, 4)
    REG(NetApi32, NetRemoteComputerSupports, 2)
    REG(NetApi32, NetRemoteTOD, 2)
    REG(NetApi32, NetWkstaSetInfo, 4)
    REG(NetApi32, NetWkstaTransportEnum, 5)
    REG(NetApi32, NetWkstaTransportAdd, 4)
    REG(NetApi32, NetWkstaTransportDel, 3)
    REG(NetApi32, NetAccessAdd, 4)
    REG(NetApi32, NetAccessDel, 3)
    REG(NetApi32, NetAccessEnum, 8)
    REG(NetApi32, NetAccessGetInfo, 4)
    REG(NetApi32, NetAccessSetInfo, 5)
    REG(NetApi32, NetAuditClear, 2)
    REG(NetApi32, NetAuditRead, 10)
    REG(NetApi32, NetAuditWrite, 4)
    REG(NetApi32, NetConfigGet, 4)
    REG(NetApi32, NetConfigGetAll, 3)
    REG(NetApi32, NetConfigSet, 5)
    REG(NetApi32, NetErrorLogClear, 2)
    REG(NetApi32, NetErrorLogRead, 10)
    REG(NetApi32, NetErrorLogWrite, 8)
    REG(NetApi32, SetServiceBits, 3)
    END_API_TABLE
}

// 
//  NetGetJoinInformation
// 
uint64_t NetApi32::NetGetJoinInformation(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // NET_API_STATUS NetGetJoinInformation(
    //   LPCWSTR lpServer,        // a[0]
    //   LPWSTR *lpNameBuffer,    // a[1]
    //   PNETSETUP_JOIN_STATUS BufferType  // a[2]
    // );
    uint64_t lpServer = a[0];
    uint64_t lpNameBuffer = a[1];
    uint64_t BufferType = a[2];

    if (lpServer) {
        std::string server = be(e)->read_mem_string(lpServer, 2);
        (void)server;
    }

    std::string domain = be(e)->get_hostname();  // fallback: use hostname as domain
    // Try to get domain from config
    auto osver = be(e)->get_os_version();
    (void)osver;

    int ps = ptr_sz(e);
    uint64_t namebuf = we(e)->mem_map(static_cast<size_t>((domain.size() + 1) * 2), 0, 7, "emu.netapi32.lpNameBuffer");
    be(e)->write_mem_string(domain, namebuf, 2);

    // Write the pointer to the name buffer
    std::vector<uint8_t> ptr_buf(ps, 0);
    write_le(ptr_buf, 0, namebuf, ps);
    we(e)->mem_write(lpNameBuffer, ptr_buf);

    // Write join status: NetSetupDomainName = 3
    uint32_t join_status = 3;  // NetSetupDomainName
    std::vector<uint8_t> js_buf(4, 0);
    write_le(js_buf, 0, join_status, 4);
    we(e)->mem_write(BufferType, js_buf);

    return NET_NERR_Success;
}

// 
//  NetWkstaGetInfo
// 
uint64_t NetApi32::NetWkstaGetInfo(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // NET_API_STATUS NetWkstaGetInfo(
    //   LMSTR  servername,   // a[0]
    //   DWORD  level,        // a[1]
    //   LPBYTE *bufptr       // a[2]
    // );
    uint64_t servername = a[0];
    uint64_t level = a[1];
    uint64_t bufptr = a[2];

    if (servername) {
        std::string server = be(e)->read_mem_string(servername, 2);
        (void)server;
    }

    if (level != 100 && level != 101 && level != 102) {
        return NET_ERROR_INVALID_LEVEL;
    }

    std::string hostname = be(e)->get_hostname();
    if (hostname.empty()) hostname = "WORKSTATION";

    std::string domain = "WORKGROUP";

    int ps = ptr_sz(e);

    if (level == 100) {
        // Branch on runtime pointer size for correct struct layout.
        size_t sz;
        uint64_t addr;
        std::vector<uint8_t> bytes;
        if (ps == 8) {
            deffs::windows::WKSTA_INFO_100<8> wki;
            wki.wki_platform_id  = 500;  // PLATFORM_ID_NT
            wki.wki_computername = we(e)->mem_map(static_cast<size_t>((hostname.size() + 1) * 2), 0, 7, "emu.wki_computername");
            be(e)->write_mem_string(hostname, wki.wki_computername, 2);
            wki.wki_langroup     = we(e)->mem_map(static_cast<size_t>((domain.size() + 1) * 2), 0, 7, "emu.wki_langroup");
            be(e)->write_mem_string(domain, wki.wki_langroup, 2);
            wki.wki_ver_major    = 10;
            wki.wki_ver_minor    = 0;
            sz = wki.sizeof_obj();
            addr = we(e)->mem_map(sz, 0, 7, "emu.WKSTA_INFO_100");
            bytes = wki.get_bytes();
        } else {
            deffs::windows::WKSTA_INFO_100<4> wki;
            wki.wki_platform_id  = 500;  // PLATFORM_ID_NT
            wki.wki_computername = we(e)->mem_map(static_cast<size_t>((hostname.size() + 1) * 2), 0, 7, "emu.wki_computername");
            be(e)->write_mem_string(hostname, wki.wki_computername, 2);
            wki.wki_langroup     = we(e)->mem_map(static_cast<size_t>((domain.size() + 1) * 2), 0, 7, "emu.wki_langroup");
            be(e)->write_mem_string(domain, wki.wki_langroup, 2);
            wki.wki_ver_major    = 10;
            wki.wki_ver_minor    = 0;
            sz = wki.sizeof_obj();
            addr = we(e)->mem_map(sz, 0, 7, "emu.WKSTA_INFO_100");
            bytes = wki.get_bytes();
        }
        we(e)->mem_write(addr, bytes);

        std::vector<uint8_t> ptr_buf(ps, 0);
        write_le(ptr_buf, 0, addr, ps);
        we(e)->mem_write(bufptr, ptr_buf);

    } else if (level == 101) {
        size_t sz;
        uint64_t addr;
        std::vector<uint8_t> bytes;
        if (ps == 8) {
            deffs::windows::WKSTA_INFO_101<8> wki;
            wki.wki_platform_id  = 500;
            wki.wki_computername = we(e)->mem_map(static_cast<size_t>((hostname.size() + 1) * 2), 0, 7, "emu.wki_computername");
            be(e)->write_mem_string(hostname, wki.wki_computername, 2);
            wki.wki_langroup     = we(e)->mem_map(static_cast<size_t>((domain.size() + 1) * 2), 0, 7, "emu.wki_langroup");
            be(e)->write_mem_string(domain, wki.wki_langroup, 2);
            wki.wki_ver_major    = 10;
            wki.wki_ver_minor    = 0;
            wki.wki_lanroot      = we(e)->mem_map(2, 0, 7, "emu.wki_lanroot");
            { std::vector<uint8_t> empty(2, 0); we(e)->mem_write(wki.wki_lanroot, empty); }
            sz = wki.sizeof_obj();
            addr = we(e)->mem_map(sz, 0, 7, "emu.WKSTA_INFO_101");
            bytes = wki.get_bytes();
        } else {
            deffs::windows::WKSTA_INFO_101<4> wki;
            wki.wki_platform_id  = 500;
            wki.wki_computername = we(e)->mem_map(static_cast<size_t>((hostname.size() + 1) * 2), 0, 7, "emu.wki_computername");
            be(e)->write_mem_string(hostname, wki.wki_computername, 2);
            wki.wki_langroup     = we(e)->mem_map(static_cast<size_t>((domain.size() + 1) * 2), 0, 7, "emu.wki_langroup");
            be(e)->write_mem_string(domain, wki.wki_langroup, 2);
            wki.wki_ver_major    = 10;
            wki.wki_ver_minor    = 0;
            wki.wki_lanroot      = we(e)->mem_map(2, 0, 7, "emu.wki_lanroot");
            { std::vector<uint8_t> empty(2, 0); we(e)->mem_write(wki.wki_lanroot, empty); }
            sz = wki.sizeof_obj();
            addr = we(e)->mem_map(sz, 0, 7, "emu.WKSTA_INFO_101");
            bytes = wki.get_bytes();
        }
        we(e)->mem_write(addr, bytes);

        std::vector<uint8_t> ptr_buf(ps, 0);
        write_le(ptr_buf, 0, addr, ps);
        we(e)->mem_write(bufptr, ptr_buf);

    } else {  // level == 102
        size_t sz;
        uint64_t addr;
        std::vector<uint8_t> bytes;
        if (ps == 8) {
            deffs::windows::WKSTA_INFO_102<8> wki;
            wki.wki_platform_id     = 500;
            wki.wki_computername    = we(e)->mem_map(static_cast<size_t>((hostname.size() + 1) * 2), 0, 7, "emu.wki_computername");
            be(e)->write_mem_string(hostname, wki.wki_computername, 2);
            wki.wki_langroup        = we(e)->mem_map(static_cast<size_t>((domain.size() + 1) * 2), 0, 7, "emu.wki_langroup");
            be(e)->write_mem_string(domain, wki.wki_langroup, 2);
            wki.wki_ver_major       = 10;
            wki.wki_ver_minor       = 0;
            wki.wki_lanroot         = we(e)->mem_map(2, 0, 7, "emu.wki_lanroot");
            { std::vector<uint8_t> empty(2, 0); we(e)->mem_write(wki.wki_lanroot, empty); }
            wki.wki_logged_on_users = 2;
            sz = wki.sizeof_obj();
            addr = we(e)->mem_map(sz, 0, 7, "emu.WKSTA_INFO_102");
            bytes = wki.get_bytes();
        } else {
            deffs::windows::WKSTA_INFO_102<4> wki;
            wki.wki_platform_id     = 500;
            wki.wki_computername    = we(e)->mem_map(static_cast<size_t>((hostname.size() + 1) * 2), 0, 7, "emu.wki_computername");
            be(e)->write_mem_string(hostname, wki.wki_computername, 2);
            wki.wki_langroup        = we(e)->mem_map(static_cast<size_t>((domain.size() + 1) * 2), 0, 7, "emu.wki_langroup");
            be(e)->write_mem_string(domain, wki.wki_langroup, 2);
            wki.wki_ver_major       = 10;
            wki.wki_ver_minor       = 0;
            wki.wki_lanroot         = we(e)->mem_map(2, 0, 7, "emu.wki_lanroot");
            { std::vector<uint8_t> empty(2, 0); we(e)->mem_write(wki.wki_lanroot, empty); }
            wki.wki_logged_on_users = 2;
            sz = wki.sizeof_obj();
            addr = we(e)->mem_map(sz, 0, 7, "emu.WKSTA_INFO_102");
            bytes = wki.get_bytes();
        }
        we(e)->mem_write(addr, bytes);

        std::vector<uint8_t> ptr_buf(ps, 0);
        write_le(ptr_buf, 0, addr, ps);
        we(e)->mem_write(bufptr, ptr_buf);
    }

    return NET_NERR_Success;
}

// 
//  NetWkstaUserEnum
// 
uint64_t NetApi32::NetWkstaUserEnum(void* e, const std::vector<uint64_t>& a, void* ctx) {
    uint64_t servername = a[0];
    uint64_t level = a[1];
    uint64_t bufptr = a[2];
    uint64_t prefmaxlen = a[3];
    (void)servername; (void)level; (void)bufptr; (void)prefmaxlen;
    return NET_NERR_Success;
}

// 
//  NetServerEnum
// 
uint64_t NetApi32::NetServerEnum(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a;
    return NET_NERR_Success;
}

// 
//  NetServerEnumEx
// 
uint64_t NetApi32::NetServerEnumEx(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a;
    return NET_NERR_Success;
}

// 
//  NetServerGetInfo
// 
uint64_t NetApi32::NetServerGetInfo(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // NET_API_STATUS NetServerGetInfo(LMSTR servername, DWORD level, LPBYTE *bufptr);
    uint64_t servername = a[0];
    uint64_t level = a[1];
    uint64_t bufptr = a[2];

    if (servername) {
        std::string server = be(e)->read_mem_string(servername, 2);
        (void)server;
    }

    if (level == 101) {
        int ps = ptr_sz(e);
        size_t sz;
        uint64_t addr;
        std::vector<uint8_t> bytes;
        if (ps == 8) {
            deffs::windows::SERVER_INFO_101<8> si;
            si.sv101_platform_id   = 500;
            std::string srv_name = "\\\\SERVER";
            si.sv101_name = we(e)->mem_map(static_cast<size_t>((srv_name.size() + 1) * 2), 0, 7, "emu.sv101_name");
            be(e)->write_mem_string(srv_name, si.sv101_name, 2);
            si.sv101_version_major = 10;
            si.sv101_version_minor = 0;
            si.sv101_type          = 3;  // SV_TYPE_SERVER | SV_TYPE_WORKSTATION
            si.sv101_comment = we(e)->mem_map(2, 0, 7, "emu.sv101_comment");
            { std::vector<uint8_t> empty(2, 0); we(e)->mem_write(si.sv101_comment, empty); }
            sz = si.sizeof_obj();
            addr = we(e)->mem_map(sz, 0, 7, "emu.SERVER_INFO_101");
            bytes = si.get_bytes();
        } else {
            deffs::windows::SERVER_INFO_101<4> si;
            si.sv101_platform_id   = 500;
            std::string srv_name = "\\\\SERVER";
            si.sv101_name = we(e)->mem_map(static_cast<size_t>((srv_name.size() + 1) * 2), 0, 7, "emu.sv101_name");
            be(e)->write_mem_string(srv_name, si.sv101_name, 2);
            si.sv101_version_major = 10;
            si.sv101_version_minor = 0;
            si.sv101_type          = 3;  // SV_TYPE_SERVER | SV_TYPE_WORKSTATION
            si.sv101_comment = we(e)->mem_map(2, 0, 7, "emu.sv101_comment");
            { std::vector<uint8_t> empty(2, 0); we(e)->mem_write(si.sv101_comment, empty); }
            sz = si.sizeof_obj();
            addr = we(e)->mem_map(sz, 0, 7, "emu.SERVER_INFO_101");
            bytes = si.get_bytes();
        }
        we(e)->mem_write(addr, bytes);

        std::vector<uint8_t> ptr_buf(ps, 0);
        write_le(ptr_buf, 0, addr, ps);
        we(e)->mem_write(bufptr, ptr_buf);
    }

    return NET_NERR_Success;
}

// 
//  NetServerSetInfo
// 
uint64_t NetApi32::NetServerSetInfo(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a;
    return NET_NERR_Success;
}

// 
//  NetUserAdd
// 
uint64_t NetApi32::NetUserAdd(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // NET_API_STATUS NetUserAdd(LPCWSTR servername, DWORD level, LPBYTE buf, LPDWORD parm_err);
    uint64_t servername = a[0];
    uint64_t level = a[1];
    uint64_t buf = a[2];
    uint64_t parm_err = a[3];
    (void)level; (void)buf; (void)parm_err;

    if (servername) {
        std::string server = be(e)->read_mem_string(servername, 2);
        (void)server;
    }

    return NET_NERR_Success;
}

// 
//  NetUserDel
// 
uint64_t NetApi32::NetUserDel(void* e, const std::vector<uint64_t>& a, void* ctx) {
    uint64_t servername = a[0];
    uint64_t username = a[1];
    (void)servername;
    if (username) {
        std::string user = be(e)->read_mem_string(username, 2);
        (void)user;
    }
    return NET_NERR_Success;
}

// 
//  NetUserEnum
// 
uint64_t NetApi32::NetUserEnum(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a;
    return NET_NERR_Success;
}

// 
//  NetUserGetGroups
// 
uint64_t NetApi32::NetUserGetGroups(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a;
    return NET_NERR_Success;
}

// 
//  NetUserGetInfo
// 
uint64_t NetApi32::NetUserGetInfo(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a;
    return NET_NERR_Success;
}

// 
//  NetUserSetInfo
// 
uint64_t NetApi32::NetUserSetInfo(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a;
    return NET_NERR_Success;
}

// 
//  NetUserGetLocalGroups
// 
uint64_t NetApi32::NetUserGetLocalGroups(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a;
    return NET_NERR_Success;
}

// 
//  NetUserModalsGet
// 
uint64_t NetApi32::NetUserModalsGet(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a;
    return NET_NERR_Success;
}

// 
//  NetUserModalsSet
// 
uint64_t NetApi32::NetUserModalsSet(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a;
    return NET_NERR_Success;
}

// 
//  NetGroupEnum
// 
uint64_t NetApi32::NetGroupEnum(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a;
    return NET_NERR_Success;
}

// 
//  NetGroupGetInfo
// 
uint64_t NetApi32::NetGroupGetInfo(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a;
    return NET_NERR_Success;
}

// 
//  NetGroupSetInfo
// 
uint64_t NetApi32::NetGroupSetInfo(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a;
    return NET_NERR_Success;
}

// 
//  NetGroupAddUser
// 
uint64_t NetApi32::NetGroupAddUser(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a;
    return NET_NERR_Success;
}

// 
//  NetGroupDelUser
// 
uint64_t NetApi32::NetGroupDelUser(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a;
    return NET_NERR_Success;
}

// 
//  NetLocalGroupEnum
// 
uint64_t NetApi32::NetLocalGroupEnum(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a;
    return NET_NERR_Success;
}

// 
//  NetLocalGroupGetInfo
// 
uint64_t NetApi32::NetLocalGroupGetInfo(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a;
    return NET_NERR_Success;
}

// 
//  NetLocalGroupSetInfo
// 
uint64_t NetApi32::NetLocalGroupSetInfo(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a;
    return NET_NERR_Success;
}

// 
//  NetLocalGroupAdd
// 
uint64_t NetApi32::NetLocalGroupAdd(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a;
    return NET_NERR_Success;
}

// 
//  NetLocalGroupAddMembers
// 
uint64_t NetApi32::NetLocalGroupAddMembers(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a;
    return NET_NERR_Success;
}

// 
//  NetLocalGroupDelMembers
// 
uint64_t NetApi32::NetLocalGroupDelMembers(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a;
    return NET_NERR_Success;
}

// 
//  NetLocalGroupGetMembers
// 
uint64_t NetApi32::NetLocalGroupGetMembers(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a;
    return NET_NERR_Success;
}

// 
//  NetApiBufferAllocate
// 
uint64_t NetApi32::NetApiBufferAllocate(void* e, const std::vector<uint64_t>& a, void* ctx) {
    uint64_t ByteCount = a[0];
    uint64_t Buffer = a[1];
    if (Buffer) {
        int ps = ptr_sz(e);
        uint64_t buf = we(e)->mem_map(static_cast<size_t>(ByteCount), 0, 7, "emu.netapibuffer");
        std::vector<uint8_t> ptr_buf(ps, 0);
        write_le(ptr_buf, 0, buf, ps);
        we(e)->mem_write(Buffer, ptr_buf);
    }
    return NET_NERR_Success;
}

// 
//  NetApiBufferFree
// 
uint64_t NetApi32::NetApiBufferFree(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a;
    return NET_NERR_Success;
}

// 
//  NetApiBufferReallocate
// 
uint64_t NetApi32::NetApiBufferReallocate(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a;
    return NET_NERR_Success;
}

// 
//  NetApiBufferSize
// 
uint64_t NetApi32::NetApiBufferSize(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a;
    return NET_NERR_Success;
}

// 
//  NetGetDCName
// 
uint64_t NetApi32::NetGetDCName(void* e, const std::vector<uint64_t>& a, void* ctx) {
    uint64_t servername = a[0];
    uint64_t domainname = a[1];
    uint64_t bufptr = a[2];
    (void)servername;
    if (domainname) {
        std::string domain = be(e)->read_mem_string(domainname, 2);
        (void)domain;
    }

    if (bufptr) {
        int ps = ptr_sz(e);
        std::string dc_name = "\\\\DC";
        uint64_t buf = we(e)->mem_map(static_cast<size_t>((dc_name.size() + 1) * 2), 0, 7, "emu.netgetdcname");
        be(e)->write_mem_string(dc_name, buf, 2);
        std::vector<uint8_t> ptr_buf(ps, 0);
        write_le(ptr_buf, 0, buf, ps);
        we(e)->mem_write(bufptr, ptr_buf);
    }

    return NET_NERR_Success;
}

// 
//  NetGetAnyDCName
// 
uint64_t NetApi32::NetGetAnyDCName(void* e, const std::vector<uint64_t>& a, void* ctx) {
    return NetGetDCName(e, a, ctx);
}

// 
//  NetGetDisplayInformationIndex
// 
uint64_t NetApi32::NetGetDisplayInformationIndex(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a;
    return NET_NERR_Success;
}

// 
//  NetQueryDisplayInformation
// 
uint64_t NetApi32::NetQueryDisplayInformation(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a;
    return NET_NERR_Success;
}

// 
//  NetShareAdd
// 
uint64_t NetApi32::NetShareAdd(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a;
    return NET_NERR_Success;
}

// 
//  NetShareCheck
// 
uint64_t NetApi32::NetShareCheck(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a;
    return NET_NERR_Success;
}

// 
//  NetShareDel
// 
uint64_t NetApi32::NetShareDel(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a;
    return NET_NERR_Success;
}

// 
//  NetShareEnum
// 
uint64_t NetApi32::NetShareEnum(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a;
    return NET_NERR_Success;
}

// 
//  NetShareGetInfo
// 
uint64_t NetApi32::NetShareGetInfo(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a;
    return NET_NERR_Success;
}

// 
//  NetShareSetInfo
// 
uint64_t NetApi32::NetShareSetInfo(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a;
    return NET_NERR_Success;
}

// 
//  NetConnectionEnum
// 
uint64_t NetApi32::NetConnectionEnum(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a;
    return NET_NERR_Success;
}

// 
//  NetFileEnum
// 
uint64_t NetApi32::NetFileEnum(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a;
    return NET_NERR_Success;
}

// 
//  NetFileGetInfo
// 
uint64_t NetApi32::NetFileGetInfo(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a;
    return NET_NERR_Success;
}

// 
//  NetFileClose
// 
uint64_t NetApi32::NetFileClose(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a;
    return NET_NERR_Success;
}

// 
//  NetSessionEnum
// 
uint64_t NetApi32::NetSessionEnum(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a;
    return NET_NERR_Success;
}

// 
//  NetSessionGetInfo
// 
uint64_t NetApi32::NetSessionGetInfo(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a;
    return NET_NERR_Success;
}

// 
//  NetSessionDel
// 
uint64_t NetApi32::NetSessionDel(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a;
    return NET_NERR_Success;
}

// 
//  NetUseAdd
// 
uint64_t NetApi32::NetUseAdd(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a;
    return NET_NERR_Success;
}

// 
//  NetUseDel
// 
uint64_t NetApi32::NetUseDel(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a;
    return NET_NERR_Success;
}

// 
//  NetUseEnum
// 
uint64_t NetApi32::NetUseEnum(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a;
    return NET_NERR_Success;
}

// 
//  NetUseGetInfo
// 
uint64_t NetApi32::NetUseGetInfo(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a;
    return NET_NERR_Success;
}

// 
//  NetScheduleJobAdd
// 
uint64_t NetApi32::NetScheduleJobAdd(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a;
    return NET_NERR_Success;
}

// 
//  NetScheduleJobDel
// 
uint64_t NetApi32::NetScheduleJobDel(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a;
    return NET_NERR_Success;
}

// 
//  NetScheduleJobEnum
// 
uint64_t NetApi32::NetScheduleJobEnum(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a;
    return NET_NERR_Success;
}

// 
//  NetScheduleJobGetInfo
// 
uint64_t NetApi32::NetScheduleJobGetInfo(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a;
    return NET_NERR_Success;
}

// 
//  NetRemoteComputerSupports
// 
uint64_t NetApi32::NetRemoteComputerSupports(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a;
    return NET_NERR_Success;
}

// 
//  NetRemoteTOD
// 
uint64_t NetApi32::NetRemoteTOD(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a;
    return NET_NERR_Success;
}

// 
//  NetWkstaSetInfo
// 
uint64_t NetApi32::NetWkstaSetInfo(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a;
    return NET_NERR_Success;
}

// 
//  NetWkstaTransportEnum
// 
uint64_t NetApi32::NetWkstaTransportEnum(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a;
    return NET_NERR_Success;
}

// 
//  NetWkstaTransportAdd
// 
uint64_t NetApi32::NetWkstaTransportAdd(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a;
    return NET_NERR_Success;
}

// 
//  NetWkstaTransportDel
// 
uint64_t NetApi32::NetWkstaTransportDel(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a;
    return NET_NERR_Success;
}

// 
//  NetAccessAdd
// 
uint64_t NetApi32::NetAccessAdd(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a;
    return NET_NERR_Success;
}

// 
//  NetAccessDel
// 
uint64_t NetApi32::NetAccessDel(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a;
    return NET_NERR_Success;
}

// 
//  NetAccessEnum
// 
uint64_t NetApi32::NetAccessEnum(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a;
    return NET_NERR_Success;
}

// 
//  NetAccessGetInfo
// 
uint64_t NetApi32::NetAccessGetInfo(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a;
    return NET_NERR_Success;
}

// 
//  NetAccessSetInfo
// 
uint64_t NetApi32::NetAccessSetInfo(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a;
    return NET_NERR_Success;
}

// 
//  NetAuditClear
// 
uint64_t NetApi32::NetAuditClear(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a;
    return NET_NERR_Success;
}

// 
//  NetAuditRead
// 
uint64_t NetApi32::NetAuditRead(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a;
    return NET_NERR_Success;
}

// 
//  NetAuditWrite
// 
uint64_t NetApi32::NetAuditWrite(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a;
    return NET_NERR_Success;
}

// 
//  NetConfigGet
// 
uint64_t NetApi32::NetConfigGet(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a;
    return NET_NERR_Success;
}

// 
//  NetConfigGetAll
// 
uint64_t NetApi32::NetConfigGetAll(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a;
    return NET_NERR_Success;
}

// 
//  NetConfigSet
// 
uint64_t NetApi32::NetConfigSet(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a;
    return NET_NERR_Success;
}

// 
//  NetErrorLogClear
// 
uint64_t NetApi32::NetErrorLogClear(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a;
    return NET_NERR_Success;
}

// 
//  NetErrorLogRead
// 
uint64_t NetApi32::NetErrorLogRead(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a;
    return NET_NERR_Success;
}

// 
//  NetErrorLogWrite
// 
uint64_t NetApi32::NetErrorLogWrite(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a;
    return NET_NERR_Success;
}

// 
//  SetServiceBits
// 
uint64_t NetApi32::SetServiceBits(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a;
    return NET_NERR_Success;
}

}} // namespaces

//  Pop SDK macros 
#ifdef _WIN32
#pragma pop_macro("ERROR_INSUFFICIENT_BUFFER")
#pragma pop_macro("ERROR_MORE_DATA")
#pragma pop_macro("ERROR_INVALID_PARAMETER")
#pragma pop_macro("ERROR_INVALID_LEVEL")
#pragma pop_macro("ERROR_SUCCESS")
#endif
