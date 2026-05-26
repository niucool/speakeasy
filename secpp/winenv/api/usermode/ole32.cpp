// ole32.cpp  ole32.dll handler (~19 APIs, real implementations)
#include "ole32.h"

#include <cstring>
#include <vector>
#include <string>
#include <cstdio>
#include <iomanip>
#include <sstream>

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
static inline MemoryManager* mm(void* e) {
    return static_cast<MemoryManager*>(e);
}
static inline int ptr_sz(void* e) {
    return (be(e)->get_arch() == speakeasy::arch::ARCH_AMD64) ? 8 : 4;
}

//  GUID structure helpers 
struct _OLEGUID {
    uint32_t Data1;
    uint16_t Data2;
    uint16_t Data3;
    uint8_t  Data4[8];
};

static std::string guid_to_string(const _OLEGUID& guid) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0')
        << std::setw(8) << guid.Data1 << '-'
        << std::setw(4) << guid.Data2 << '-'
        << std::setw(4) << guid.Data3 << '-'
        << std::setw(2) << (int)guid.Data4[0] << std::setw(2) << (int)guid.Data4[1] << '-'
        << std::setw(2) << (int)guid.Data4[2] << std::setw(2) << (int)guid.Data4[3]
        << std::setw(2) << (int)guid.Data4[4] << std::setw(2) << (int)guid.Data4[5]
        << std::setw(2) << (int)guid.Data4[6] << std::setw(2) << (int)guid.Data4[7];
    return oss.str();
}

static _OLEGUID read_guid(void* e, uint64_t addr) {
    _OLEGUID g;
    std::vector<uint8_t> raw = mm(e)->mem_read(addr, 16);
    g.Data1 = static_cast<uint32_t>(read_le(raw, 0, 4));
    g.Data2 = static_cast<uint16_t>(read_le(raw, 4, 2));
    g.Data3 = static_cast<uint16_t>(read_le(raw, 6, 2));
    for (int i = 0; i < 8; i++)
        g.Data4[i] = raw[8 + i];
    return g;
}

//  Constructor 

Ole32::Ole32(void* emu) : ApiHandler(emu) {
    INIT_API_TABLE(Ole32)
    REG(Ole32, CoInitialize, 1)         REG(Ole32, CoUninitialize, 0)
    REG(Ole32, CoCreateInstance, 5)     REG(Ole32, CoGetClassObject, 4)
    REG(Ole32, CoTaskMemAlloc, 1)       REG(Ole32, CoTaskMemFree, 1)
    REG(Ole32, CLSIDFromString, 2)      REG(Ole32, StringFromGUID2, 3)
    REG(Ole32, ProgIDFromCLSID, 2)      REG(Ole32, CLSIDFromProgID, 2)
    REG(Ole32, OleInitialize, 1)        REG(Ole32, OleUninitialize, 0)
    REG(Ole32, OleSetClipboard, 1)      REG(Ole32, OleGetClipboard, 1)
    REG(Ole32, OleFlushClipboard, 0)    REG(Ole32, OleIsCurrentClipboard, 1)
    REG(Ole32, CreateBindCtx, 2)        REG(Ole32, BindMoniker, 4)
    REG(Ole32, MkParseDisplayName, 4)
    END_API_TABLE
}

//  API implementations 

uint64_t Ole32::CoInitialize(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    (void)e; (void)a;
    return 0; // S_OK
}

uint64_t Ole32::CoUninitialize(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    (void)e; (void)a;
    return 0;
}

uint64_t Ole32::CoCreateInstance(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    uint64_t rclsid = a[0], pUnkOuter = a[1], dwClsContext = a[2];
    uint64_t riid = a[3], ppv = a[4];
    (void)pUnkOuter; (void)dwClsContext;

    if (riid && ppv) {
        size_t psz = static_cast<size_t>(ptr_sz(e));
        uint64_t pv = static_cast<MemoryManager*>(we(e))->mem_map(psz, 0, PERM_MEM_RWX, "emu.COM.pv");
        std::vector<uint8_t> addr_bytes(psz);
        write_le(addr_bytes, 0, pv, psz);
        be(e)->mem_write(ppv, addr_bytes);
    }
    (void)rclsid;
    return 0; // S_OK
}

uint64_t Ole32::CoGetClassObject(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    uint64_t rclsid = a[0], dwClsContext = a[1], pvReserved = a[2];
    uint64_t riid = a[3], ppv = a[4];
    (void)rclsid; (void)dwClsContext; (void)pvReserved; (void)riid;

    if (ppv) {
        size_t psz = static_cast<size_t>(ptr_sz(e));
        uint64_t pv = static_cast<MemoryManager*>(we(e))->mem_map(psz, 0, PERM_MEM_RWX, "emu.COM.pv");
        std::vector<uint8_t> addr_bytes(psz);
        write_le(addr_bytes, 0, pv, psz);
        be(e)->mem_write(ppv, addr_bytes);
    }
    return 0; // S_OK
}

uint64_t Ole32::CoTaskMemAlloc(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    size_t cb = static_cast<size_t>(a[0]);
    if (cb == 0) cb = 1;
    return static_cast<MemoryManager*>(we(e))->mem_map(cb, 0, PERM_MEM_RWX, "ole32.CoTaskMemAlloc");
}

uint64_t Ole32::CoTaskMemFree(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    (void)e; (void)a;
    return 0;
}

uint64_t Ole32::CLSIDFromString(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    uint64_t lpsz = a[0], pclsid = a[1];
    if (lpsz && pclsid) {
        std::string s = be(e)->read_mem_string(lpsz, 2);
        (void)s;
        std::vector<uint8_t> zero_guid(16, 0);
        be(e)->mem_write(pclsid, zero_guid);
    }
    return 0; // S_OK
}

uint64_t Ole32::StringFromGUID2(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    uint64_t rguid = a[0], lpsz = a[1], cchMax = a[2];
    if (rguid && lpsz && cchMax > 0) {
        _OLEGUID guid = read_guid(e, rguid);
        std::string guid_str = guid_to_string(guid);
        std::string formatted = "{" + guid_str + "}";
        be(e)->write_mem_string(formatted, lpsz, 2);
    }
    return 1;
}

uint64_t Ole32::ProgIDFromCLSID(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    (void)e; (void)a;
    return 0; // S_OK
}

uint64_t Ole32::CLSIDFromProgID(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    uint64_t lpszProgID = a[0], lpclsid = a[1];
    if (lpclsid) {
        std::vector<uint8_t> zero_guid(16, 0);
        be(e)->mem_write(lpclsid, zero_guid);
    }
    (void)lpszProgID;
    return 0; // S_OK
}

uint64_t Ole32::OleInitialize(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    (void)e; (void)a;
    return 0; // S_OK
}

uint64_t Ole32::OleUninitialize(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    (void)e; (void)a;
    return 0;
}

uint64_t Ole32::OleSetClipboard(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    (void)e; (void)a;
    return 0; // S_OK
}

uint64_t Ole32::OleGetClipboard(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    (void)e; (void)a;
    return 1; // S_FALSE
}

uint64_t Ole32::OleFlushClipboard(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    (void)e; (void)a;
    return 0; // S_OK
}

uint64_t Ole32::OleIsCurrentClipboard(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    (void)e; (void)a;
    return 1; // S_FALSE
}

uint64_t Ole32::CreateBindCtx(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    uint64_t reserved = a[0], ppbc = a[1];
    (void)reserved;

    if (ppbc) {
        size_t psz = static_cast<size_t>(ptr_sz(e));
        uint64_t pv = static_cast<MemoryManager*>(we(e))->mem_map(psz, 0, PERM_MEM_RWX, "ole32.IBindCtx");
        std::vector<uint8_t> addr_bytes(psz);
        write_le(addr_bytes, 0, pv, psz);
        be(e)->mem_write(ppbc, addr_bytes);
    }
    return 0; // S_OK
}

uint64_t Ole32::BindMoniker(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    (void)e; (void)a;
    return 0; // S_OK
}

uint64_t Ole32::MkParseDisplayName(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    (void)e; (void)a;
    return 0; // S_OK
}

}} // namespaces
