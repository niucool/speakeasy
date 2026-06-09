// ncrypt.cpp  ncrypt.dll handler (real implementations)
#include "ncrypt.h"
#include <cstring>
#include <cstdint>
#include <string>
#include <vector>
#include <map>
#include "windows/winemu.h"
#include "struct.h"

using namespace speakeasy;

namespace speakeasy { namespace api {

static inline WindowsEmulator* we(void* e) { return static_cast<WindowsEmulator*>(e); }
static inline BinaryEmulator* be(void* e) { return static_cast<BinaryEmulator*>(e); }

//  SECURITY_STATUS constants (NC_ prefix to avoid macro conflicts) 
static constexpr uint32_t NC_OK = 0x00000000;
static constexpr uint32_t NC_NTE_INVALID_HANDLE = 0x80090026;

// Handle tracking
static uint64_t next_handle() {
    static uint64_t h = 0x2000;
    return ++h;
}

struct NcryptProv {
    uint64_t hnd;
    std::string name;
    uint32_t flags;
    std::map<uint64_t, std::string> keys;
};

static std::map<uint64_t, NcryptProv>& providers() {
    static std::map<uint64_t, NcryptProv> m;
    return m;
}

// 
//  NCryptOpenStorageProvider
// 
uint64_t Ncrypt::NCryptOpenStorageProvider(void* e, std::vector<uint64_t>& a, void* ctx) {
    if (a.size() < 3) return NC_NTE_INVALID_HANDLE;
    uint64_t phProvider = a[0];
    uint64_t pszProviderName = a[1];
    uint32_t flags = static_cast<uint32_t>(a[2]);

    std::string prov_name;
    if (pszProviderName) {
        prov_name = be(e)->read_mem_string(pszProviderName, 2);
    }

    uint64_t hnd = next_handle();
    NcryptProv prov;
    prov.hnd = hnd;
    prov.name = prov_name;
    prov.flags = flags;
    providers()[hnd] = prov;

    if (phProvider) {
        std::vector<uint8_t> buf(we(e)->get_ptr_size(), 0);
        write_le(buf, 0, hnd, we(e)->get_ptr_size());
        we(e)->mem_write(phProvider, buf);
    }

    return NC_OK;
}

// 
//  NCryptImportKey
// 
uint64_t Ncrypt::NCryptImportKey(void* e, std::vector<uint64_t>& a, void* ctx) {
    if (a.size() < 8) return NC_NTE_INVALID_HANDLE;
    uint64_t hProvider = a[0];
    uint64_t hImportKey = a[1];
    uint64_t pszBlobType = a[2];
    uint64_t pParameterList = a[3];
    uint64_t phKey = a[4];
    uint64_t pbData = a[5];
    uint32_t cbData = static_cast<uint32_t>(a[6]);
    uint32_t flags = static_cast<uint32_t>(a[7]);
    (void)hImportKey; (void)pParameterList; (void)flags;

    auto it = providers().find(hProvider);
    if (it == providers().end()) return NC_NTE_INVALID_HANDLE;

    std::string blob_type;
    if (pszBlobType) {
        blob_type = be(e)->read_mem_string(pszBlobType, 2);
    }

    if (pbData && cbData > 0) {
        we(e)->mem_read(pbData, cbData);
    }

    uint64_t key_hnd = next_handle();
    it->second.keys[key_hnd] = blob_type;

    if (phKey) {
        std::vector<uint8_t> buf(we(e)->get_ptr_size(), 0);
        write_le(buf, 0, key_hnd, we(e)->get_ptr_size());
        we(e)->mem_write(phKey, buf);
    }

    return NC_OK;
}

// 
//  NCryptDeleteKey
// 
uint64_t Ncrypt::NCryptDeleteKey(void* e, std::vector<uint64_t>& a, void* ctx) {
    if (a.size() < 2) return NC_NTE_INVALID_HANDLE;
    uint64_t hKey = a[0];
    uint32_t flags = static_cast<uint32_t>(a[1]);
    (void)flags;
    (void)e;

    for (auto& [hnd, prov] : providers()) {
        (void)hnd;
        if (prov.keys.erase(hKey) > 0) {
            return NC_OK;
        }
    }
    return NC_NTE_INVALID_HANDLE;
}

// 
//  NCryptFreeObject
// 
uint64_t Ncrypt::NCryptFreeObject(void* e, std::vector<uint64_t>& a, void* ctx) {
    if (a.size() < 1) return NC_NTE_INVALID_HANDLE;
    uint64_t hObject = a[0];
    (void)e;

    // Try as provider handle
    auto it = providers().find(hObject);
    if (it != providers().end()) {
        providers().erase(it);
        return NC_OK;
    }

    // Try as key handle
    for (auto& [hnd, prov] : providers()) {
        (void)hnd;
        if (prov.keys.erase(hObject) > 0) {
            return NC_OK;
        }
    }

    return NC_NTE_INVALID_HANDLE;
}

//  Constructor 
Ncrypt::Ncrypt(void* emu) : ApiHandler(emu) {
    INIT_API_TABLE(Ncrypt)
    REG(Ncrypt, NCryptOpenStorageProvider, 3)
    REG(Ncrypt, NCryptImportKey, 8)
    REG(Ncrypt, NCryptDeleteKey, 2)
    REG(Ncrypt, NCryptFreeObject, 1)
    END_API_TABLE
}

}} // namespaces
