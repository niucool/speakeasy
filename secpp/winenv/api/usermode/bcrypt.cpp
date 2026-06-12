// bcrypt.cpp  bcrypt.dll API handler (real implementations)
#include "bcrypt.h"
#include <cstring>
#include <cstdint>
#include <string>
#include <vector>
#include <map>
#include "windows/winemu.h"
#include "struct.h"

using namespace speakeasy;

namespace speakeasy { namespace api {


//  NTSTATUS constants (BC_ prefix to avoid Windows macro conflicts) 
static constexpr uint32_t BC_OK = 0x00000000;
static constexpr uint32_t BC_INVALID_HANDLE = 0xC0000008;

// Handle tracking
static uint64_t next_handle() {
    static uint64_t h = 0x1000;
    return ++h;
}

struct BcryptAlg {
    uint64_t hnd;
    std::string alg_id;
    std::string impl;
    uint32_t flags;
    std::map<uint64_t, std::string> keys;
};

static std::map<uint64_t, BcryptAlg>& algs() {
    static std::map<uint64_t, BcryptAlg> m;
    return m;
}

// 
//  BCryptOpenAlgorithmProvider
// 
uint64_t Bcrypt::BCryptOpenAlgorithmProvider(void* e, ArgList& a, void* ctx) {
    if (a.size() < 4) return BC_INVALID_HANDLE;
    uint64_t phAlgorithm = a[0];
    uint64_t pszAlgId = a[1];
    uint64_t pszImplementation = a[2];
    uint32_t flags = static_cast<uint32_t>(a[3]);

    std::string alg_id;
    if (pszAlgId) {
        alg_id = be(e)->read_mem_string(pszAlgId, 2);
    }

    std::string impl;
    if (pszImplementation) {
        impl = be(e)->read_mem_string(pszImplementation, 2);
    }

    uint64_t hnd = next_handle();
    BcryptAlg alg;
    alg.hnd = hnd;
    alg.alg_id = alg_id;
    alg.impl = impl;
    alg.flags = flags;
    algs()[hnd] = alg;

    if (phAlgorithm) {
        std::vector<uint8_t> buf(we(e)->get_ptr_size(), 0);
        write_le(buf, 0, hnd, we(e)->get_ptr_size());
        we(e)->mem_write(phAlgorithm, buf);
    }

    return BC_OK;
}

// 
//  BCryptImportKeyPair
// 
uint64_t Bcrypt::BCryptImportKeyPair(void* e, ArgList& a, void* ctx) {
    if (a.size() < 7) return BC_INVALID_HANDLE;
    uint64_t hAlgorithm = a[0];
    uint64_t hImportKey = a[1];
    uint64_t pszBlobType = a[2];
    uint64_t phKey = a[3];
    uint64_t pbInput = a[4];
    uint32_t cbInput = static_cast<uint32_t>(a[5]);
    uint32_t flags = static_cast<uint32_t>(a[6]);
    (void)hImportKey; (void)flags;

    auto it = algs().find(hAlgorithm);
    if (it == algs().end()) return BC_INVALID_HANDLE;

    std::string blob_type;
    if (pszBlobType) {
        blob_type = be(e)->read_mem_string(pszBlobType, 2);
    }

    // Read blob data (for logging)
    if (pbInput && cbInput > 0) {
        we(e)->mem_read(pbInput, cbInput);
    }

    uint64_t key_hnd = next_handle();
    it->second.keys[key_hnd] = blob_type;

    if (phKey) {
        std::vector<uint8_t> buf(we(e)->get_ptr_size(), 0);
        write_le(buf, 0, key_hnd, we(e)->get_ptr_size());
        we(e)->mem_write(phKey, buf);
    }

    return BC_OK;
}

// 
//  BCryptCloseAlgorithmProvider
// 
uint64_t Bcrypt::BCryptCloseAlgorithmProvider(void* e, ArgList& a, void* ctx) {
    if (a.size() < 1) return BC_INVALID_HANDLE;
    uint64_t hAlgorithm = a[0];
    (void)e;

    algs().erase(hAlgorithm);
    return BC_OK;
}

// 
//  BCryptGetProperty
// 
uint64_t Bcrypt::BCryptGetProperty(void* e, ArgList& a, void* ctx) {
    if (a.size() < 6) return BC_INVALID_HANDLE;
    uint64_t hObject = a[0];
    uint64_t pszProperty = a[1];
    uint64_t pbOutput = a[2];
    uint32_t cbOutput = static_cast<uint32_t>(a[3]);
    uint64_t pcbResult = a[4];
    uint32_t flags = static_cast<uint32_t>(a[5]);
    (void)hObject; (void)flags;

    std::string property;
    if (pszProperty) {
        property = be(e)->read_mem_string(pszProperty, 2);
    }

    uint32_t result_value = 0;
    size_t result_size = 4;

    // Compare using regular string literals (not wide)
    if (property == "KeyLength" || property == "BlockLength") {
        result_value = 32;
    } else if (property == "ObjectLength") {
        result_value = 256;
    }

    if (pbOutput && cbOutput >= 4) {
        std::vector<uint8_t> out(4, 0);
        write_le(out, 0, result_value, 4);
        we(e)->mem_write(pbOutput, out);
    }

    if (pcbResult) {
        std::vector<uint8_t> sz(4, 0);
        write_le(sz, 0, static_cast<uint64_t>(result_size), 4);
        we(e)->mem_write(pcbResult, sz);
    }

    return BC_OK;
}

// 
//  BCryptDestroyKey
// 
uint64_t Bcrypt::BCryptDestroyKey(void* e, ArgList& a, void* ctx) {
    if (a.size() < 1) return BC_INVALID_HANDLE;
    uint64_t hKey = a[0];
    (void)e;

    for (auto& [hnd, alg] : algs()) {
        (void)hnd;
        if (alg.keys.erase(hKey) > 0) {
            return BC_OK;
        }
    }
    return BC_INVALID_HANDLE;
}

//  Constructor 
Bcrypt::Bcrypt(void* emu) : ApiHandler(emu) {
    INIT_API_TABLE(Bcrypt)
    REG(Bcrypt, BCryptOpenAlgorithmProvider, 4)
    REG(Bcrypt, BCryptImportKeyPair, 7)
    REG(Bcrypt, BCryptCloseAlgorithmProvider, 2)
    REG(Bcrypt, BCryptGetProperty, 6)
    REG(Bcrypt, BCryptDestroyKey, 1)
    END_API_TABLE
}

}} // namespaces
