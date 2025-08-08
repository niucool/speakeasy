// cryptman.cpp
#include "cryptman.h"

// Static member initialization
uint32_t CryptContext::curr_handle = 0x680;

// CryptKey implementation
CryptKey::CryptKey(int blob_type, const std::vector<uint8_t>& blob, size_t blob_len, 
                   uint32_t hnd_import_key, const std::vector<std::string>& param_list, 
                   uint32_t flags)
    : blob_type(blob_type), blob(blob), blob_len(blob_len), 
      import_key(hnd_import_key), param_list(param_list), flags(flags) {
    // Constructor
}

// CryptContext implementation
CryptContext::CryptContext(const std::string& cname, const std::string& pname, 
                           int ptype, uint32_t flags)
    : container_name(cname), provider_name(pname), ptype(ptype), flags(flags) {
    // Constructor
}

uint32_t CryptContext::get_handle() {
    uint32_t hkey = CryptContext::curr_handle;
    CryptContext::curr_handle += 4;
    return hkey;
}

uint32_t CryptContext::import_key(int blob_type, const std::vector<uint8_t>& blob, 
                                  size_t blob_len, uint32_t hnd_import_key, 
                                  const std::vector<std::string>& param_list, uint32_t flags) {
    std::shared_ptr<CryptKey> key = std::make_shared<CryptKey>(blob_type, blob, blob_len, 
                                                               hnd_import_key, param_list, flags);
    uint32_t hnd = get_handle();
    keys[hnd] = key;
    return hnd;
}

std::shared_ptr<CryptKey> CryptContext::get_key(uint32_t hnd) {
    auto it = keys.find(hnd);
    if (it != keys.end()) {
        return it->second;
    }
    return nullptr;
}

void CryptContext::delete_key(uint32_t hnd) {
    keys.erase(hnd);
}

// CryptoManager implementation
CryptoManager::CryptoManager(const std::map<std::string, std::string>& config) 
    : config(config) {
    // Constructor
    // super(CryptoManager, this).__init__() - Not needed in C++
}

uint32_t CryptoManager::crypt_open(const std::string& cname, const std::string& pname, 
                                   int ptype, uint32_t flags) {
    std::shared_ptr<CryptContext> ctx = std::make_shared<CryptContext>(cname, pname, ptype, flags);
    uint32_t hnd = ctx->get_handle();
    ctx_handles[hnd] = ctx;
    return hnd;
}

void CryptoManager::crypt_close(uint32_t hnd) {
    ctx_handles.erase(hnd);
}

std::shared_ptr<CryptContext> CryptoManager::crypt_get(uint32_t hnd) {
    auto it = ctx_handles.find(hnd);
    if (it != ctx_handles.end()) {
        return it->second;
    }
    return nullptr;
}