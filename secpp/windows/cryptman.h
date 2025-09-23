// cryptman.h
#ifndef CRYPTMAN_H
#define CRYPTMAN_H

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <cstdint>

// Represents a crypto key used by crypto functions
class CryptKey {
private:
    int blob_type;
    std::vector<uint8_t> blob;
    size_t blob_len;
    uint32_t import_key;
    std::vector<std::string> param_list;
    uint32_t flags;

public:
    // Constructor
    CryptKey(int blob_type, const std::vector<uint8_t>& blob, size_t blob_len, 
             uint32_t hnd_import_key, const std::vector<std::string>& param_list, uint32_t flags);
    
    // Getters
    int get_blob_type() const { return blob_type; }
    const std::vector<uint8_t>& get_blob() const { return blob; }
    size_t get_blob_len() const { return blob_len; }
    uint32_t get_import_key() const { return import_key; }
    const std::vector<std::string>& get_param_list() const { return param_list; }
    uint32_t get_flags() const { return flags; }
};

// Represents crypto context used by crypto functions
class CryptContext {
private:
    static uint32_t curr_handle;
    std::string container_name;
    std::string provider_name;
    int ptype;
    uint32_t flags;
    std::map<uint32_t, std::shared_ptr<CryptKey>> keys;

public:
    // Constructor
    CryptContext(const std::string& cname, const std::string& pname, int ptype, uint32_t flags);
    
    // Methods
    uint32_t get_handle();
    uint32_t import_key(int blob_type, const std::vector<uint8_t>& blob, size_t blob_len, 
                        uint32_t hnd_import_key, const std::vector<std::string>& param_list, 
                        uint32_t flags);
    std::shared_ptr<CryptKey> get_key(uint32_t hnd);
    void delete_key(uint32_t hnd);
    
    // Getters
    const std::string& get_container_name() const { return container_name; }
    const std::string& get_provider_name() const { return provider_name; }
    int get_ptype() const { return ptype; }
    uint32_t get_flags() const { return flags; }
};

// Manages the emulation of crypto functions
class CryptoManager {
private:
    std::map<uint32_t, std::shared_ptr<CryptContext>> ctx_handles;
    std::map<std::string, std::string> config;

public:
    // Constructor
    CryptoManager(const std::map<std::string, std::string>& config = {});
    
    // Methods
    uint32_t crypt_open(const std::string& cname = "", const std::string& pname = "", 
                        int ptype = 0, uint32_t flags = 0);
    void crypt_close(uint32_t hnd);
    std::shared_ptr<CryptContext> crypt_get(uint32_t hnd);
};

#endif // CRYPTMAN_H