// regman.h
#ifndef REGMAN_H
#define REGMAN_H

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <cstdint>

// TODO: Need C++ equivalents for these Python imports
// #include "winenv/defs/registry/reg.h"
// #include "errors.h"

// Registry key constants
const uint32_t HKEY_CLASSES_ROOT = 0x80000000;
const uint32_t HKEY_CURRENT_USER = 0x80000001;
const uint32_t HKEY_LOCAL_MACHINE = 0x80000002;
const uint32_t HKEY_USERS = 0x80000003;

// Forward declarations
class RegValue;
class RegKey;
class RegistryEmuError;

// Represents a registry value
class RegValue {
private:
    std::string name;
    int val_type;
    std::string data;

public:
    // Constructor
    RegValue(const std::string& name, int val_type, const std::string& data);
    
    // Methods
    std::string normalize_value(int val_type, const std::string& data);
    std::string get_name();
    int get_type();
    std::string get_data();
};

// Represents a registry key
class RegKey {
private:
    static uint32_t curr_handle;
    std::string path;
    std::vector<std::shared_ptr<RegValue>> values;

public:
    // Constructor
    RegKey(const std::string& path);
    
    // Methods
    uint32_t get_handle();
    std::string get_path();
    std::shared_ptr<RegValue> create_value(const std::string& name, int val_type, const std::string& value);
    std::vector<std::shared_ptr<RegValue>> get_values();
    std::shared_ptr<RegValue> get_value(const std::string& val_name);
};

// Manages the emulation of the windows registry. This includes creating keys, subkeys and values
class RegistryManager {
private:
    std::map<uint32_t, std::shared_ptr<RegKey>> reg_handles;
    std::vector<std::shared_ptr<RegKey>> keys;
    std::map<std::string, std::string> config;
    std::vector<std::string> reg_tree;

public:
    // Constructor
    RegistryManager(const std::map<std::string, std::string>& config = {});
    
    // Methods
    std::string normalize_reg_path(const std::string& path);
    std::shared_ptr<RegKey> get_key_from_handle(uint32_t handle);
    std::shared_ptr<RegKey> get_key_from_path(const std::string& path);
    bool is_key_a_parent_key(const std::string& path);
    std::vector<std::string> get_subkeys(std::shared_ptr<RegKey> key);
    std::shared_ptr<RegKey> get_key_from_config(const std::string& path);
    std::shared_ptr<RegKey> create_key(const std::string& path);
    uint32_t open_key(const std::string& path, bool create = false);
};

#endif // REGMAN_H