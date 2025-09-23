// regman.cpp
#include "regman.h"
#include <algorithm>
#include <cctype>
#include <stdexcept>

// Static member initialization
uint32_t RegKey::curr_handle = 0x180;

// RegValue implementation
RegValue::RegValue(const std::string& name, int val_type, const std::string& data)
    : name(name), val_type(val_type) {
    this->data = normalize_value(val_type, data);
}

std::string RegValue::normalize_value(int val_type, const std::string& data) {
    // Convert registry values to python types
    // TODO: Implementation depends on regdefs constants
    /*
    if val_type in (regdefs.REG_EXPAND_SZ, regdefs.REG_MULTI_SZ, regdefs.REG_SZ):
        if not isinstance(data, str):
            raise RegistryEmuError('Invalid registry value expected string')
        return data
    elif val_type in (regdefs.REG_DWORD, regdefs.REG_QWORD):
        if isinstance(data, str):
            return int(data, 0)
        elif isinstance(data, int):
            return data
    elif val_type == regdefs.REG_BINARY:
        // Binary data is expected to be base64'd
        return base64.b64encode(data.encode('utf-8'))
    else:
        return data
    */
    return data;
}

std::string RegValue::get_name() {
    return name;
}

int RegValue::get_type() {
    return val_type;
}

std::string RegValue::get_data() {
    return data;
}

// RegKey implementation
RegKey::RegKey(const std::string& path) : path(path) {
    // Constructor
}

uint32_t RegKey::get_handle() {
    uint32_t hkey = RegKey::curr_handle;
    RegKey::curr_handle += 4;
    return hkey;
}

std::string RegKey::get_path() {
    return path;
}

std::shared_ptr<RegValue> RegKey::create_value(const std::string& name, int val_type, const std::string& value) {
    std::shared_ptr<RegValue> val = std::make_shared<RegValue>(name, val_type, value);
    values.push_back(val);
    return val;
}

std::vector<std::shared_ptr<RegValue>> RegKey::get_values() {
    return values;
}

std::shared_ptr<RegValue> RegKey::get_value(const std::string& val_name) {
    std::string name = val_name;
    if (name.empty()) {
        name = "default";
    }
    
    for (auto& v : values) {
        std::string v_name = v->get_name();
        std::transform(name.begin(), name.end(), name.begin(), ::tolower);
        std::transform(v_name.begin(), v_name.end(), v_name.begin(), ::tolower);
        
        if (name == v_name) {
            return v;
        }
    }
    return nullptr;
}

// RegistryManager implementation
RegistryManager::RegistryManager(const std::map<std::string, std::string>& config) : config(config) {
    // Initialize default registry keys
    std::vector<uint32_t> hkeys = {HKEY_CLASSES_ROOT, HKEY_CURRENT_USER,
                                   HKEY_LOCAL_MACHINE, HKEY_USERS};
    
    // TODO: Implementation depends on regdefs.get_hkey_type
    /*
    for hk in (HKEY_CLASSES_ROOT, HKEY_CURRENT_USER,
               HKEY_LOCAL_MACHINE, HKEY_USERS):
        path = regdefs.get_hkey_type(hk)
        key = this.create_key(path)
        this.reg_handles.update({hk: key})
    */
}

std::string RegistryManager::normalize_reg_path(const std::string& path) {
    std::string new_path = path;
    if (!path.empty()) {
        std::vector<std::string> roots = {"\\registry\\machine\\", "hklm\\"};
        for (const std::string& r : roots) {
            if (path.length() >= r.length()) {
                std::string lower_path = path;
                std::transform(lower_path.begin(), lower_path.end(), lower_path.begin(), ::tolower);
                
                if (lower_path.substr(0, r.length()) == r) {
                    new_path = "HKEY_LOCAL_MACHINE\\" + path.substr(r.length());
                    return new_path;
                }
            }
        }
    }
    return new_path;
}

std::shared_ptr<RegKey> RegistryManager::get_key_from_handle(uint32_t handle) {
    auto it = reg_handles.find(handle);
    if (it != reg_handles.end()) {
        return it->second;
    }
    return nullptr;
}

std::shared_ptr<RegKey> RegistryManager::get_key_from_path(const std::string& path) {
    std::string normalized_path = normalize_reg_path(path);
    std::string lower_normalized_path = normalized_path;
    std::transform(lower_normalized_path.begin(), lower_normalized_path.end(), 
                   lower_normalized_path.begin(), ::tolower);
    
    for (auto& key : keys) {
        std::string key_path = key->get_path();
        std::transform(key_path.begin(), key_path.end(), key_path.begin(), ::tolower);
        
        // TODO: Implementation depends on fnmatch functionality
        // if fnmatch.fnmatch(key.get_path().lower(), path.lower()):
        if (key_path == lower_normalized_path) {
            return key;
        }
    }
    return nullptr;
}

bool RegistryManager::is_key_a_parent_key(const std::string& path) {
    std::string lower_path = path;
    std::transform(lower_path.begin(), lower_path.end(), lower_path.begin(), ::tolower);
    
    for (auto& key : keys) {
        std::string key_path = key->get_path();
        std::transform(key_path.begin(), key_path.end(), key_path.begin(), ::tolower);
        
        if (key_path.substr(0, lower_path.length()) == lower_path) {
            return true;
        }
    }
    return false;
}

std::vector<std::string> RegistryManager::get_subkeys(std::shared_ptr<RegKey> key) {
    // TODO: once we revamp the registry emulation,
    // make this better

    std::string parent_path = key->get_path();
    std::vector<std::string> subkeys;
    
    for (auto& k : keys) {
        std::string test_path = k->get_path();
        std::string lower_test_path = test_path;
        std::string lower_parent_path = parent_path;
        std::transform(lower_test_path.begin(), lower_test_path.end(), 
                       lower_test_path.begin(), ::tolower);
        std::transform(lower_parent_path.begin(), lower_parent_path.end(), 
                       lower_parent_path.begin(), ::tolower);
        
        if (lower_test_path.substr(0, lower_parent_path.length()) == lower_parent_path) {
            std::string sub = test_path.substr(parent_path.length());
            if (!sub.empty() && sub[0] == '\\') {
                sub = sub.substr(1);
            }

            size_t end_slash = sub.find('\\');
            if (end_slash != std::string::npos) {
                sub = sub.substr(0, end_slash);
            }

            if (!sub.empty()) {
                // Check if subkey already exists in subkeys
                bool exists = false;
                for (const std::string& existing_subkey : subkeys) {
                    if (existing_subkey == sub) {
                        exists = true;
                        break;
                    }
                }
                if (!exists) {
                    subkeys.push_back(sub);
                }
            }
        }
    }

    return subkeys;
}

std::shared_ptr<RegKey> RegistryManager::get_key_from_config(const std::string& path) {
    // TODO: Implementation depends on config structure
    /*
    // See if the emulator config file contains a handler for the requested registry path
    for key in this.config.get('keys', []):
        if key['path'].lower() == path.lower():
            new_key = RegKey(path)
            for value in key.get('values', []):
                val_type = value.get('type')
                vts = regdefs.get_flag_value(val_type)  // noqa

                val_name = value.get('name', '')
                data = value.get('data')
                new_key.create_value(val_name, val_type, data)
            return new_key
    return None
    */
    return nullptr;
}

std::shared_ptr<RegKey> RegistryManager::create_key(const std::string& path) {
    // Create a registry key
    std::string normalized_path = normalize_reg_path(path);
    
    // Does this key already exist?
    std::shared_ptr<RegKey> key = get_key_from_path(normalized_path);
    if (key) {
        return key;
    }

    // Does this key exist in our config
    key = get_key_from_config(normalized_path);
    if (key) {
        return key;
    }

    key = std::make_shared<RegKey>(normalized_path);
    keys.push_back(key);
    return key;
}

uint32_t RegistryManager::open_key(const std::string& path, bool create) {
    // Open or optionally create a registry key
    uint32_t hnd = 0;
    std::string normalized_path = normalize_reg_path(path);
    
    // Does the key already exist?
    std::shared_ptr<RegKey> key = get_key_from_path(normalized_path);
    if (key) {
        hnd = key->get_handle();
        reg_handles[hnd] = key;
        return hnd;
    }

    // Does this key exist in our config
    key = get_key_from_config(normalized_path);
    if (key) {
        hnd = key->get_handle();
        reg_handles[hnd] = key;
        return hnd;
    }

    // If we are instructed to create the key, do so
    if (create || is_key_a_parent_key(normalized_path)) {
        key = std::make_shared<RegKey>(normalized_path);
        hnd = key->get_handle();
        reg_handles[hnd] = key;
        keys.push_back(key);
    }
    return hnd;
}