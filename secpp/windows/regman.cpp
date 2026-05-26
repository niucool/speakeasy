// regman.cpp
#include "regman.h"
#include <algorithm>
#include <cctype>
#include <stdexcept>
#include <sstream>
#include <cstring>

// Static member initialization
uint32_t RegKey::curr_handle = 0x180;

//  Simple base64 encoder (for REG_BINARY normalization) 
namespace {

static const char b64_table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string base64_encode(const std::string& input) {
    std::string out;
    out.reserve(((input.size() + 2) / 3) * 4);
    size_t i = 0;
    while (i < input.size()) {
        unsigned char b0 = static_cast<unsigned char>(input[i++]);
        unsigned char b1 = (i < input.size()) ? static_cast<unsigned char>(input[i++]) : 0;
        unsigned char b2 = (i < input.size()) ? static_cast<unsigned char>(input[i++]) : 0;
        out += b64_table[b0 >> 2];
        out += b64_table[((b0 & 0x03) << 4) | (b1 >> 4)];
        out += (i > input.size() + 0) ? '=' : b64_table[((b1 & 0x0F) << 2) | (b2 >> 6)];
        out += (i > input.size() + 1) ? '=' : b64_table[b2 & 0x3F];
    }
    return out;
}

bool string_is_numeric(const std::string& s) {
    if (s.empty()) return false;
    size_t start = 0;
    if (s[0] == '-' || s[0] == '+') {
        if (s.size() == 1) return false;
        start = 1;
    }
    for (size_t i = start; i < s.size(); ++i) {
        if (!std::isdigit(static_cast<unsigned char>(s[i]))) {
            return false;
        }
    }
    return true;
}

} // anonymous namespace

// RegValue implementation
RegValue::RegValue(const std::string& name, int val_type, const std::string& data)
    : name(name), val_type(val_type) {
    this->data = normalize_value(val_type, data);
}

std::string RegValue::normalize_value(int vtype, const std::string& vdata) {
    // Convert registry values to string types (matching speakeasy/winenv/defs/registry/reg.py)
    if (vtype == REG_SZ || vtype == REG_EXPAND_SZ || vtype == REG_MULTI_SZ) {
        // String types - data must be a string
        return vdata;
    } else if (vtype == REG_DWORD || vtype == REG_QWORD) {
        // Numeric types - data may be a hex string or decimal string
        if (vdata.empty()) {
            return "0";
        }
        // If it starts with 0x, it's hex; otherwise try to parse as decimal
        // Store as decimal string representation
        if (vdata.size() > 2 && vdata[0] == '0' && (vdata[1] == 'x' || vdata[1] == 'X')) {
            // Hex string - convert to numeric string
            try {
                unsigned long long val = std::stoull(vdata, nullptr, 0);
                return std::to_string(val);
            } catch (...) {
                return vdata;
            }
        } else if (string_is_numeric(vdata)) {
            return vdata;
        } else {
            // Try to parse as hex
            try {
                unsigned long long val = std::stoull(vdata, nullptr, 0);
                return std::to_string(val);
            } catch (...) {
                return vdata;
            }
        }
    } else if (vtype == REG_BINARY) {
        // Binary data - base64 encode the raw bytes
        return base64_encode(vdata);
    } else {
        // Unknown type - return as-is
        return vdata;
    }
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
        std::string lname = name;
        std::string lvname = v_name;
        std::transform(lname.begin(), lname.end(), lname.begin(), ::tolower);
        std::transform(lvname.begin(), lvname.end(), lvname.begin(), ::tolower);
        
        if (lname == lvname) {
            return v;
        }
    }
    return nullptr;
}

// RegistryManager implementation
RegistryManager::RegistryManager(const speakeasy::RegistryConfig& config) : config(config) {
    // Initialize default registry keys matching Python's regdefs.get_hkey_type
    std::vector<uint32_t> hkeys = {HKEY_CLASSES_ROOT, HKEY_CURRENT_USER,
                                   HKEY_LOCAL_MACHINE, HKEY_USERS};
    
    for (uint32_t hk : hkeys) {
        std::string path = get_hkey_type(hk);
        if (!path.empty()) {
            auto key = create_key(path);
            reg_handles[hk] = key;
        }
    }
}

std::string RegistryManager::normalize_reg_path(const std::string& path) {
    std::string new_path = path;
    if (!path.empty()) {
        std::vector<std::string> roots = {"\\registry\\machine\\", "hklm\\"};
        for (const std::string& r : roots) {
            if (path.length() >= r.length()) {
                std::string lower_path = path;
                std::transform(lower_path.begin(), lower_path.end(), lower_path.begin(), ::tolower);
                
                std::string lower_r = r;
                std::transform(lower_r.begin(), lower_r.end(), lower_r.begin(), ::tolower);
                
                if (lower_path.substr(0, lower_r.length()) == lower_r) {
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

// Simple fnmatch-like matching for registry paths
// Supports '*' as wildcard matching any sequence of characters
static bool path_matches(const std::string& pattern, const std::string& str) {
    // Simple wildcard matching: '*' matches any sequence
    size_t pi = 0, si = 0;
    size_t last_star = std::string::npos;
    size_t last_si = 0;
    
    while (si < str.size()) {
        if (pi < pattern.size() && (pattern[pi] == str[si] || pattern[pi] == '?')) {
            pi++; si++;
        } else if (pi < pattern.size() && pattern[pi] == '*') {
            last_star = pi;
            last_si = si;
            pi++;
        } else if (last_star != std::string::npos) {
            pi = last_star + 1;
            last_si++;
            si = last_si;
        } else {
            return false;
        }
    }
    
    while (pi < pattern.size() && pattern[pi] == '*') {
        pi++;
    }
    
    return pi == pattern.size();
}

std::shared_ptr<RegKey> RegistryManager::get_key_from_path(const std::string& path) {
    std::string normalized_path = normalize_reg_path(path);
    std::string lower_normalized_path = normalized_path;
    std::transform(lower_normalized_path.begin(), lower_normalized_path.end(), 
                   lower_normalized_path.begin(), ::tolower);
    
    for (auto& key : keys) {
        std::string key_path = key->get_path();
        std::transform(key_path.begin(), key_path.end(), key_path.begin(), ::tolower);
        
        // fnmatch-style matching: check if key path matches the pattern
        if (path_matches(lower_normalized_path, key_path)) {
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
    // See if the emulator config file contains a handler for the requested registry path
    // Matches Python: for key in self.config.get('keys', []):
    //if (config.is_null() || !config.contains("registry") || 
    //    !config["registry"].is_object() || !config["registry"].contains("keys")) {
    //    return nullptr;
    //}
    if(config.keys.empty()) {
        return nullptr;
    }
    
    const auto& keys_arr = config.keys;
    
    std::string lower_path = path;
    std::transform(lower_path.begin(), lower_path.end(), lower_path.begin(), ::tolower);
    
    for (const auto& key_entry : keys_arr) {
        std::string key_path = key_entry.path;
        std::string lower_key_path = key_path;
        std::transform(lower_key_path.begin(), lower_key_path.end(), 
                       lower_key_path.begin(), ::tolower);
        
        if (lower_key_path == lower_path) {
            auto new_key = std::make_shared<RegKey>(path);
            
            if (!key_entry.values.empty()) {
                for (const auto& value_entry : key_entry.values) {
                    std::string val_name = value_entry.name;
                    std::string val_type_str = value_entry.type;
                    std::string val_data = value_entry.data;
                    
                    int val_type = get_flag_value(val_type_str);
                    new_key->create_value(val_name, val_type, val_data);
                }
            }
            
            return new_key;
        }
    }
    
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
