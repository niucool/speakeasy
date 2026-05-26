// regdefs.h  Registry type constants and helpers
// Maps to: speakeasy/winenv/defs/registry/reg.py

#ifndef REGDEFS_H
#define REGDEFS_H

#include <cstdint>
#include <string>

// Registry value type constants (guarded against Windows SDK macros)
#ifndef REG_NONE
constexpr int REG_NONE = 0;
#endif
#ifndef REG_SZ
constexpr int REG_SZ = 1;
#endif
#ifndef REG_EXPAND_SZ
constexpr int REG_EXPAND_SZ = 2;
#endif
#ifndef REG_BINARY
constexpr int REG_BINARY = 3;
#endif
#ifndef REG_DWORD
constexpr int REG_DWORD = 4;
#endif
#ifndef REG_MULTI_SZ
constexpr int REG_MULTI_SZ = 7;
#endif
#ifndef REG_QWORD
constexpr int REG_QWORD = 11;
#endif

// RTL registry path constants (guarded against Windows SDK macros)
#ifndef RTL_REGISTRY_ABSOLUTE
constexpr int RTL_REGISTRY_ABSOLUTE = 0;
#endif
#ifndef RTL_REGISTRY_SERVICES
constexpr int RTL_REGISTRY_SERVICES = 1;
#endif
#ifndef RTL_REGISTRY_CONTROL
constexpr int RTL_REGISTRY_CONTROL = 2;
#endif
#ifndef RTL_REGISTRY_WINDOWS_NT
constexpr int RTL_REGISTRY_WINDOWS_NT = 3;
#endif
#ifndef RTL_REGISTRY_DEVICEMAP
constexpr int RTL_REGISTRY_DEVICEMAP = 4;
#endif
#ifndef RTL_REGISTRY_USER
constexpr int RTL_REGISTRY_USER = 5;
#endif
#ifndef RTL_REGISTRY_MAXIMUM
constexpr int RTL_REGISTRY_MAXIMUM = 6;
#endif

// HKEY constants (guarded against Windows SDK macros)
#ifndef HKEY_CLASSES_ROOT
constexpr uint32_t HKEY_CLASSES_ROOT = 0x80000000;
constexpr uint32_t HKEY_CURRENT_USER = 0x80000001;
constexpr uint32_t HKEY_LOCAL_MACHINE = 0x80000002;
constexpr uint32_t HKEY_USERS = 0x80000003;
#endif

// HKEY type name lookup
inline std::string get_hkey_type(uint32_t hkey) {
    switch (hkey) {
        case 0x80000000: return "HKEY_CLASSES_ROOT";
        case 0x80000001: return "HKEY_CURRENT_USER";
        case 0x80000002: return "HKEY_LOCAL_MACHINE";
        case 0x80000003: return "HKEY_USERS";
        default: return "";
    }
}

// Get string name for a registry value type
inline std::string get_value_type(int define) {
    switch (define) {
        case 0:  return "REG_NONE";
        case 1:  return "REG_SZ";
        case 2:  return "REG_EXPAND_SZ";
        case 3:  return "REG_BINARY";
        case 4:  return "REG_DWORD";
        case 7:  return "REG_MULTI_SZ";
        case 11: return "REG_QWORD";
        default: return "REG_UNKNOWN";
    }
}

// Look up a flag value by name (from globals-like lookup)
inline int get_flag_value(const std::string& flag) {
    if (flag == "REG_NONE")      return REG_NONE;
    if (flag == "REG_SZ")        return REG_SZ;
    if (flag == "REG_EXPAND_SZ") return REG_EXPAND_SZ;
    if (flag == "REG_BINARY")    return REG_BINARY;
    if (flag == "REG_DWORD")     return REG_DWORD;
    if (flag == "REG_MULTI_SZ")  return REG_MULTI_SZ;
    if (flag == "REG_QWORD")     return REG_QWORD;
    return REG_NONE;
}

#endif // REGDEFS_H
