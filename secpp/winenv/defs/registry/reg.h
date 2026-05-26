// spea_reg.h  Registry type definitions
//
// Maps to: speakeasy/winenv/defs/registry/reg.py
//
// Registry value type constants, HKEY constants, RTL registry path constants,
// KEY_VALUE_INFORMATION_CLASS enum, and KEY_VALUE_*_INFORMATION structures
// used by registry API handlers and kernel emulation.

#ifndef SPEAKEASY_DEFS_REGISTRY_SPEA_REG_H
#define SPEAKEASY_DEFS_REGISTRY_SPEA_REG_H

#include <cstdint>
#include <string>
#include <vector>
#include "../../../struct.h"

namespace speakeasy { namespace defs { namespace registry {

//  Registry value type constants 
// (Inside namespace to avoid Windows SDK REG_* macro conflicts)

constexpr int kRegNone     = 0;
constexpr int kRegSz       = 1;
constexpr int kRegExpandSz = 2;
constexpr int kRegBinary   = 3;
constexpr int kRegDword    = 4;
constexpr int kRegMultiSz  = 7;
constexpr int kRegQword    = 11;

//  RTL registry path constants 

constexpr int kRtlRegistryAbsolute   = 0;
constexpr int kRtlRegistryServices   = 1;
constexpr int kRtlRegistryControl    = 2;
constexpr int kRtlRegistryWindowsNt  = 3;
constexpr int kRtlRegistryDevicemap  = 4;
constexpr int kRtlRegistryUser       = 5;
constexpr int kRtlRegistryMaximum    = 6;

//  HKEY constants 

constexpr uint32_t kHkeyClassesRoot   = 0x80000000;
constexpr uint32_t kHkeyCurrentUser   = 0x80000001;
constexpr uint32_t kHkeyLocalMachine  = 0x80000002;
constexpr uint32_t kHkeyUsers        = 0x80000003;

//  KEY_VALUE_INFORMATION_CLASS enum 

enum class KeyValueInformationClass : int {
    KeyValueBasicInformation           = 0x00,
    KeyValueFullInformation            = 0x01,
    KeyValuePartialInformation         = 0x02,
    KeyValueFullInformationAlign64     = 0x03,
    KeyValuePartialInformationAlign64  = 0x04,
    KeyValueLayerInformation           = 0x05,
    MaxKeyValueInfoClass               = 0x06,
};

//  KEY_VALUE_PARTIAL_INFORMATION 

struct KEY_VALUE_PARTIAL_INFORMATION : speakeasy::EmuStruct {
    uint32_t TitleIndex = 0;
    uint32_t Type       = 0;
    uint32_t DataLength = 0;
    // Followed by Data[1] (variable-length)  handled at call site

    size_t sizeof_obj() const override { return 12; }
    std::vector<uint8_t> get_bytes() const override {
        std::vector<uint8_t> b(12);
        speakeasy::write_le(b, 0,  TitleIndex, 4);
        speakeasy::write_le(b, 4,  Type,       4);
        speakeasy::write_le(b, 8,  DataLength, 4);
        return b;
    }
};

//  KEY_VALUE_BASIC_INFORMATION 

struct KEY_VALUE_BASIC_INFORMATION : speakeasy::EmuStruct {
    uint32_t TitleIndex = 0;
    uint32_t Type       = 0;
    uint32_t NameLength = 0;
    // Followed by Name[1] (variable-length)  handled at call site

    size_t sizeof_obj() const override { return 12; }
    std::vector<uint8_t> get_bytes() const override {
        std::vector<uint8_t> b(12);
        speakeasy::write_le(b, 0,  TitleIndex, 4);
        speakeasy::write_le(b, 4,  Type,       4);
        speakeasy::write_le(b, 8,  NameLength, 4);
        return b;
    }
};

//  KEY_VALUE_FULL_INFORMATION 

struct KEY_VALUE_FULL_INFORMATION : speakeasy::EmuStruct {
    uint32_t TitleIndex = 0;
    uint32_t Type       = 0;
    uint32_t DataOffset = 0;
    uint32_t DataLength = 0;
    uint32_t NameLength = 0;
    // Followed by Name[1] (variable-length)  handled at call site

    size_t sizeof_obj() const override { return 20; }
    std::vector<uint8_t> get_bytes() const override {
        std::vector<uint8_t> b(20);
        speakeasy::write_le(b, 0,  TitleIndex, 4);
        speakeasy::write_le(b, 4,  Type,       4);
        speakeasy::write_le(b, 8,  DataOffset, 4);
        speakeasy::write_le(b, 12, DataLength, 4);
        speakeasy::write_le(b, 16, NameLength, 4);
        return b;
    }
};

//  Helper functions 

// Get the string name for an HKEY value
inline std::string get_hkey_type(uint32_t hkey) {
    switch (hkey) {
        case 0x80000000: return "HKEY_CLASSES_ROOT";
        case 0x80000001: return "HKEY_CURRENT_USER";
        case 0x80000002: return "HKEY_LOCAL_MACHINE";
        case 0x80000003: return "HKEY_USERS";
        default:         return "";
    }
}

// Get the string name for a registry value type
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

// Look up a registry value type value by its string name
inline int get_flag_value(const std::string& flag) {
    if (flag == "REG_NONE")      return kRegNone;
    if (flag == "REG_SZ")        return kRegSz;
    if (flag == "REG_EXPAND_SZ") return kRegExpandSz;
    if (flag == "REG_BINARY")    return kRegBinary;
    if (flag == "REG_DWORD")     return kRegDword;
    if (flag == "REG_MULTI_SZ")  return kRegMultiSz;
    if (flag == "REG_QWORD")     return kRegQword;
    return kRegNone;
}

// Look up a define value by its integer value (generic lookup)
inline int get_defines(int define, const std::string& prefix = "") {
    (void)define;
    (void)prefix;
    // Provided for compatibility; use get_value_type() or get_hkey_type() directly.
    return -1;
}

}}} // namespace speakeasy::defs::registry

#endif // SPEAKEASY_DEFS_REGISTRY_SPEA_REG_H
