// reg.h  Registry type definitions (new EmuStructHelper CRTP)
//
// Maps to: speakeasy/winenv/defs/registry/reg.py
//
// Registry value type constants, HKEY constants, RTL registry path constants,
// KEY_VALUE_INFORMATION_CLASS enum, and KEY_VALUE_*_INFORMATION structures.
// Uses the new EmuStructHelper CRTP approach for auto serialize/deserialize.
// Namespace speakeasy::defs::new_structs to avoid conflicts with existing defs.
//
// NOTE: KEY_VALUE_PARTIAL_INFORMATION is defined below.

#ifndef SPEAKEASY_DEFS_NEW_REGISTRY_REG_H
#define SPEAKEASY_DEFS_NEW_REGISTRY_REG_H

#include <cstdint>
#include <string>
#include "struct.h"

namespace speakeasy { namespace defs { namespace new_structs {

#pragma pack(push, 1)

// ------ Registry Value Type Constants ------------------------------------------------------
constexpr int kRegNone     = 0;
constexpr int kRegSz       = 1;
constexpr int kRegExpandSz = 2;
constexpr int kRegBinary   = 3;
constexpr int kRegDword    = 4;
constexpr int kRegMultiSz  = 7;
constexpr int kRegQword    = 11;

// ------ RTL Registry Path Constants --------------------------------------------------------
constexpr int kRtlRegistryAbsolute   = 0;
constexpr int kRtlRegistryServices   = 1;
constexpr int kRtlRegistryControl    = 2;
constexpr int kRtlRegistryWindowsNt  = 3;
constexpr int kRtlRegistryDevicemap  = 4;
constexpr int kRtlRegistryUser       = 5;
constexpr int kRtlRegistryMaximum    = 6;

// ------ HKEY Constants ---------------------------------------------------------------------
constexpr uint32_t kHkeyClassesRoot   = 0x80000000;
constexpr uint32_t kHkeyCurrentUser   = 0x80000001;
constexpr uint32_t kHkeyLocalMachine  = 0x80000002;
constexpr uint32_t kHkeyUsers        = 0x80000003;

// ------ KEY_VALUE_INFORMATION_CLASS Enum ---------------------------------------------------
enum class KeyValueInformationClass : int {
    KeyValueBasicInformation           = 0x00,
    KeyValueFullInformation            = 0x01,
    KeyValuePartialInformation         = 0x02,
    KeyValueFullInformationAlign64     = 0x03,
    KeyValuePartialInformationAlign64  = 0x04,
    KeyValueLayerInformation           = 0x05,
    MaxKeyValueInfoClass               = 0x06,
};

// ------ KEY_VALUE_BASIC_INFORMATION ---------------------------------------------------------
struct KEY_VALUE_BASIC_INFORMATION_POD {
    uint32_t TitleIndex = 0;
    uint32_t Type       = 0;
    uint32_t NameLength = 0;
    // Followed by Name[1] (variable-length) — handled at call site
};

struct KEY_VALUE_BASIC_INFORMATION : public EmuStructHelper<KEY_VALUE_BASIC_INFORMATION>, public KEY_VALUE_BASIC_INFORMATION_POD {
    std::string get_mem_tag() const override { return "key_value_basic_info"; }
};

// ------ KEY_VALUE_FULL_INFORMATION ----------------------------------------------------------
struct KEY_VALUE_FULL_INFORMATION_POD {
    uint32_t TitleIndex = 0;
    uint32_t Type       = 0;
    uint32_t DataOffset = 0;
    uint32_t DataLength = 0;
    uint32_t NameLength = 0;
    // Followed by Name[1] (variable-length) — handled at call site
};

struct KEY_VALUE_FULL_INFORMATION : public EmuStructHelper<KEY_VALUE_FULL_INFORMATION>, public KEY_VALUE_FULL_INFORMATION_POD {
    std::string get_mem_tag() const override { return "key_value_full_info"; }
};

// ------ Helper Functions -------------------------------------------------------------------

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

// ==========================================================================================================
// KEY_VALUE_PARTIAL_INFORMATION — moved from struct.h
// ==========================================================================================================
struct KEY_VALUE_PARTIAL_INFORMATION : public EmuStructHelper<KEY_VALUE_PARTIAL_INFORMATION> {
    uint32_t TitleIndex = 0;
    uint32_t Type = 0;
    uint32_t DataLength = 0;
    uint8_t  Data[1] = {};
    std::string get_mem_tag() const override { return "key_value_partial_info"; }
};

#pragma pack(pop)

}}} // namespace speakeasy::defs::new_structs

#endif // SPEAKEASY_DEFS_NEW_REGISTRY_REG_H
