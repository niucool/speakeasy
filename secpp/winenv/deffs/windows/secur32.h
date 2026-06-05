// secur32.h  Windows SECUR32 constants (new EmuStructHelper CRTP)
//
// Maps to: speakeasy/winenv/defs/windows/secur32.py
//
// Constants only — no struct definitions.
// Namespace speakeasy::defs::new_structs.

#ifndef SPEAKEASY_DEFS_NEW_WINDOWS_SECUR32_H
#define SPEAKEASY_DEFS_NEW_WINDOWS_SECUR32_H

#include <string>
#include "struct.h"

namespace speakeasy { namespace defs { namespace new_structs {

// ==========================================================================================================
// EXTENDED_NAME_FORMAT
// ==========================================================================================================
constexpr int kNameUnknown              = 0;
constexpr int kNameFullyQualifiedDN     = 1;
constexpr int kNameSamCompatible        = 2;
constexpr int kNameDisplay              = 3;
constexpr int kNameUniqueId             = 6;
constexpr int kNameCanonical            = 7;
constexpr int kNameUserPrincipal        = 8;
constexpr int kNameCanonicalEx          = 9;
constexpr int kNameServicePrincipal     = 0xA;
constexpr int kNameDnsDomain            = 0xC;
constexpr int kNameGivenName            = 0xD;
constexpr int kNameSurname              = 0xE;

constexpr int kSecEInvalidHandle         = 0x80090301;

// ==========================================================================================================
// Utility function: get string name for an EXTENDED_NAME_FORMAT value
// ==========================================================================================================
inline std::string get_name_format(int define) {
    switch (define) {
        case 0:   return "NameUnknown";
        case 1:   return "NameFullyQualifiedDN";
        case 2:   return "NameSamCompatible";
        case 3:   return "NameDisplay";
        case 6:   return "NameUniqueId";
        case 7:   return "NameCanonical";
        case 8:   return "NameUserPrincipal";
        case 9:   return "NameCanonicalEx";
        case 0xA: return "NameServicePrincipal";
        case 0xC: return "NameDnsDomain";
        case 0xD: return "NameGivenName";
        case 0xE: return "NameSurname";
        default:  return "";
    }
}

}}} // namespace speakeasy::defs::new_structs

#endif // SPEAKEASY_DEFS_NEW_WINDOWS_SECUR32_H
