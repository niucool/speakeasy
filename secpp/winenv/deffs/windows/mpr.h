// mpr.h  Windows MPR constants (new EmuStructHelper CRTP)
//
// Maps to: speakeasy/winenv/defs/windows/mpr.py
//
// Constants only — no struct definitions.
// Namespace speakeasy::defs::new_structs.

#ifndef SPEAKEASY_DEFS_NEW_WINDOWS_MPR_H
#define SPEAKEASY_DEFS_NEW_WINDOWS_MPR_H

#include <string>
#include "struct.h"

namespace speakeasy { namespace defs { namespace new_structs {

// ==========================================================================================================
// MPR Constants
// ==========================================================================================================
constexpr int kResourceConnected   = 1;
constexpr int kResourceGlobalnet   = 2;
constexpr int kResourceRemembered  = 3;
constexpr int kResourceContext     = 5;

constexpr int kResourceTypeAny     = 0;
constexpr int kResourceTypeDisk    = 1;
constexpr int kResourceTypePrint   = 2;

constexpr int kResourceUsageConnectable = 1;
constexpr int kResourceUsageContainer   = 2;
constexpr int kResourceUsageAttached    = 0x10;
constexpr int kResourceUsageAll         = 0x13;

constexpr int kErrorNoNetwork      = 0x4C6;
// Old-name alias for migration compatibility
// ERROR_NO_NETWORK conflicts with Windows SDK macro; must undef first
#pragma push_macro("ERROR_NO_NETWORK")
#undef ERROR_NO_NETWORK
constexpr int ERROR_NO_NETWORK     = 0x4C6;

// ==========================================================================================================
// Utility function: get string name for a MPR constant
// ==========================================================================================================
inline std::string get_mpr_define(int define, const std::string& prefix = "") {
    if (prefix == "RESOURCE_") {
        switch (define) {
            case 1: return "RESOURCE_CONNECTED";
            case 2: return "RESOURCE_GLOBALNET";
            case 3: return "RESOURCE_REMEMBERED";
            case 5: return "RESOURCE_CONTEXT";
            default: return "";
        }
    }
    if (prefix == "RESOURCETYPE_") {
        switch (define) {
            case 0: return "RESOURCETYPE_ANY";
            case 1: return "RESOURCETYPE_DISK";
            case 2: return "RESOURCETYPE_PRINT";
            default: return "";
        }
    }
    if (prefix == "RESOURCEUSAGE_") {
        switch (define) {
            case 1:  return "RESOURCEUSAGE_CONNECTABLE";
            case 2:  return "RESOURCEUSAGE_CONTAINER";
            case 0x10: return "RESOURCEUSAGE_ATTACHED";
            case 0x13: return "RESOURCEUSAGE_ALL";
            default: return "";
        }
    }
    return "";
}

}}} // namespace speakeasy::defs::new_structs

#endif // SPEAKEASY_DEFS_NEW_WINDOWS_MPR_H
