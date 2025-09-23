// hammer.h
#ifndef HAMMER_H
#define HAMMER_H

#include <string>
#include <vector>
#include <map>
#include <set>
#include <memory>
#include <cstdint>

// TODO: Need C++ equivalents for these Python imports
// #include "speakeasy/winenv/arch.h"

// When disassembling, a minimum instruction size needs to be supplied
// This number is arbitrary and just needs to be large enough to cover
// the size of the current disasm target
const int DISASM_SIZE = 0x20;

// Forward declarations
class ApiHammer;

// Default list of APIs to always allow despite triggering API hammering detection
extern const std::vector<std::string> _default_api_hammer_allowlist;

// Helper function to create a set with lowercase strings
std::set<std::string> _lowercase_set(const std::vector<std::string>& tt);

// Class to detect and attempt to mitigate API hammering as part of anti-sandbox or
// anti-emulation in malware samples
class ApiHammer {
private:
    void* emu; // TODO: Should be WindowsEmulator* or appropriate emulator type
    std::map<std::string, int> api_stats;
    uint64_t hammer_memregion;
    size_t hammer_offset;
    
    std::map<std::string, std::string> config;
    int api_threshold;
    bool enabled;
    std::set<std::string> allow_list;

public:
    // Constructor
    ApiHammer(void* emu);
    
    // Methods
    bool is_allowed_api(const std::string& apiname);
    void handle_import_func(const std::string& imp_api, int conv, int argc);
};

#endif // HAMMER_H