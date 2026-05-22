// hammer.h
#ifndef HAMMER_H
#define HAMMER_H

#include <string>
#include <vector>
#include <map>
#include <set>
#include <cstdint>
#include <memory>

#include "../config.h"

class WindowsEmulator;

// Class to detect and attempt to mitigate API hammering as part of anti-sandbox or
// anti-emulation in malware samples
class ApiHammer {
private:
    WindowsEmulator* emu;
    std::map<std::string, int> api_stats;
    uint64_t hammer_memregion;
    size_t hammer_offset;
    std::map<std::string, uint64_t> hammer_patch_cache; // patch content key -> location in hammer_memregion

    const speakeasy::ApiHammeringConfig& config;
    int api_threshold;
    bool enabled;
    std::set<std::string> allow_list;

public:
    // Constructor
    ApiHammer(WindowsEmulator* emu,
        const speakeasy::SpeakeasyConfig& cfg = {});
    
    // Methods
    bool is_allowed_api(const std::string& apiname);
    void handle_import_func(const std::string& imp_api, int conv, int argc);

private:
    // Architecture-specific hammering handlers
    void _handle_hammer_x86(const std::string& imp_api, int conv,
                            int argc, uint64_t ret_addr);
    void _handle_hammer_amd64(const std::string& imp_api, int conv,
                              int argc, uint64_t ret_addr);
};

#endif // HAMMER_H