// hammer.cpp — API Hammering Detection and Mitigation
//
// Maps to: speakeasy/windows/hammer.py
//
// Detects and mitigates API hammering as used by anti-sandbox/anti-emulation
// in malware samples. When the same API is called many times from the same
// return address (exceeding a threshold), the emulator patches the call site
// to short-circuit future calls.

#include "hammer.h"
#include <algorithm>
#include <cctype>
#include <iostream>
#include <sstream>

#include "winemu.h"

// Default list of APIs to always allow despite triggering API hammering detection
const std::vector<std::string> _default_api_hammer_allowlist = {
    "kernel32.WriteProcessMemory",
    "kernel32.WriteFile",
    "kernel32.ReadFile",
};

// Helper function to create a set with lowercase strings
std::set<std::string> _lowercase_set(const std::vector<std::string>& tt) {
    std::set<std::string> result;
    for (const std::string& bb : tt) {
        std::string lower_bb = bb;
        std::transform(lower_bb.begin(), lower_bb.end(), lower_bb.begin(), ::tolower);
        result.insert(lower_bb);
    }
    return result;
}

// Helper: check if an instruction mnemonic is a call or jmp
static bool is_call_or_jmp(const std::string& mnem) {
    return mnem == "call" || mnem == "jmp";
}

// Helper: check if an instruction is a direct call/jmp via pointer (e.g., "call dword ptr [addr]")
static bool is_direct_ptr_instr(const std::string& mnem, const std::string& instr) {
    return is_call_or_jmp(mnem) && instr.find("ptr") != std::string::npos;
}

// ApiHammer implementation
ApiHammer::ApiHammer(WindowsEmulator* emu,
                     const std::map<std::string, std::string>& cfg)
    : emu(emu), hammer_memregion(0), hammer_offset(0) {

    // Store the config
    config = cfg;

    // Load api_hammering configuration from the provided config map
    auto threshold_it = config.find("threshold");
    api_threshold = (threshold_it != config.end())
        ? std::stoi(threshold_it->second) : 1000;

    auto enabled_it = config.find("enabled");
    enabled = (enabled_it != config.end())
        ? (enabled_it->second == "true" || enabled_it->second == "1") : false;

    auto allow_it = config.find("allow_list");
    if (allow_it != config.end()) {
        // Allow list is comma-separated
        std::string raw = allow_it->second;
        std::vector<std::string> items;
        size_t pos = 0;
        while ((pos = raw.find(',')) != std::string::npos) {
            items.push_back(raw.substr(0, pos));
            raw.erase(0, pos + 1);
        }
        if (!raw.empty()) items.push_back(raw);
        allow_list = _lowercase_set(items);
    } else {
        allow_list = _lowercase_set(_default_api_hammer_allowlist);
    }
}

bool ApiHammer::is_allowed_api(const std::string& apiname) {
    /*
    Returns true if the given apiname is one we don't want to use api hammering
    mitigation for
    */
    std::string lower_apiname = apiname;
    std::transform(lower_apiname.begin(), lower_apiname.end(), lower_apiname.begin(), ::tolower);
    return allow_list.find(lower_apiname) != allow_list.end();
}

void ApiHammer::handle_import_func(const std::string& imp_api, int conv, int argc) {
    /*
    Identifies possible API hammering and attempts to patch in mitigations.

    When the same API is called repeatedly from the same return address,
    exceeding api_threshold, we patch the call site to bypass the API call.

    Two patch strategies:
      1. Direct call via 'call dword ptr [addr]' — inline patch with
         xor eax,eax; nop...
      2. Indirect call via 'call reg' — redirect to a hammer patch region
         that contains xor eax,eax; retn
    */
    if (!enabled) {
        // api hammering mitigation not enabled, so exit
        return;
    }

    if (is_allowed_api(imp_api)) {
        // this is an api that we always want to allow, don't bother trying to
        // prevent api hammering
        return;
    }

    if (!emu) return;

    // Build hammer key from API name + return address
    uint64_t ret_addr = emu->get_ret_address();
    std::ostringstream oss;
    oss << imp_api << std::hex << ret_addr;
    std::string hammer_key = oss.str();

    // Increment and check threshold
    api_stats[hammer_key] += 1;
    if (api_stats[hammer_key] < api_threshold) {
        return;
    }

    // Architecture-dependent patching
    int arch = emu->get_arch();

    if (arch == speakeasy::arch::ARCH_X86) {
        _handle_hammer_x86(imp_api, conv, argc, ret_addr);
    } else if (arch == speakeasy::arch::ARCH_AMD64) {
        _handle_hammer_amd64(imp_api, conv, argc, ret_addr);
    }
}

void ApiHammer::_handle_hammer_x86(const std::string& imp_api, int conv,
                                    int argc, uint64_t ret_addr) {
    /*
    Handle API hammering detection and patching for x86 (32-bit) architecture.

    Two main scenarios:
      A) Direct call: 'call dword ptr [addr]' — 6 bytes before return address.
         Patch inline with xor eax,eax + stack cleanup.
      B) Indirect call via register: 'call reg' — 2 bytes before return address.
         Too little space for inline stack fixup, so we redirect the register
         to a hammerpatch memory region.
    */
    try {
        uint64_t eip = ret_addr - 6;
        auto [mnem, op, instr] = emu->get_disasm(eip, DISASM_SIZE);
        emu->log_info("api hammering at: " + imp_api + " 0x" +
                      std::to_string(emu->get_pc()) + " " + mnem + " " +
                      op + " " + instr);

        if (is_direct_ptr_instr(mnem, instr)) {
            // Scenario A: direct call/jmp via pointer, we have 6 bytes of space
            if (conv == speakeasy::arch::CALL_CONV_CDECL) {
                // cdecl: caller cleans stack — just xor eax,eax & nops
                std::vector<uint8_t> patch = {0x31, 0xc0, 0x90, 0x90, 0x90, 0x90, 0x90};
                emu->mem_write(eip, patch);
                emu->log_info("API HAMMERING DETECTED - patching 1 cdecl at " +
                              std::to_string(eip));
            } else if (conv == speakeasy::arch::CALL_CONV_STDCALL) {
                // stdcall: callee cleans stack — xor eax,eax; add esp, <count>
                std::vector<uint8_t> patch = {0x31, 0xc0, 0x83, 0xc4,
                                               static_cast<uint8_t>(4 * argc), 0x90};
                emu->mem_write(eip, patch);
                emu->log_info("API HAMMERING DETECTED - patching 1 stdcall at " +
                              std::to_string(eip));
            }
        } else {
            // Scenario B: indirect call/jmp via register (2 bytes)
            eip = ret_addr - 2;
            auto [mnem2, op2, instr2] = emu->get_disasm(eip, DISASM_SIZE);
            emu->log_info("api hammering at: 0x" + std::to_string(emu->get_pc()) +
                          " " + mnem2 + " " + op2 + " " + instr2);

            if (is_call_or_jmp(mnem2)) {
                auto reg_it = speakeasy::arch::REG_LOOKUP.find(op2);
                if (reg_it != speakeasy::arch::REG_LOOKUP.end()) {
                    // Allocate hammer patch region if not yet created
                    if (hammer_memregion == 0) {
                        hammer_memregion = emu->mem_map(0x1024 * 4, 0, PERM_MEM_RWX,
                                                        "speakeasy.hammerpatch");
                    }

                    if (conv == speakeasy::arch::CALL_CONV_CDECL) {
                        // cdecl: xor eax, eax; retn
                        std::vector<uint8_t> patch = {0x31, 0xc0, 0xc3};
                        emu->mem_write(eip, patch);
                        emu->log_info("API HAMMERING DETECTED - patching 2 cdecl at " +
                                      std::to_string(eip));
                    } else if (conv == speakeasy::arch::CALL_CONV_STDCALL) {
                        // stdcall: xor eax, eax; retn <count>
                        uint16_t stack_pop = static_cast<uint16_t>(4 * argc);
                        std::vector<uint8_t> patch = {0x31, 0xc0, 0xc2,
                                                       static_cast<uint8_t>(stack_pop & 0xFF),
                                                       static_cast<uint8_t>((stack_pop >> 8) & 0xFF),
                                                       0x90};
                        // Build cache key from calling convention and argument count
                        std::string cache_key = "x86_stdcall_" + std::to_string(argc);
                        auto cache_it = hammer_patch_cache.find(cache_key);
                        uint64_t loc;
                        if (cache_it != hammer_patch_cache.end()) {
                            // Reuse existing patch location
                            loc = cache_it->second;
                        } else if ((hammer_offset + patch.size()) < 0x1024 * 4) {
                            // Write new patch to hammer_memregion and cache it
                            loc = hammer_memregion + hammer_offset;
                            emu->mem_write(loc, patch);
                            hammer_offset += patch.size();
                            hammer_patch_cache[cache_key] = loc;
                        } else {
                            return;
                        }
                        // Redirect the register to our hammer patch
                        int reg = reg_it->second;
                        emu->reg_write(reg, loc);
                        emu->log_info("API HAMMERING DETECTED - patching 2 stdcall at " +
                                      std::to_string(eip));
                    }
                }
            } else {
                emu->log_info("API HAMMERING DETECTED - unable to patch " +
                              std::to_string(eip));
            }
        }
    } catch (const std::exception& e) {
        emu->log_info("api hammering disassembly failed at return address 0x" +
                      std::to_string(ret_addr) + ": " + e.what());
    }
}

void ApiHammer::_handle_hammer_amd64(const std::string& imp_api, int conv,
                                      int argc, uint64_t ret_addr) {
    /*
    Handle API hammering detection and patching for x64 (AMD64) architecture.

    The x64 calling convention uses registers rcx, rdx, r8, r9 for the first
    4 arguments and the stack for the rest. The caller is responsible for
    cleaning the stack (like cdecl), so patches always use xor eax,eax; ret.

    Two main scenarios:
      A) Direct call/jmp: 'call qword ptr [addr]' or 'jmp qword ptr [addr]' —
         6 bytes before return address. Patch inline with xor eax,eax; ret + nops.
      B) Indirect call/jmp via register: 'call reg' or 'jmp reg' — 2 bytes.
         Redirect the register to our hammer patch region (xor eax,eax; ret).
    */
    try {
        // Scenario A: try direct call/jmp via qword ptr (6 bytes)
        uint64_t eip = ret_addr - 6;
        auto [mnem, op, instr] = emu->get_disasm(eip, DISASM_SIZE);
        emu->log_info("api hammering at: " + imp_api + " 0x" +
                      std::to_string(emu->get_pc()) + " " + mnem + " " +
                      op + " " + instr);

        if (is_direct_ptr_instr(mnem, instr)) {
            // Scenario A: direct call/jmp via pointer — 6 bytes of space
            // x64 always uses caller-cleanup (like cdecl)
            // Patch: xor eax, eax (31 c0); ret (c3); nop padding
            std::vector<uint8_t> patch = {0x31, 0xc0, 0xc3, 0x90, 0x90, 0x90};
            emu->mem_write(eip, patch);
            emu->log_info("API HAMMERING DETECTED - patching amd64 direct at " +
                          std::to_string(eip));
        } else {
            // Scenario B: try indirect call/jmp via register (2 bytes)
            eip = ret_addr - 2;
            auto [mnem2, op2, instr2] = emu->get_disasm(eip, DISASM_SIZE);
            emu->log_info("api hammering at: 0x" + std::to_string(emu->get_pc()) +
                          " " + mnem2 + " " + op2 + " " + instr2);

            if (is_call_or_jmp(mnem2)) {
                auto reg_it = speakeasy::arch::REG_LOOKUP.find(op2);
                if (reg_it != speakeasy::arch::REG_LOOKUP.end()) {
                    // Allocate hammer patch region if not yet created
                    if (hammer_memregion == 0) {
                        hammer_memregion = emu->mem_map(0x1024 * 4, 0, PERM_MEM_RWX,
                                                        "speakeasy.hammerpatch");
                    }

                    // x64: patch is always xor eax, eax; ret (31 c0 c3)
                    std::vector<uint8_t> patch = {0x31, 0xc0, 0xc3};

                    // Check cache for existing patch
                    std::string cache_key = "amd64_default";
                    auto cache_it = hammer_patch_cache.find(cache_key);
                    uint64_t loc;
                    if (cache_it != hammer_patch_cache.end()) {
                        // Reuse existing patch location
                        loc = cache_it->second;
                    } else if ((hammer_offset + patch.size()) < 0x1024 * 4) {
                        // Write new patch and cache it
                        loc = hammer_memregion + hammer_offset;
                        emu->mem_write(loc, patch);
                        hammer_offset += patch.size();
                        hammer_patch_cache[cache_key] = loc;
                    } else {
                        return;
                    }

                    // Redirect the register to our hammer patch
                    int reg = reg_it->second;
                    emu->reg_write(reg, loc);
                    emu->log_info("API HAMMERING DETECTED - patching amd64 reg at " +
                                  std::to_string(eip));
                }
            } else {
                emu->log_info("API HAMMERING DETECTED - unable to patch " +
                              std::to_string(eip));
            }
        }
    } catch (const std::exception& e) {
        emu->log_info("api hammering disassembly failed at return address 0x" +
                      std::to_string(ret_addr) + ": " + e.what());
    }
}
