// speakeasy.cpp
#include "speakeasy.h"
#include "windows/kernel.h"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cstring>
// MSVC + pe-parse: pe-parse provides its own constexpr constants for PE
// structures, but Windows SDK defines most of them as macros, causing
// compilation errors. Use _PEPARSE_WINDOWS_CONFLICTS to skip pe-parse's
// own definitions (relying on Windows SDK macros instead on MSVC).
// We use raw integer values in this file to avoid depending on either.
#ifdef PLATFORM_WINDOWS
#define _PEPARSE_WINDOWS_CONFLICTS
#endif
#include <pe-parse/parse.h>
#include "struct.h"

Speakeasy::Speakeasy(const speakeasy::SpeakeasyConfig& cfg, void* logger, 
                     const std::vector<std::string>& argv, bool debug, void* exit_event)
    : logger(logger), config(cfg), emu(nullptr), argv(argv), exit_event(exit_event), 
      debug(debug) {
    try {
        validate_config(this->config);
    } catch (const std::exception& err) {
        throw ConfigError("Invalid config: " + std::string(err.what()));
    }
}

Speakeasy::~Speakeasy() { shutdown(); }

void Speakeasy::_init_emulator(const std::string& path, const std::vector<uint8_t>& data, bool is_raw_code) {
    if (!is_raw_code) {
        // ── Use pe-parse for PE analysis (Python: _PeParser) ──
        peparse::parsed_pe* pe = nullptr;
        if (!path.empty()) {
            pe = peparse::ParsePEFromFile(path.c_str());
        } else if (!data.empty()) {
            // ParsePEFromPointer requires mutable buffer with uint32_t length
            auto* buf = const_cast<uint8_t*>(data.data());
            auto sz = static_cast<uint32_t>(data.size());
            pe = peparse::ParsePEFromPointer(buf, sz);
        }

        bool is_driver = false;
        bool is_dotnet = false;
        std::string pe_arch;

        if (pe) {
            try {
                auto& nt = pe->peHeader.nt;
                auto& fh = nt.FileHeader;
                auto& oh = nt.OptionalHeader;

                // ── Architecture check (Python: MACHINE_TYPE) ──
                if (fh.Machine == 0x8664) {  // IMAGE_FILE_MACHINE_AMD64
                    pe_arch = "amd64";
                } else if (fh.Machine == 0x14c) {  // IMAGE_FILE_MACHINE_I386
                    pe_arch = "i386";
                } else {
                    std::string arch_str = "0x" + std::to_string(fh.Machine);
                    throw SpeakeasyError("Unsupported architecture: " + arch_str);
                }

                // ── .NET detection (Python: pe.is_dotnet()) ──
                // DIR_COM_DESCRIPTOR (index 14) has non-zero VA for .NET
                if (nt.OptionalMagic == 0x20B ||  // NT_OPTIONAL_64_MAGIC
                    nt.OptionalMagic == 0x10B) {  // NT_OPTIONAL_32_MAGIC
                    auto& dirs = oh.DataDirectory;
                    if (dirs[14].VirtualAddress != 0) {  // DIR_COM_DESCRIPTOR
                        is_dotnet = true;
                    }
                }

                // ── Driver detection (Python: pe.is_driver()) ──
                // 1. Characteristics check
                if (fh.Characteristics & 0x1000) {  // IMAGE_FILE_SYSTEM
                    is_driver = true;
                }
                // 2. Subsystem check: IMAGE_SUBSYSTEM_NATIVE often indicates driver
                if (nt.OptionalMagic == 0x10B) {  // NT_OPTIONAL_32_MAGIC
                    if (oh.Subsystem == 1)  // IMAGE_SUBSYSTEM_NATIVE
                        is_driver = true;
                }

            } catch (...) {
                peparse::DestructParsedPE(pe);
                throw;
            }
            peparse::DestructParsedPE(pe);
        }

        if (is_dotnet) {
            throw NotSupportedError(".NET assemblies are not currently supported");
        }

        if (is_driver) {
            // ── Kernel-mode emulator (Python: WinKernelEmulator) ──
            emu = new speakeasy::WinKernelEmulator(config, argv, debug, logger, exit_event);
        } else {
            // ── User-mode emulator (Python: Win32Emulator) ──
            emu = new Win32Emulator(config, argv, debug, logger, exit_event);
        }
    } else {
        // ── Raw/Shellcode mode (Python: Win32Emulator) ──
        emu = new Win32Emulator(config, argv, debug, logger, exit_event);
    }
}

void Speakeasy::_init_hooks() {
    while (!api_hooks.empty()) {
        auto [cb, mod, func, argc, cconv] = api_hooks.front();
        api_hooks.erase(api_hooks.begin());
        add_api_hook(cb, mod, func, argc, cconv);
    }
    while (!code_hooks.empty()) {
        auto [cb, begin, end, ctx] = code_hooks.front();
        code_hooks.erase(code_hooks.begin());
        add_code_hook(cb, begin, end, ctx);
    }
}

std::tuple<std::string, std::string, std::string> Speakeasy::disasm(uint64_t addr, size_t size, bool fast) {
    return std::make_tuple("","",""); // get_disasm deferred
}

bool Speakeasy::is_pe(const std::vector<uint8_t>& data) {
    return (data.size() >= 2 && data[0] == 'M' && data[1] == 'Z');
}

speakeasy::LoadedImage* Speakeasy::load_module(const std::string& path, const std::vector<uint8_t>& data) {
    if (path.empty() && data.empty())
        throw SpeakeasyError("No emulation target supplied");
    if (!path.empty() && !std::ifstream(path).good())
        throw SpeakeasyError("Target file not found: " + path);
    loaded_bins.push_back(path);
    std::vector<uint8_t> test;
    if (!data.empty()) {
        test = data;
    }
    else {
        std::ifstream f(path, std::ios::binary); 
        test.resize(4); 
        f.read(reinterpret_cast<char*>(test.data()), 4); 
    }
    if (!is_pe(test)) 
        throw SpeakeasyError("Target file is not a PE");
    _init_emulator(path, data);
    return emu->load_module(path, data);
}

void Speakeasy::run_module(speakeasy::LoadedImage* module, bool all_entrypoints, bool emulate_children) {
    _init_hooks();
    emu->run_module(module, all_entrypoints, emulate_children);
}

uint64_t Speakeasy::load_shellcode(const std::string& fpath, const std::string& arch, 
                                  const std::vector<uint8_t>& data) {
    _init_emulator("", {}, true);
    loaded_bins.push_back(fpath);
    return emu->load_shellcode(fpath, arch, data);
}

void Speakeasy::run_shellcode(uint64_t sc_addr, size_t stack_commit, size_t offset) {
    _init_hooks();
    emu->run_shellcode(sc_addr, stack_commit, offset);
}

nlohmann::json Speakeasy::get_report() { return emu->get_report(); }

std::string Speakeasy::get_json_report() { return emu->get_json_report_string(); }

void* Speakeasy::add_api_hook(std::function<void()> cb, const std::string& module, 
                             const std::string& api_name, int argc, const std::string& call_conv) {
    if (!emu) {
        api_hooks.emplace_back(cb, module, api_name, argc, call_conv); // call_conv string stored
        return nullptr;
    }
    emu->add_api_hook(cb, module, api_name, argc, nullptr, (BinaryEmulator*)this);
    return nullptr;  // call_conv deferred
}

void Speakeasy::resume(uint64_t addr, int count) { emu->resume(addr, count); }

void Speakeasy::stop() { emu->stop(); }

void Speakeasy::shutdown() { if (emu) { delete emu; emu = nullptr; } }

void Speakeasy::call(uint64_t addr, const std::vector<void*>& params) { (void)addr; (void)params; }

void* Speakeasy::add_code_hook(std::function<void()> cb, uint64_t begin, uint64_t end, const std::map<std::string, std::string>& ctx) {
    if (!emu) { code_hooks.emplace_back(cb, begin, end, ctx); return nullptr; }
    emu->add_code_hook(cb, begin, end, ctx, (BinaryEmulator*)this);
    return nullptr;
}

void* Speakeasy::add_dyn_code_hook(std::function<void()> cb, const std::map<std::string, std::string>& ctx) {
    if (!emu) { dyn_code_hooks.emplace_back(cb, ctx); return nullptr; }
    std::vector<std::string> ctx_vec;
    for (auto& [k, v] : ctx) ctx_vec.push_back(k + "=" + v);
    emu->add_dyn_code_hook(cb, ctx_vec, (BinaryEmulator*)this);
    return nullptr;
}

void* Speakeasy::add_mem_read_hook(std::function<void()> cb, uint64_t begin, uint64_t end) {
    if (!emu) { mem_read_hooks.emplace_back(cb, begin, end); return nullptr; }
    emu->add_mem_read_hook(cb, begin, end, (BinaryEmulator*)this);
    return nullptr;
}

void* Speakeasy::add_mem_write_hook(std::function<void()> cb, uint64_t begin, uint64_t end) {
    if (!emu) { mem_write_hooks.emplace_back(cb, begin, end); return nullptr; }
    emu->add_mem_write_hook(cb, begin, end, (BinaryEmulator*)this);
    return nullptr;
}

void* Speakeasy::add_IN_instruction_hook(std::function<void()> cb, uint64_t begin, uint64_t end) {
    if (!emu) { mem_write_hooks.emplace_back(cb, begin, end); return nullptr; }
    emu->add_instruction_hook(cb, begin, end, {}, (BinaryEmulator*)this, (void*)(uintptr_t)218);
    return nullptr;
}

void* Speakeasy::add_SYSCALL_instruction_hook(std::function<void()> cb, uint64_t begin, uint64_t end) {
    if (!emu) { mem_write_hooks.emplace_back(cb, begin, end); return nullptr; }
    emu->add_instruction_hook(cb, begin, end, {}, (BinaryEmulator*)this, (void*)(uintptr_t)700);
    return nullptr;
}

void* Speakeasy::add_invalid_instruction_hook(std::function<void()> cb, const std::vector<void*>& ctx) {
    if (!emu) { invalid_insn_hooks.emplace_back(cb, ctx); return nullptr; } // ctx type mismatch
    std::vector<std::string> ctx_str;
    for (auto p : ctx) ctx_str.push_back(std::to_string((uintptr_t)p));
    emu->add_invalid_instruction_hook(cb, ctx_str);
    return nullptr;
}

void* Speakeasy::add_mem_invalid_hook(std::function<void()> cb) {
    if (!emu) { mem_invalid_hooks.emplace_back(cb); return nullptr; }
    // cb type mismatch: emu expects bool(void*,int,uint64_t,size_t,uint64_t,void*)
    return nullptr;
}

void* Speakeasy::add_interrupt_hook(std::function<void()> cb, const std::map<std::string, std::string>& ctx) {
    if (!emu) { interrupt_hooks.emplace_back(cb, ctx); return nullptr; }
    // cb type mismatch
    return nullptr;
}

void* Speakeasy::add_mem_map_hook(std::function<void()> cb, uint64_t begin, uint64_t end) {
    if (!emu) { mem_map_hooks.emplace_back(cb, begin, end); return nullptr; }
    emu->add_mem_map_hook(cb, begin, end, (BinaryEmulator*)this);
    return nullptr;
}

void* Speakeasy::get_registry_key(int handle, const std::string& path) { (void)handle; (void)path; return nullptr; }
void* Speakeasy::get_address_map(uint64_t addr) { (void)addr; return nullptr; }
std::vector<void*> Speakeasy::get_user_modules() { return {}; }
std::vector<void*> Speakeasy::get_sys_modules() { return {}; }

uint64_t Speakeasy::mem_alloc(size_t size, uint64_t base, const std::string& tag) {
    return emu->mem_map(size, PERM_MEM_READ | PERM_MEM_WRITE, base, tag);
}

void Speakeasy::mem_free(uint64_t base) { emu->mem_free(base); }

std::vector<uint8_t> Speakeasy::mem_read(uint64_t addr, size_t size) {
    return emu->mem_read(addr, size);
}

void Speakeasy::mem_write(uint64_t addr, const std::vector<uint8_t>& data) { emu->mem_write(addr, data); }
void* Speakeasy::mem_cast(void* obj, uint64_t addr) { (void)obj; (void)addr; return nullptr; }

uint64_t Speakeasy::reg_read(const std::string& reg) {
    // reg name translation needed
    (void)reg;
    return 0;
}

std::vector<std::tuple<uint64_t, std::string, std::string>> Speakeasy::get_dyn_imports() {
    return {};
}

void Speakeasy::reg_write(const std::string& reg, uint64_t val) {
    (void)reg; (void)val;
}

std::vector<void*> Speakeasy::get_dropped_files() { return {}; }

std::vector<uint8_t> Speakeasy::create_file_archive() { return {}; }

std::vector<void*> Speakeasy::get_mem_maps() { return {}; }

std::vector<std::tuple<std::string, uint64_t, size_t, bool, void*, std::vector<uint8_t>>>
Speakeasy::get_memory_dumps() { return {}; }

std::string Speakeasy::read_mem_string(uint64_t address, int width, size_t max_chars) {
    return emu->read_mem_string(address, width, max_chars);
}

std::map<uint64_t, std::tuple<std::string, std::string>> Speakeasy::get_symbols() {
    return {}; // symbols access deferred
}

uint64_t Speakeasy::get_ret_address() { return emu->get_ret_address(); }
void Speakeasy::set_ret_address(uint64_t addr) { emu->set_ret_address(addr); }
void Speakeasy::push_stack(uint64_t val) { emu->push_stack(val); }
uint64_t Speakeasy::pop_stack() { return emu->pop_stack(); }
uint64_t Speakeasy::get_stack_ptr() { return emu->get_stack_ptr(); }
void Speakeasy::set_stack_ptr(uint64_t addr) { emu->set_stack_ptr(addr); }
uint64_t Speakeasy::get_pc() { return emu->get_pc(); }
void Speakeasy::set_pc(uint64_t addr) { emu->set_pc(addr); }

std::tuple<uint64_t, uint64_t> Speakeasy::reset_stack(uint64_t base) { return emu->reset_stack(base); }
uint64_t Speakeasy::get_stack_base() { return 0; }
int Speakeasy::get_arch() { return emu->get_arch(); }
int Speakeasy::get_ptr_size() { return emu->get_ptr_size(); }
std::map<std::string, uint64_t> Speakeasy::get_all_registers() {
    return {}; // all_registers access deferred
}

std::string Speakeasy::get_symbol_from_address(uint64_t address) { (void)address;return ""; }
bool Speakeasy::is_address_valid(uint64_t address) { (void)address;return false; }

std::vector<uint8_t> Speakeasy::create_memdump_archive() { return {}; }

void validate_config(const nlohmann::json& config) { (void)config; }
