// binemu.h
#ifndef BINEMU_H
#define BINEMU_H

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <exception>
#include <regex>
#include <functional>
#include <chrono>
#include <cstdint>

// TODO: Need C++ equivalents for these Python imports
// #include <json/json.h>  // For JSON handling (e.g., nlohmann/json.hpp)
// #include <capstone/capstone.h>  // For disassembly engine

#include "memmgr.h"
#include "profiler.h"
#include "common.h"
#include "arch.h"
#include "emuengine.h"
#include "version.h"
#include "errors.h"

// Constants
const bool WILDCARD_FLAG = bool;
// typedef std::tuple<std::map<std::string, std::vector<ApiHook>>, WILDCARD_FLAG> API_LEVEL;
// typedef std::tuple<std::map<std::string, API_LEVEL>, WILDCARD_FLAG> MODULE_LEVEL;

// Generic emulator class for binary code
class BinaryEmulator : public MemoryManager {
private:
    uint64_t stack_base;
    uint64_t page_size;
    uint64_t inst_count;
    uint64_t curr_instr_size;
    void* disasm_eng;
    bool builtin_hooks_set;
    EmuEngine* emu_eng;
    std::vector<void*> maps;
    std::map<std::string, std::string> config;
    std::map<int, std::vector<void*>> hooks;
    
    std::shared_ptr<Profiler> profiler;
    double runtime;
    std::string emu_version;
    void* logger;
    
    // Config fields
    std::map<std::string, std::string> osversion;
    std::map<std::string, std::string> env;
    std::map<std::string, std::string> user_config;
    std::string domain;
    std::string hostname;
    std::vector<std::string> symlinks;
    std::map<std::string, std::string> config_modules;
    std::vector<std::string> config_system_modules;
    std::vector<std::string> config_processes;
    std::vector<std::string> config_user_modules;
    std::map<std::string, std::string> config_analysis;
    int max_instructions;
    int timeout;
    int max_api_count;
    std::map<std::string, std::string> exceptions;
    std::vector<std::string> drive_config;
    std::map<std::string, std::string> filesystem_config;
    bool keep_memory_on_free;
    std::map<std::string, std::string> network_config;
    std::vector<std::string> network_adapters;
    std::string command_line;

public:
    // Constructor
    BinaryEmulator(const std::string& config, void* logger = nullptr);
    
    // Logging methods
    void log_info(const std::string& msg);
    void log_error(const std::string& msg);
    void log_exception(const std::string& msg);
    
    // Profiler methods
    std::shared_ptr<Profiler> get_profiler();
    std::map<std::string, std::string> get_report();
    std::string get_json_report();
    
    // Config methods
    void _parse_config(const std::string& config);
    std::string get_emu_version();
    std::map<std::string, std::string> get_os_version();
    std::string get_osver_string();
    std::string get_domain();
    std::string get_hostname();
    std::map<std::string, std::string> get_user();
    
    // Memory methods
    template<typename T>
    size_t sizeof(T obj);
    template<typename T>
    std::vector<uint8_t> get_bytes(T obj);
    
    // Emulation control methods
    void stop();
    void start(uint64_t addr, size_t size);
    
    // Network config methods
    std::map<std::string, std::string> get_network_config();
    std::vector<std::string> get_network_adapters();
    std::map<std::string, std::string> get_filesystem_config();
    std::vector<std::string> get_drive_config();
    
    // Register methods
    void reg_write(const std::string& reg, uint64_t val);
    void reg_write(int reg, uint64_t val);
    uint64_t reg_read(const std::string& reg);
    uint64_t reg_read(int reg);
    
    // Hook methods
    void set_hooks();
    std::tuple<std::string, std::string, std::string> _cs_disasm(const std::vector<uint8_t>& mem, 
                                                                 uint64_t addr, bool fast = true);
    std::tuple<std::string, std::string, std::string> disasm(const std::vector<uint8_t>& mem, 
                                                             uint64_t addr, bool fast = true);
    std::map<std::string, std::string> get_register_state();
    std::tuple<std::string, std::string, std::string> get_disasm(uint64_t addr, size_t size, bool fast = true);
    
    // Function call methods
    void set_func_args(uint64_t stack_addr, uint64_t ret_addr, 
                       const std::vector<uint64_t>& args, bool home_space = true);
    std::vector<uint64_t> get_func_argv(int callconv, int argc);
    void do_call_return(int argc, uint64_t ret_addr = 0, uint64_t ret_value = 0, int conv = 0);
    
    // Stack methods
    uint64_t get_ret_address();
    void set_ret_address(uint64_t addr);
    uint64_t push_stack(uint64_t val);
    uint64_t pop_stack();
    uint64_t get_stack_ptr();
    void set_stack_ptr(uint64_t addr);
    std::vector<std::tuple<uint64_t, uint64_t, std::string>> format_stack(int num_ptrs);
    void print_stack(int num_ptrs);
    std::vector<std::string> get_stack_trace(int num_ptrs = 16);
    
    // Program counter methods
    uint64_t get_pc();
    void set_pc(uint64_t addr);
    uint64_t get_return_val();
    
    // Stack management methods
    std::tuple<uint64_t, uint64_t> reset_stack(uint64_t base);
    std::tuple<uint64_t, uint64_t> alloc_stack(size_t size);
    void clean_stack_args(int argc);
    
    // Architecture methods
    int get_arch();
    std::string get_arch_name();
    
    // Memory string methods
    std::string read_mem_string(uint64_t address, int width = 1, int max_chars = 0);
    int mem_string_len(uint64_t address, int width = 1);
    std::vector<std::tuple<int, std::string>> get_ansi_strings(const std::vector<uint8_t>& data, int min_len = 4);
    std::vector<std::tuple<int, std::string>> get_unicode_strings(const std::vector<uint8_t>& data, int min_len = 4);
    size_t mem_copy(uint64_t dst, uint64_t src, size_t n);
    void write_mem_string(const std::string& string, uint64_t address, int width = 1);
    uint64_t read_ptr(uint64_t address);
    void write_ptr(uint64_t address, uint64_t val);
    int get_ptr_size();
    std::tuple<std::vector<std::tuple<int, std::string>>, std::vector<std::tuple<int, std::string>>> get_mem_strings();
    void set_ptr_size(int arch);
    
    // Module methods
    void* get_module_from_addr(uint64_t addr);
    
    // Hook management methods
    std::vector<ApiHook> get_api_hooks(const std::string& mod_name, const std::string& func_name);
    ApiHook add_api_hook(std::function<void()> cb, const std::string& module = "", 
                         const std::string& api_name = "", int argc = 0, 
                         void* call_conv = nullptr, BinaryEmulator* emu = nullptr);
    CodeHook add_code_hook(std::function<void()> cb, uint64_t begin = 1, uint64_t end = 0, 
                           std::map<std::string, std::string> ctx = {}, BinaryEmulator* emu = nullptr);
    void _dynamic_code_cb(BinaryEmulator* emu, uint64_t addr, size_t size, 
                          std::map<std::string, std::string> ctx = {});
    void _set_dyn_code_hook(uint64_t addr, size_t size, std::map<std::string, std::string> ctx = {});
    DynCodeHook add_dyn_code_hook(std::function<void()> cb, std::vector<std::string> ctx = {}, 
                                  BinaryEmulator* emu = nullptr);
    ReadMemHook add_mem_read_hook(std::function<void()> cb, uint64_t begin = 1, uint64_t end = 0, 
                                  BinaryEmulator* emu = nullptr);
    WriteMemHook add_mem_write_hook(std::function<void()> cb, uint64_t begin = 1, uint64_t end = 0, 
                                    BinaryEmulator* emu = nullptr);
    MapMemHook add_mem_map_hook(std::function<void()> cb, uint64_t begin = 1, uint64_t end = 0, 
                                BinaryEmulator* emu = nullptr);
    bool _hook_mem_invalid_dispatch(BinaryEmulator* emu, int access, uint64_t address, 
                                    size_t size, uint64_t value, std::map<std::string, std::string> ctx);
    InvalidMemHook add_mem_invalid_hook(std::function<void()> cb, BinaryEmulator* emu = nullptr);
    InterruptHook add_interrupt_hook(std::function<void()> cb, std::vector<std::string> ctx = {}, 
                                     BinaryEmulator* emu = nullptr);
    InstructionHook add_instruction_hook(std::function<void()> cb, uint64_t begin = 1, uint64_t end = 0, 
                                         std::vector<std::string> ctx = {}, BinaryEmulator* emu = nullptr, 
                                         void* insn = nullptr);
    InvalidInstructionHook add_invalid_instruction_hook(std::function<void()> cb, 
                                                        std::vector<std::string> ctx = {}, 
                                                        BinaryEmulator* emu = nullptr);
    
    // Virtual methods to be implemented by subclasses
    virtual void on_emu_complete() = 0;
    virtual void _set_emu_hooks() = 0;
    virtual std::tuple<uint64_t, size_t> get_valid_ranges(size_t size, uint64_t addr = 0) = 0;
    virtual std::shared_ptr<void> get_current_run() = 0;
    virtual std::vector<void*> get_mem_maps() = 0;
    virtual std::string get_address_tag(uint64_t ptr) = 0;
    virtual void* get_address_map(uint64_t addr) = 0;
    virtual void mem_reserve(size_t size, uint64_t base = 0) = 0;
};

#endif // BINEMU_H