// binemu.h -- Binary Emulator base class (porting layer)
// Ported from: speakeasy/binemu.py (1147 lines)
// Porting status: 48/48 functions | 3 known gaps (PORTING_PROGRESS.md)
// Last sync: 2026-05-17
//
// Notes:
// - sizeof/get_bytes (objsize/get_bytes) use sizeof(T)/raw byte copy as fallback;
//   subclass overrides needed for EmuStruct types with virtual methods.
// - Hook classes (ApiHook, CodeHook, etc.) are wrappers around binaryemulator-generated IDs;
//   full cb() dispatch with memory access info (emu, access, address, size, value)
//   requires subclass Hook type extensions.
// - eval_emu_var() is a stub (empty body in Python).
//
// Python class tree:
//   BinaryEmulator(MemoryManager, ABC)
//     -> WindowsEmulator(BinaryEmulator)            [winemu.h]
//       -> Win32Emulator(WindowsEmulator)           [win32.h]
//         -> WinKernelEmulator(Win32Emulator, IoManager) [kernel.h]
//
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

#include "memmgr.h"
#include "profiler.h"
#include "common.h"
#include "config.h"
#include "winenv/arch.h"
#include "engines/unicorn_eng.h"
#include "version.h"
#include "errors.h"

// Hook type aliases (match Python binemu.py:24-26)
// WILDCARD_FLAG = bool
// API_LEVEL  = tuple[dict[str, list[ApiHook]], WILDCARD_FLAG]
// MODULE_LEVEL = tuple[dict[str, API_LEVEL], WILDCARD_FLAG]

using ApiLevel = std::pair<std::map<std::string, std::vector<ApiHook>>, bool>;
using ModuleLevel = std::pair<std::map<std::string, ApiLevel>, bool>;

// Generic emulator class for binary code
class BinaryEmulator : public MemoryManager {
private:
    uint64_t inst_count;
    uint64_t curr_instr_size;
    void* disasm_eng;
    bool builtin_hooks_set;
protected:
    uint64_t page_size;
    uint64_t stack_base;
    EmuEngine* emu_eng;
    std::vector<void*> maps;
    ModuleLevel api_hooks_{};
    std::map<int, std::vector<Hook*>> hooks_;
    
    std::shared_ptr<Profiler> profiler;
    double runtime;
    std::string emu_version;
    
    // -- Python member mapping --
    // self.arch -> arch_        self.ptr_size -> ptr_size_
    // self.emu_eng -> emu_eng   self.profiler -> profiler
    // self.hooks -> api_hooks_ + hooks_       self.runtime -> runtime
    // self.osversion -> osversion             self.env -> env
    // self.domain -> domain     self.hostname -> hostname
    // self.modules -> modules (subclass)      self.input -> input (subclass)
    // Config fields
    std::map<std::string, std::string> osversion;
protected:
    const speakeasy::SpeakeasyConfig& config;
    std::map<std::string, std::string> env;
    std::map<std::string, std::string> user_config;
private:
    std::string domain;
    std::string hostname;
    std::vector<std::string> symlinks;
    //std::map<std::string, std::string> config_modules;
    //std::vector<std::string> config_system_modules;
    //std::vector<std::string> config_processes;
    //std::vector<std::string> config_user_modules;
    //std::map<std::string, std::string> config_analysis;
    int max_instructions;
    int timeout;
    int max_api_count;
    int arch_;
    int ptr_size_;
    std::map<std::string, std::string> exceptions;
    std::vector<std::string> drive_config;
    std::vector <std::shared_ptr<speakeasy::Module>> modules;
    std::map<std::string, std::string> filesystem_config;
    bool keep_memory_on_free;
    std::map<std::string, std::string> network_config;
    std::vector<std::string> network_adapters;
    std::string command_line;

public:
    // Constructor
    BinaryEmulator(const speakeasy::SpeakeasyConfig& cfg);
    
    // Logging methods
    // Python binemu.py:33-34 doc: "Base class for emulating binaries\n\nSubclasses must define the following attributes:\n    arch: Architecture constant (e.g., ARCH_X86, ARCH_AMD64)\n    modules: List of loaded modules\n    input: Input metadata dictionary (or None)"
    void log_info(const std::string& msg);
    void log_error(const std::string& msg);
    void log_exception(const std::string& msg);
    
    // Python binemu.py:80-84 doc: "Get the current event profiler object (if any)"
    std::shared_ptr<Profiler> get_profiler();
    // Python binemu.py:86-92 doc: "Get the emulation report for all runs that were executed"
    speakeasy::Report get_report();
    // Python binemu.py:94-100 doc: "Get the emulation report for all runs that were executed formatted as a JSON string"
    std::string get_json_report_string();
    
    // Config methods
    // Python binemu.py:102-116 doc: "Parse the config to be used for emulation"
    void _parse_config(const speakeasy::SpeakeasyConfig& cfg);
    // Python binemu.py:117-121 doc: "Get the version of the emulator"
    std::string get_emu_version();
    // See Python binemu.py:123-135 doc
    std::map<std::string, std::string> get_os_version();
    // Python binemu.py:123-135 doc: "Get the human readable OS version string"
    std::string get_osver_string();
    std::string get_domain();
    std::string get_hostname();
    std::map<std::string, std::string> get_user();
    
    // Python binemu.py:137-141 doc: "Get the size (in the emulation space) of the supplied object"
    template<typename T>
    size_t objsize(T obj);
    // Python binemu.py:143-147 doc: "Get the bytes represented in the emulation space of the supplied object"
    template<typename T>
    std::vector<uint8_t> get_bytes(T obj);
    
    // Python binemu.py:149-156 doc: "Stop emulation completely"
    void stop();
    // Python binemu.py:158-172 doc: "Begin emulation"
    void start(uint64_t addr, size_t size);
    
    // Network config methods
    std::map<std::string, std::string> get_network_config();
    std::vector<std::string> get_network_adapters();
    std::map<std::string, std::string> get_filesystem_config();
    std::vector<std::string> get_drive_config();
    
    // Python binemu.py:174-185 doc: "Write a value to an emulated cpu register"
    void reg_write(const std::string& reg, uint64_t val);
    // Python binemu.py:174-185 doc: "Write a value to an emulated cpu register"
    void reg_write(int reg, uint64_t val);
    // Python binemu.py:187-198 doc: "Read a value from an emulated cpu register"
    uint64_t reg_read(const std::string& reg);
    // Python binemu.py:187-198 doc: "Read a value from an emulated cpu register"
    uint64_t reg_read(int reg);
    
    // Python binemu.py:200-213 doc: "Set instruction level hooks"
    void set_hooks();
    // Python binemu.py:215-230 doc: "Disassemble bytes using capstone"
    std::tuple<std::string, std::string, std::string> _cs_disasm(const std::vector<uint8_t>& mem, 
                                                                 uint64_t addr, bool fast = true);
    // Python binemu.py:232-236 doc: "Disassemble bytes at a specified address"
    std::tuple<std::string, std::string, std::string> disasm(const std::vector<uint8_t>& mem, 
                                                             uint64_t addr, bool fast = true);
    // Python binemu.py:238-279 doc: "Get the current state of registers from the emulator"
    std::map<std::string, std::string> get_register_state();
    // Python binemu.py:281-285 doc: "Get the disassembly from an address"
    std::tuple<std::string, std::string, std::string> get_disasm(uint64_t addr, size_t size, bool fast = true);
    
    // Python binemu.py:287-325 doc: "Set the arguments before an emulated function call"
    void set_func_args(uint64_t stack_addr, uint64_t ret_addr, 
                       const std::vector<uint64_t>& args, bool home_space = true);
    // Python binemu.py:327-381 doc: "Get the arguments for a function given the supplied calling convention"
    std::vector<uint64_t> get_func_argv(int callconv, int argc);
    // Python binemu.py:383-418 doc: "Set the emulation state after a call has completed"
    void do_call_return(int argc, uint64_t ret_addr = 0, uint64_t ret_value = 0, int conv = 0);
    
    // Stack methods
    // Python binemu.py:420-430 doc: "Get the return address from the stack"
    uint64_t get_ret_address();
    // Python binemu.py:432-438 doc: "Set the return address on the stack"
    void set_ret_address(uint64_t addr);
    // Python binemu.py:440-450 doc: "Put a value on the stack and adjust the stack pointer"
    uint64_t push_stack(uint64_t val);
    // Python binemu.py:452-462 doc: "Get value from the stack and adjust the stack pointer"
    uint64_t pop_stack();
    // Python binemu.py:464-472 doc: "Get the current address of the stack pointer"
    uint64_t get_stack_ptr();
    // Python binemu.py:474-481 doc: "Set the current address of the stack pointer"
    void set_stack_ptr(uint64_t addr);
    // Python binemu.py:483-498 doc: "Get the stack and format it for display"
    std::vector<std::tuple<uint64_t, uint64_t, std::string>> format_stack(int num_ptrs);
    // Python binemu.py:500-515 doc: "Debug function used to print the current stack state"
    void print_stack(int num_ptrs);
    // Python binemu.py:517-540 doc: "Get the current stack state"
    std::vector<std::string> get_stack_trace(int num_ptrs = 16);
    
    // Python binemu.py:542-552 doc: "Get the value of the current program counter"
    uint64_t get_pc();
    // Python binemu.py:554-563 doc: "Set the value of the current program counter"
    void set_pc(uint64_t addr);
    // Python binemu.py:565-575 doc: "Get the current value in the return register"
    uint64_t get_return_val();
    
    // Python binemu.py:577-593 doc: "Reset stack to the supplied base address"
    std::tuple<uint64_t, uint64_t> reset_stack(uint64_t base);
    // Python binemu.py:595-610 doc: "Allocate memory to use for the program stack"
    std::tuple<uint64_t, uint64_t> alloc_stack(size_t size);
    // Python binemu.py:612-630 doc: "Adjust the stack for arguments that were supplied"
    void clean_stack_args(int argc);
    
    // Python binemu.py:632-636 doc: "Get the current emulated architecture"
    int get_arch();
    // Python binemu.py:638-646 doc: "Get the name of current emulated architecture"
    std::string get_arch_name();
    
    // Python binemu.py:657-685 doc: "Read a string from emulated memory"
    std::string read_mem_string(uint64_t address, int width = 1, int max_chars = 0);
    // Python binemu.py:687-698 doc: "Get the length of a string from emulated memory"
    int mem_string_len(uint64_t address, int width = 1);
    // Python binemu.py:700-717 doc: "Get all ansi strings from a supplied memory blob"
    std::vector<std::tuple<int, std::string>> get_ansi_strings(const std::vector<uint8_t>& data, int min_len = 4);
    // Python binemu.py:719-736 doc: "Get all unicode strings from a supplied memory blob"
    std::vector<std::tuple<int, std::string>> get_unicode_strings(const std::vector<uint8_t>& data, int min_len = 4);
    // Python binemu.py:738-744 doc: "Copy bytes from one emulated address to another"
    size_t mem_copy(uint64_t dst, uint64_t src, size_t n);
    // Python binemu.py:746-762 doc: "Write string data to an emulated memory address. Appends terminating zero byte if not present."
    void write_mem_string(const std::string& string, uint64_t address, int width = 1);
    // Python binemu.py:764-766 doc: "Read a pointer-sized value from memory"
    uint64_t read_ptr(uint64_t address);
    // Python binemu.py:768-769 doc: "Write a pointer-sized value to memory"
    void write_ptr(uint64_t address, uint64_t val);
    // Python binemu.py:771-775 doc: "Get the pointer size of the current emulation state"
    int get_ptr_size();
    // Python binemu.py:777-798 doc: "Get ansi and unicode strings from emulated memory"
    std::tuple<std::vector<std::tuple<int, std::string>>, std::vector<std::tuple<int, std::string>>> get_mem_strings();
    // Python binemu.py:800-809 doc: "Set the current pointer size used in the emulator"
    void set_ptr_size(int arch);
    
    // Python binemu.py:811-820 doc: "If the supplied address belongs to a module, return it"
    std::shared_ptr<speakeasy::Module> get_module_from_addr(uint64_t addr);
    
    // Hook management methods (Python:822-1147)
    // Python binemu.py:822-852 doc: "If an API hook has been set, return it here"
    std::vector<ApiHook> get_api_hooks(const std::string& mod_name, const std::string& func_name);
    // Python binemu.py:854-895 doc: "Add an API level hook (e.g. kernel32.CreateFile) here"
    ApiHook add_api_hook(std::function<void()> cb, const std::string& module = "", 
                         const std::string& api_name = "", int argc = 0, 
                         void* call_conv = nullptr, BinaryEmulator* emu = nullptr);
    // Python binemu.py:897-919 doc: "Add a hook that will fire for every CPU instruction"
    CodeHook add_code_hook(std::function<void()> cb, uint64_t begin = 1, uint64_t end = 0, 
                           std::map<std::string, std::string> ctx = {}, BinaryEmulator* emu = nullptr);
    // Python binemu.py:1042-1054 doc: "This handler will dispatch other invalid memory hooks"
    void _dynamic_code_cb(BinaryEmulator* emu, uint64_t addr, size_t size, 
                          std::map<std::string, std::string> ctx = {});
    // Python binemu.py:931-946 doc: "Set the top level dispatch hook for dynamic code execution"
    void _set_dyn_code_hook(uint64_t addr, size_t size, std::map<std::string, std::string> ctx = {});
    // Python binemu.py:948-968 doc: "Add a hook that will fire when dynamically generated/copied code is executed"
    DynCodeHook add_dyn_code_hook(std::function<void()> cb, std::vector<std::string> ctx = {}, 
                                  BinaryEmulator* emu = nullptr);
    // Python binemu.py:970-992 doc: "Add a hook that will fire for memory reads"
    ReadMemHook add_mem_read_hook(std::function<void()> cb, uint64_t begin = 1, uint64_t end = 0, 
                                  BinaryEmulator* emu = nullptr);
    // Python binemu.py:994-1016 doc: "Add a hook that will fire for memory writes"
    WriteMemHook add_mem_write_hook(std::function<void()> cb, uint64_t begin = 1, uint64_t end = 0, 
                                    BinaryEmulator* emu = nullptr);
    // Python binemu.py:1018-1040 doc: "Add a hook that will fire for memory maps"
    MapMemHook add_mem_map_hook(std::function<void()> cb, uint64_t begin = 1, uint64_t end = 0, 
                                BinaryEmulator* emu = nullptr);
    bool _hook_mem_invalid_dispatch(BinaryEmulator* emu, int access, uint64_t address, 
                                    size_t size, uint64_t value, std::map<std::string, std::string> ctx);
    // Python binemu.py:1056-1076 doc: "Add a hook that will fire for invalid memory access"
    InvalidMemHook add_mem_invalid_hook(std::function<void()> cb, BinaryEmulator* emu = nullptr);
    // Python binemu.py:1078-1100 doc: "Add a hook that will fire for software interrupts"
    InterruptHook add_interrupt_hook(std::function<void()> cb, std::vector<std::string> ctx = {}, 
                                     BinaryEmulator* emu = nullptr);
    // Python binemu.py:1102-1124 doc: "Add a hook that will fire for IN, SYSCALL, or SYSENTER instructions"
    InstructionHook add_instruction_hook(std::function<void()> cb, uint64_t begin = 1, uint64_t end = 0, 
                                         std::vector<std::string> ctx = {}, BinaryEmulator* emu = nullptr, 
                                         void* insn = nullptr);
    // Python binemu.py:1126-1147 doc: "Add a hook that will fire for invalid instruction attempts"
    InvalidInstructionHook add_invalid_instruction_hook(std::function<void()> cb, 
                                                        std::vector<std::string> ctx = {}, 
                                                        BinaryEmulator* emu = nullptr);
    
    void _fire_dyn_code_hooks(uint64_t addr);
    
    // Python binemu.py:648-655 doc: "Used to expand variables supplied in the emulator config file"
    void eval_emu_var();
    
    // Virtual methods to be implemented by subclasses
    virtual void on_emu_complete() = 0;
    virtual void _set_emu_hooks() = 0;
    virtual std::shared_ptr<Run> get_current_run() = 0;
};

#endif // BINEMU_H