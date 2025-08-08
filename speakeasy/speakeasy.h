// speakeasy.h
#ifndef SPEAKEASY_H
#define SPEAKEASY_H

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <functional>
#include <cstdint>
#include <nlohmann/json.hpp>

// TODO: Replace Python imports with C++ equivalents
// #include "pefile.h"
// #include "win32.h"
// #include "winkernel.h"
// #include "errors.h"

// Forward declarations
class PeFile;
class Win32Emulator;
class WinKernelEmulator;
class Emulator;

/**
 * Wrapper class for invoking the speakeasy emulators
 */
class Speakeasy {
private:
    void* logger;
    nlohmann::json config;
    Emulator* emu;
    std::vector<std::tuple<std::function<void()>, std::string, std::string, int, std::string>> api_hooks;
    std::vector<std::tuple<std::function<void()>, uint64_t, uint64_t, std::map<std::string, std::string>>> code_hooks;
    std::vector<std::tuple<std::function<void()>, std::map<std::string, std::string>>> dyn_code_hooks;
    std::vector<std::tuple<std::function<void()>, std::vector<void*>>> invalid_insn_hooks;
    std::vector<std::tuple<std::function<void()>, uint64_t, uint64_t>> mem_read_hooks;
    std::vector<std::string> argv;
    void* exit_event;
    bool debug;
    std::vector<std::string> loaded_bins;
    std::vector<std::tuple<std::function<void()>, uint64_t, uint64_t>> mem_write_hooks;
    std::vector<std::tuple<std::function<void()>>> mem_invalid_hooks;
    std::vector<std::tuple<std::function<void()>, std::map<std::string, std::string>>> interrupt_hooks;
    std::vector<std::tuple<std::function<void()>, uint64_t, uint64_t>> mem_map_hooks;

    /**
     * Init the emulator config
     */
    void _init_config(const nlohmann::json& config = nlohmann::json());
    
    /**
     * Based on the PE metadata, use the appropriate emulator
     */
    void _init_emulator(const std::string& path = "", const std::vector<uint8_t>& data = {}, bool is_raw_code = false);
    
    /**
     * Lazily add hooks if users added them early before emulator engine was instantiated
     */
    void _init_hooks();

public:
    /**
     * Constructor
     */
    Speakeasy(const nlohmann::json& config = nlohmann::json(), void* logger = nullptr, 
              const std::vector<std::string>& argv = {}, bool debug = false, void* exit_event = nullptr);
    
    /**
     * Destructor
     */
    ~Speakeasy();
    
    /**
     * Get the disassembly from an address
     */
    std::tuple<std::string, std::string, std::string> disasm(uint64_t addr, size_t size, bool fast = true);
    
    /**
     * Test data to see if it looks like a PE
     */
    bool is_pe(const std::vector<uint8_t>& data);
    
    /**
     * Load a module into the speakeasy emulator
     */
    PeFile* load_module(const std::string& path = "", const std::vector<uint8_t>& data = {});
    
    /**
     * Run a previously loaded module through the configured emulator
     */
    void run_module(PeFile* module, bool all_entrypoints = false, bool emulate_children = false);
    
    /**
     * Load a shellcode blob into emulation space
     */
    uint64_t load_shellcode(const std::string& fpath, const std::string& arch, 
                           const std::vector<uint8_t>& data = {});
    
    /**
     * Run a previously loaded shellcode blob by address
     */
    void run_shellcode(uint64_t sc_addr, size_t stack_commit = 0x4000, size_t offset = 0);
    
    /**
     * Get the emulation report from the emulator
     */
    nlohmann::json get_report();
    
    /**
     * Get the emulation report from the emulator formatted as a JSON string
     */
    std::string get_json_report();
    
    /**
     * Set a callback to fire when a specified API is called during emulation
     */
    void* add_api_hook(std::function<void()> cb, const std::string& module = "", 
                       const std::string& api_name = "", int argc = 0, 
                       const std::string& call_conv = "");
    
    /**
     * Resume emulating at the specified address
     */
    void resume(uint64_t addr, int count = -1);
    
    /**
     * Stops emulation
     */
    void stop();
    
    /**
     * Closes the emulation instance
     */
    void shutdown();
    
    /**
     * Start emulating at the specified address
     */
    void call(uint64_t addr, const std::vector<void*>& params = {});
    
    /**
     * Set a callback to fire for every CPU instruction that is emulated
     */
    void* add_code_hook(std::function<void()> cb, uint64_t begin = 1, uint64_t end = 0, 
                        const std::map<std::string, std::string>& ctx = {});
    
    /**
     * Set a callback to fire when dynamically generated/copied code is executed
     */
    void* add_dyn_code_hook(std::function<void()> cb, 
                           const std::map<std::string, std::string>& ctx = {});
    
    /**
     * Set a callback to fire when a memory address is read from
     */
    void* add_mem_read_hook(std::function<void()> cb, uint64_t begin = 1, uint64_t end = 0);
    
    /**
     * Set a callback to fire when a memory address is written to
     */
    void* add_mem_write_hook(std::function<void()> cb, uint64_t begin = 1, uint64_t end = 0);
    
    /**
     * Set a callback to fire when an IN instruction executes
     */
    void* add_IN_instruction_hook(std::function<void()> cb, uint64_t begin = 1, uint64_t end = 0);
    
    /**
     * Set a callback to fire when a SYSCALL / SYSENTER instruction executes
     */
    void* add_SYSCALL_instruction_hook(std::function<void()> cb, uint64_t begin = 1, uint64_t end = 0);
    
    /**
     * Set a callback to fire when an invalid instruction is attempted to be executed
     */
    void* add_invalid_instruction_hook(std::function<void()> cb, const std::vector<void*>& ctx = {});
    
    /**
     * Get a callback for when a memory access violation occurs
     */
    void* add_mem_invalid_hook(std::function<void()> cb);
    
    /**
     * Get a callback for software interrupts
     */
    void* add_interrupt_hook(std::function<void()> cb, 
                            const std::map<std::string, std::string>& ctx = {});
    
    /**
     * Get registry key by path or handle
     */
    void* get_registry_key(int handle = 0, const std::string& path = "");
    
    /**
     * Get the address mapping object associated with the specified address
     */
    void* get_address_map(uint64_t addr);
    
    /**
     * Get the address ranges of loaded user modules
     */
    std::vector<void*> get_user_modules();
    
    /**
     * Get the address ranges of loaded system modules
     */
    std::vector<void*> get_sys_modules();
    
    /**
     * Allocate a block of memory in the emulation space
     */
    uint64_t mem_alloc(size_t size, uint64_t base = 0, const std::string& tag = "speakeasy.None");
    
    /**
     * Free a block of memory in the emulation space
     */
    void mem_free(uint64_t base);
    
    /**
     * Read bytes from a memory address
     */
    std::vector<uint8_t> mem_read(uint64_t addr, size_t size);
    
    /**
     * Write bytes to a memory address
     */
    void mem_write(uint64_t addr, const std::vector<uint8_t>& data);
    
    /**
     * Cast an address as an object for easy access
     */
    void* mem_cast(void* obj, uint64_t addr);
    
    /**
     * Read value from a register
     */
    uint64_t reg_read(const std::string& reg);
    
    /**
     * Returns the imports dynamically resolved at runtime
     */
    std::vector<std::tuple<uint64_t, std::string, std::string>> get_dyn_imports();
    
    /**
     * Write value to a register
     */
    void reg_write(const std::string& reg, uint64_t val);
    
    /**
     * Get files that were written to disk during emulation
     */
    std::vector<void*> get_dropped_files();
    
    /**
     * Creates a file archive package
     */
    std::vector<uint8_t> create_file_archive();
    
    /**
     * Get all memory maps in the emulation space
     */
    std::vector<void*> get_mem_maps();
    
    /**
     * Returns all memory contents along with context information
     */
    // TODO: Implement generator equivalent
    std::vector<std::tuple<std::string, uint64_t, size_t, bool, void*, std::vector<uint8_t>>> get_memory_dumps();
    
    /**
     * Read a string from emulated memory
     */
    std::string read_mem_string(uint64_t address, int width = 1, size_t max_chars = 0);
    
    /**
     * Returns a dictionary of symbol information
     */
    std::map<uint64_t, std::tuple<std::string, std::string>> get_symbols();
    
    /**
     * Returns the value stored at the top of the stack
     */
    uint64_t get_ret_address();
    
    /**
     * Sets the return address on the stack
     */
    void set_ret_address(uint64_t addr);
    
    /**
     * Put a value on the stack and adjust the stack pointer
     */
    void push_stack(uint64_t val);
    
    /**
     * Get value from the stack and adjust the stack pointer
     */
    uint64_t pop_stack();
    
    /**
     * Get the current address of the stack pointer
     */
    uint64_t get_stack_ptr();
    
    /**
     * Set the current address of the stack pointer
     */
    void set_stack_ptr(uint64_t addr);
    
    /**
     * Get the value of the current program counter
     */
    uint64_t get_pc();
    
    /**
     * Set the value of the current program counter
     */
    void set_pc(uint64_t addr);
    
    /**
     * Reset stack to the supplied base address
     */
    std::tuple<uint64_t, uint64_t> reset_stack(uint64_t base);
    
    /**
     * Get the base address of the stack
     */
    uint64_t get_stack_base();
    
    /**
     * Get the architecture of the emulator
     */
    int get_arch();
    
    /**
     * Get the size of a pointer
     */
    int get_ptr_size();
    
    /**
     * Get the state of all registers
     */
    std::map<std::string, uint64_t> get_all_registers();
    
    /**
     * If the supplied address is related to a known symbol, look it up here
     */
    std::string get_symbol_from_address(uint64_t address);
    
    /**
     * Was this address previously reserved or mapped?
     */
    bool is_address_valid(uint64_t address);
    
    /**
     * Set a callback to fire when a memory address is mapped
     */
    void* add_mem_map_hook(std::function<void()> cb, uint64_t begin = 1, uint64_t end = 0);
    
    /**
     * Creates a memory dump archive package of the emulated sample
     */
    std::vector<uint8_t> create_memdump_archive();
};

/**
 * Validates the given configuration objects against the built-in schemas
 */
void validate_config(const nlohmann::json& config);

#endif // SPEAKEASY_H