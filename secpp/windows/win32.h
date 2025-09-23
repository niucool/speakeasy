// win32.h
#ifndef WIN32_H
#define WIN32_H

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <cstdint>
#include <nlohmann/json.hpp>

// TODO: Replace Python imports with C++ equivalents
// #include "winemu.h"
// #include "objman.h"
// #include "sessman.h"
// #include "com.h"
// #include "winapi.h"
// #include "common.h"
// #include "errors.h"

const int DLL_PROCESS_DETACH = 0;
const int DLL_PROCESS_ATTACH = 1;
const int MAX_EXPORTS_TO_EMULATE = 10;

// Forward declarations
class WindowsEmulator;
class SessionManager;
class COM;
class WindowsApi;
class Process;
class Module;
class Run;

/**
 * User Mode Windows Emulator Class
 */
class Win32Emulator : public WindowsEmulator {
private:
    int last_error;
    uint64_t peb_addr;
    std::vector<std::tuple<uint64_t, size_t, std::string>> heap_allocs;
    std::vector<std::string> argv;
    SessionManager* sessman;
    COM* com;
    std::string command_line;
    std::string file_name;
    std::string mod_name;
    std::string bin_base_name;
    uint64_t stack_base;
    std::vector<nlohmann::json> config_processes;
    std::vector<nlohmann::json> config_system_modules;
    std::vector<nlohmann::json> config_user_modules;
    std::vector<nlohmann::json> symlinks;
    std::vector<void*> config;

public:
    /**
     * Constructor
     */
    Win32Emulator(const nlohmann::json& config, const std::vector<std::string>& argv = {},
                  bool debug = false, void* logger = nullptr, void* exit_event = nullptr);
    
    /**
     * Get command line arguments (if any) that are being passed
     * to the emulated process. (e.g. main(argv))
     */
    std::vector<std::string> get_argv();
    
    /**
     * Set the last error code for the current thread
     */
    void set_last_error(int code);
    
    /**
     * Get the last error code for the current thread
     */
    int get_last_error();
    
    /**
     * Get the session manager for the emulator. This will manage things like desktops,
     * windows, and session isolation
     */
    SessionManager* get_session_manager() override;
    
    /**
     * Add a vectored exception handler that will be executed on an exception
     */
    void add_vectored_exception_handler(bool first, uint64_t handler);
    
    /**
     * Remove a vectored exception handler
     */
    void remove_vectored_exception_handler(uint64_t handler);
    
    /**
     * Get processes
     */
    std::vector<void*> get_processes() override;
    
    /**
     * Initialize configured processes set in the emulator config
     */
    void init_processes(const std::vector<nlohmann::json>& processes);
    
    /**
     * Load a module into the emulator space from the specified path
     */
    void* load_module(const std::string& path = "", const std::vector<uint8_t>& data = {},
                      bool first_time_setup = true);
    
    /**
     * Prepare module for emulation
     */
    void prepare_module_for_emulation(void* module, bool all_entrypoints);
    
    /**
     * Begin emulating a previously loaded module
     */
    void run_module(void* module, bool all_entrypoints = false, bool emulate_children = false);
    
    /**
     * Initialize name
     */
    void _init_name(const std::string& path, const std::vector<uint8_t>& data = {});
    
    /**
     * Load and emulate binary from the given path
     */
    void emulate_module(const std::string& path);
    
    /**
     * Load position independent code (i.e. shellcode) to prepare for emulation
     */
    uint64_t load_shellcode(const std::string& path, const std::string& arch,
                           const std::vector<uint8_t>& data = {});
    
    /**
     * Begin emulating position independent code (i.e. shellcode) to prepare for emulation
     */
    void run_shellcode(uint64_t sc_addr, size_t stack_commit = 0x4000, size_t offset = 0);
    
    /**
     * Allocate memory for the Process Environment Block (PEB)
     */
    void* alloc_peb(void* proc);
    
    /**
     * Establish a handler for unhandled exceptions that occur during emulation
     */
    void set_unhandled_exception_handler(uint64_t handler_addr);
    
    /**
     * Setup the emulator
     */
    void setup(size_t stack_commit = 0, bool first_time_setup = true);
    
    /**
     * Get the system modules (e.g. drivers) that are loaded in the emulator
     */
    std::vector<void*> init_sys_modules(const std::vector<nlohmann::json>& modules_config);
    
    /**
     * Create a process to be used to host shellcode or DLLs
     */
    void* init_container_process();
    
    /**
     * Get the user modules (e.g. dlls) that are loaded in the emulator
     */
    std::vector<void*> get_user_modules() override;
    
    /**
     * An emulated binary is attempted to terminate its current process.
     * Signal that the run has finished.
     */
    void exit_process();
    
    /**
     * Hook for unmapped memory access
     */
    bool _hook_mem_unmapped(void* emu, int access, uint64_t address, 
                           size_t size, uint64_t value, void* user_data);
    
    /**
     * Set the emulator callbacks
     */
    void set_hooks() override;
    
    /**
     * Stop emulation
     */
    void stop() override;
    
    /**
     * Called when all runs have completed emulation
     */
    void on_emu_complete() override;
    
    /**
     * Clean up after a run completes. This function will pop the
     * next run from the run queue and emulate it.
     */
    bool on_run_complete() override;
    
    /**
     * Allocate a memory chunk and add it to the "heap"
     */
    uint64_t heap_alloc(size_t size, const std::string& heap = "None");
    
    /**
     * Get OS version string
     */
    std::string get_osver_string();
    
    /**
     * Get emulator version
     */
    std::string get_emu_version();
    
    /**
     * Allocate stack
     */
    std::tuple<uint64_t, uint64_t> alloc_stack(size_t size);
    
    /**
     * Set function arguments
     */
    void set_func_args(uint64_t stack_base, uint64_t return_hook, ...);
    
    /**
     * Get return value
     */
    uint64_t get_return_val();
    
    /**
     * Add run
     */
    void add_run(std::shared_ptr<Run> run);
    
    /**
     * Execute next run
     */
    bool _exec_next_run();
    
    /**
     * Start emulation
     */
    void start();
    
    /**
     * Get dropped files
     */
    std::vector<void*> get_dropped_files();
    
    /**
     * Get ANSI strings
     */
    std::vector<std::tuple<uint64_t, std::string>> get_ansi_strings(const std::vector<uint8_t>& data);
    
    /**
     * Get Unicode strings
     */
    std::vector<std::tuple<uint64_t, std::string>> get_unicode_strings(const std::vector<uint8_t>& data);
    
    /**
     * Get memory strings
     */
    std::tuple<std::vector<std::tuple<uint64_t, std::string>>, 
               std::vector<std::tuple<uint64_t, std::string>>> get_mem_strings();
    
    /**
     * Memory map
     */
    uint64_t mem_map(size_t size, uint64_t base = 0, const std::string& tag = "");
    
    /**
     * Memory write
     */
    void mem_write(uint64_t addr, const std::vector<uint8_t>& data);
    
    /**
     * Memory read
     */
    std::vector<uint8_t> mem_read(uint64_t addr, size_t size);
    
    /**
     * Get valid memory ranges
     */
    std::tuple<uint64_t, size_t> get_valid_ranges(size_t size, uint64_t addr = 0);
    
    /**
     * Memory map reserve
     */
    void mem_map_reserve(uint64_t addr);
    
    /**
     * Memory remap
     */
    int64_t mem_remap(uint64_t old_addr, uint64_t new_addr);
    
    /**
     * Get address map
     */
    void* get_address_map(uint64_t addr);
    
    /**
     * Initialize PEB
     */
    void* init_peb(const std::vector<void*>& user_mods);
    
    /**
     * Initialize TEB
     */
    void init_teb(void* thread, void* peb);
    
    /**
     * Initialize user modules
     */
    std::vector<void*> init_user_modules(const std::vector<nlohmann::json>& modules_config);
    
    /**
     * Add memory invalid hook
     */
    void add_mem_invalid_hook(std::function<bool(void*, int, uint64_t, size_t, uint64_t, void*)> cb);
    
    /**
     * Add interrupt hook
     */
    void add_interrupt_hook(std::function<bool(void*, int, const std::vector<void*>&)> cb);
    
    /**
     * Write pointer
     */
    void write_ptr(uint64_t addr, uint64_t value);
    
    /**
     * Register write
     */
    void reg_write(int reg, uint64_t value);
    
    /**
     * Get current process
     */
    void* get_current_process();
    
    /**
     * New object
     */
    void* new_object(const std::string& type);
    
    /**
     * Hook interrupt
     */
    bool _hook_interrupt(void* emu, int intnum, const std::vector<void*>& ctx);
    
    /**
     * Unset emulation hooks
     */
    void _unset_emu_hooks();
    
    /**
     * Unset hooks
     */
    void unset_hooks();
};

#endif // WIN32_H