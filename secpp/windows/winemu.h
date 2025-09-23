// winemu.h
#ifndef WINEMU_H
#define WINEMU_H

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <functional>
#include <tuple>
#include <cstdint>
#include <exception>

// TODO: Need C++ equivalents for these Python imports
// #include "binemu.h"
// #include "profiler.h"
// #include "arch.h"
// #include "common.h"
// #include "windows/common.h"
// #include "windows/objman.h"
// #include "windows/regman.h"
// #include "windows/fileman.h"
// #include "windows/cryptman.h"
// #include "windows/netman.h"
// #include "windows/hammer.h"
// #include "windows/driveman.h"
// #include "winenv/defs/nt/ddk.h"
// #include "winenv/defs/windows/windows.h"
// #include "struct.h"
// #include "errors.h"

// When disassembling, a minimum instruction size needs to be supplied
// This number is arbitrary and just needs to be large enough to cover
// the size of the current disasm target
const int DISASM_SIZE = 0x20;

// Forward declarations
class BinaryEmulator;
class MemAccess;
class Run;
class EmuStruct;
class WindowsEmuError;

// Base class providing emulation of all Windows modules and shellcode.
// This class is meant to provide overlapping functionality for both
// user mode and kernel mode samples.
class WindowsEmulator : public BinaryEmulator {
protected:
    bool debug;
    int arch;
    std::vector<std::tuple<void*, std::tuple<uint64_t, size_t>, std::string>> modules;
    std::vector<void*> pic_buffers;
    std::shared_ptr<Run> curr_run;
    bool restart_curr_run;
    void* curr_mod;
    std::vector<std::shared_ptr<Run>> runs;
    std::map<std::string, std::string> input;
    void* exit_event;
    uint64_t page_size;
    int ptr_size;
    std::vector<void*> user_modules;
    int max_runs;

    std::vector<void*> sys_modules;
    std::map<uint64_t, std::tuple<std::string, std::string>> symbols;
    std::vector<std::string> ansi_strings;
    std::vector<std::string> unicode_strings;
    std::vector<std::tuple<uint64_t, size_t>> tmp_maps;
    std::vector<std::tuple<std::string, std::string, uint64_t>> impdata_queue;
    std::vector<std::shared_ptr<Run>> run_queue;
    std::vector<std::shared_ptr<Run>> suspended_runs;
    std::string cd;
    bool emu_hooks_set;
    void* api;
    void* curr_process;
    void* om; // Object manager
    std::vector<std::tuple<uint64_t, std::string, std::string>> dyn_imps;
    std::vector<std::tuple<uint64_t, std::string, std::string>> callbacks;
    std::vector<void*> mem_trace_hooks;
    bool kernel_mode;
    uint64_t virtual_mem_base;

    bool mem_tracing_enabled;
    void* tmp_code_hook;
    std::vector<void*> veh_handlers;

    bool run_complete;
    bool emu_complete;
    std::map<uint64_t, std::tuple<std::string, uint64_t>> global_data;
    std::vector<void*> processes;
    // Child processes created by calls to CreateProcess
    // by any module. This is separate from processes in order
    // to not mix up config processes with child processes
    std::vector<void*> child_processes;
    void* curr_thread;
    uint64_t curr_exception_code;
    uint64_t prev_pc;
    uint64_t unhandled_exception_filter;

    uint64_t fs_addr;
    uint64_t gs_addr;

    uint64_t return_hook;
    uint64_t exit_hook;
    
    // OS resource managers
    void* regman;
    void* fileman;
    void* netman;
    void* driveman;
    void* cryptman;
    void* hammer;
    
    void* wintypes;
    
    // Config fields
    std::map<std::string, std::string> registry_config;
    bool dispatch_handlers;
    bool do_strings;
    bool modules_always_exist;
    bool functions_always_exist;

public:
    // Constructor
    WindowsEmulator(const std::string& config, void* logger = nullptr, 
                    void* exit_event = nullptr, bool debug = false);
    
    // Virtual methods to be implemented by subclasses
    virtual void on_run_complete() = 0;
    virtual void on_emu_complete() = 0;
    
    // Config methods
    void _parse_config(const std::string& config);
    std::map<std::string, std::string> get_registry_config();
    
    // Hook methods
    void enable_code_hook();
    void disable_code_hook();
    bool _module_access_hook(void* emu, uint64_t addr, size_t size, void* ctx);
    void set_mem_tracing_hooks();
    
    // Memory methods
    EmuStruct* cast(EmuStruct* obj, const std::vector<uint8_t>& bytez);
    void _unset_emu_hooks();
    
    // File methods
    void* file_open(const std::string& path, bool create = false);
    void* pipe_open(const std::string& path, const std::string& mode, 
                    int num_instances, size_t out_size, size_t in_size);
    bool does_file_exist(const std::string& path);
    void* file_create_mapping(void* hfile, const std::string& name, 
                              size_t size, int prot);
    void* file_get(int handle);
    bool file_delete(const std::string& path);
    void* pipe_get(int handle);
    void* get_file_manager();
    
    // Network methods
    void* get_network_manager();
    
    // Crypto methods
    void* get_crypt_manager();
    
    // Drive methods
    void* get_drive_manager();
    
    // Registry methods
    void* reg_open_key(const std::string& path, bool create = false);
    std::vector<std::string> reg_get_subkeys(void* hkey);
    void* reg_get_key(int handle = 0, const std::string& path = "");
    void* reg_create_key(const std::string& path);
    
    // Emulation control methods
    void _set_emu_hooks();
    void add_run(std::shared_ptr<Run> run);
    std::shared_ptr<Run> _exec_next_run();
    void call(uint64_t addr, const std::vector<std::string>& params = {});
    std::shared_ptr<Run> _exec_run(std::shared_ptr<Run> run);
    EmuStruct* mem_cast(EmuStruct* obj, uint64_t addr);
    void mem_purge();
    void setup_user_shared_data();
    void resume(uint64_t addr, int count = -1);
    void start();
    
    // Run methods
    std::shared_ptr<Run> get_current_run();
    void* get_current_module();
    std::vector<void*> get_dropped_files();
    void set_hooks() override;
    
    // Process methods
    std::vector<void*> get_processes();
    void kill_process(void* proc);
    void* get_current_thread();
    void* get_current_process();
    void set_current_process(void* process);
    void set_current_thread(void* thread);
    
    // GDT methods
    std::tuple<uint64_t, uint64_t> _setup_gdt(int arch);
    
    // PEB/TEB methods
    void* init_peb(const std::vector<void*>& user_mods, void* proc = nullptr);
    void init_teb(void* thread, void* peb);
    void init_tls(void* thread);
    
    // PE methods
    void* load_pe(const std::string& path = "", const std::vector<uint8_t>& data = {}, 
                  uint64_t imp_id = 0); // TODO: Replace 0 with winemu.IMPORT_HOOK_ADDR
    uint64_t map_pe(void* pe, const std::string& mod_name = "none", 
                    const std::string& emu_path = "");
    
    // Module methods
    std::vector<void*> get_sys_modules();
    std::vector<void*> get_user_modules();
    void* get_mod_from_addr(uint64_t addr);
    std::string get_system_root();
    std::string get_windows_dir();
    std::string get_cd();
    void set_cd(const std::string& cd);
    std::map<std::string, std::string> get_env();
    void set_env(const std::string& var, const std::string& val);
    std::map<std::string, std::string> get_os_version();
    
    // Object methods
    void* get_object_from_addr(uint64_t addr);
    void* get_object_from_id(int id);
    void* get_object_from_name(const std::string& name);
    void* get_object_from_handle(int handle);
    int get_object_handle(void* obj);
    void add_object(void* obj);
    std::string search_path(const std::string& file_name);
    void* new_object(const std::string& otype);
    
    // Process/Thread methods
    void* create_process(const std::string& path = "", const std::string& cmdline = "", 
                         void* image = nullptr, bool child = false);
    std::tuple<int, void*> create_thread(uint64_t addr, void* ctx, void* proc_obj, 
                                         const std::string& thread_type = "thread", 
                                         bool is_suspended = false);
    bool resume_thread(void* thread);
    
    // Import methods
    std::vector<std::tuple<uint64_t, std::string, std::string>> get_dyn_imports();
    void* get_process_peb(void* process);
    uint64_t add_callback(const std::string& mod_name, const std::string& func_name);
    uint64_t get_proc(const std::string& mod_name, const std::string& func_name);
    uint64_t handle_import_data(const std::string& mod_name, const std::string& sym, 
                                uint64_t data_ptr = 0);
    
    // Error handling methods
    bool _handle_invalid_fetch(void* emu, uint64_t address, size_t size, 
                               uint64_t value, void* ctx);
    std::map<std::string, std::string> get_error_info(const std::string& desc, 
                                                      uint64_t address, 
                                                      const std::string& traceback = "");
    std::tuple<void*, std::tuple<std::string, std::string>> normalize_import_miss(
        const std::string& dll, const std::string& name);
    std::string read_unicode_string(uint64_t addr);
    void log_api(uint64_t pc, const std::string& imp_api, uint64_t rv, 
                 const std::vector<std::string>& argv);
    void handle_import_func(const std::string& dll, const std::string& name);
    
    // Memory hook methods
    bool _hook_mem_unmapped(void* emu, int access, uint64_t address, 
                            size_t size, uint64_t value, void* ctx);
    bool _handle_prot_write(void* emu, uint64_t address, size_t size, 
                            uint64_t value, void* ctx);
    void restart_run(std::shared_ptr<Run> run);
    std::string get_symbol_from_address(uint64_t address);
    bool _hook_mem_read(void* emu, int access, uint64_t address, 
                        size_t size, uint64_t value, void* ctx);
    bool _hook_mem_write(void* emu, int access, uint64_t address, 
                         size_t size, uint64_t value, void* ctx);
    bool _handle_invalid_read(void* emu, uint64_t address, size_t size, 
                              uint64_t value, void* ctx);
    bool _handle_prot_fetch(void* emu, uint64_t address, size_t size, 
                            uint64_t value, void* ctx);
    bool _handle_invalid_write(void* emu, uint64_t address, size_t size, 
                               uint64_t value, void* ctx);
    bool _hook_code(void* emu, uint64_t addr, size_t size, void* ctx);
    
    // Module methods
    std::string get_native_module_path(const std::string& mod_name = "");
    uint64_t load_library(const std::string& mod_name);
    void* generate_export_table(const std::string& modname);
    void* init_module(const std::map<std::string, std::string>& modconf = {}, 
                      const std::string& name = "none", 
                      const std::string& emu_path = "", 
                      uint64_t default_base = 0);
    std::vector<uint8_t> get_module_data_from_emu_file(const std::string& file_path);
    std::vector<void*> init_sys_modules(const std::vector<std::map<std::string, std::string>>& modules_config);
    std::vector<void*> init_user_modules(const std::vector<std::map<std::string, std::string>>& modules_config);
    bool map_decoy(void* decoy);
    
    // Context methods
    void* get_thread_context(void* thread = nullptr);
    void load_thread_context(void* ctx, void* thread = nullptr);
    
    // SEH methods
    uint64_t _get_exception_list();
    bool _dispatch_seh_x86(uint64_t except_code);
    std::tuple<uint64_t, uint64_t> get_reserved_ranges();
    void _continue_seh_x86();
    bool dispatch_seh(uint64_t except_code, uint64_t faulting_address = 0);
    void continue_seh();
    
    // Object creation methods
    std::tuple<int, void*> create_event(const std::string& name = "");
    int dec_ref(void* obj);
    std::tuple<int, void*> create_mutant(const std::string& name = "");
    
    // Interrupt methods
    bool _hook_interrupt(void* emu, int intnum, const std::vector<void*>& ctx = {});
    
    // Virtual methods from BinaryEmulator
    std::tuple<uint64_t, size_t> get_valid_ranges(size_t size, uint64_t addr = 0) override {
        // TODO: Implementation needed
        return std::make_tuple(0, 0);
    }
};

#endif // WINEMU_H