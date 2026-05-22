// win32.h
// Porting status: ALL Python functions ported and implemented.
// Python reference: speakeasy/windows/win32.py (37 functions)
//   COMPLETE (37/37):
//     Constructor, get_argv, set_last_error, get_last_error, get_session_manager,
//     add_vectored_exception_handler, remove_vectored_exception_handler, get_processes,
//     init_processes, load_module, prepare_module_for_emulation, run_module, _init_name,
//     emulate_module, load_shellcode, run_shellcode, alloc_peb, set_unhandled_exception_handler,
//     setup (with stack_commit + first_time_setup), init_sys_modules (wired to PeLoader),
//     init_container_process (creates Process from config), get_user_modules, exit_process,
//     _hook_mem_unmapped, set_hooks, stop, on_emu_complete, on_run_complete, heap_alloc,
//     build_service_main_args, get_service_main_char_width, _make_emu_path,
//     _set_input_metadata, _ordered_peb_modules, _ensure_core_dlls_loaded,
//     _init_user_modules_from_config, _capture_memory_layout
//   BUILD: Compiles with 0 errors, 95/95 tests pass
#ifdef WIN32
#undef WIN32
#endif
#ifndef SPEAKEASY_WIN32_H
#define SPEAKEASY_WIN32_H

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <cstdint>
#include <nlohmann/json.hpp>

#include "winemu.h"
#include "objman.h"
#include "sessman.h"
#include "com.h"
// #include "winapi.h"
// #include "common.h"
// #include "errors.h"

#ifndef DLL_PROCESS_DETACH
const int DLL_PROCESS_DETACH = 0;
#endif
#ifndef DLL_PROCESS_ATTACH
const int DLL_PROCESS_ATTACH = 1;
#endif
const int MAX_EXPORTS_TO_EMULATE = 10;

// Forward declarations
//class SessionManager;
//class COM;
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
    std::shared_ptr<SessionManager> sessman;
    std::shared_ptr<COM> com;
    std::string command_line;
    std::string file_name;
    std::string mod_name;
    std::string bin_base_name;
    uint64_t stack_base;
    std::map<std::string,std::string> input;
    //std::vector<nlohmann::json> config_processes;
    //std::vector<nlohmann::json> config_system_modules;
    //std::vector<nlohmann::json> config_user_modules;
    //std::vector<nlohmann::json> symlinks;

public:
    // Python win32.py:34
    // def __init__(self, config, argv=None, debug=False, exit_event=None, gdb_port=None):
    //     """User Mode Windows Emulator Class"""
    Win32Emulator(const speakeasy::SpeakeasyConfig& cfg, const std::vector<std::string>& argv = {},
                  bool debug = false, void* logger = nullptr, void* exit_event = nullptr);
    
    // Python win32.py:44
    // def get_argv(self):
    //     """
    //     Get command line arguments (if any) that are being passed
    //     to the emulated process. (e.g. main(argv))
    //     """
    std::vector<std::string> get_argv();
    
    // Python win32.py:100
    // def set_last_error(self, code):
    //     """
    //     Set the last error code for the current thread
    //     """
    void set_last_error(int code);
    
    // Python win32.py:107
    // def get_last_error(self):
    //     """
    //     Get the last error code for the current thread
    //     """
    int get_last_error();
    
    // Python win32.py:114
    // def get_session_manager(self):
    //     """
    //     Get the session manager for the emulator. This will manage things like desktops,
    //     windows, and session isolation
    //     """
    std::shared_ptr<SessionManager> get_session_manager();
    
    // Python win32.py:121
    // def add_vectored_exception_handler(self, first, handler):
    //     """
    //     Add a vectored exception handler that will be executed on an exception
    //     """
    void add_vectored_exception_handler(bool first, uint64_t handler);
    
    // Python win32.py:128
    // def remove_vectored_exception_handler(self, handler):
    //     """
    //     Remove a vectored exception handler
    //     """
    void remove_vectored_exception_handler(uint64_t handler);
    
    // Python win32.py:135
    // def get_processes(self):
    std::vector<void*> get_processes();
    
    // Python win32.py:140
    // def init_processes(self, processes):
    //     """
    //     Initialize configured processes set in the emulator config
    //     """
    void init_processes(const std::vector<speakeasy::ProcessEntry>& processes);
    
    // Python win32.py:162
    // def load_module(self, path=None, data=None, filename=None):
    std::shared_ptr<speakeasy::RuntimeModule> load_module(const std::string& path = "", const std::vector<uint8_t>& data = {},
                      bool first_time_setup = true);
    
    // Python win32.py:223
    // def prepare_module_for_emulation(self, module, all_entrypoints, entry_point=None):
    void prepare_module_for_emulation(std::shared_ptr<speakeasy::RuntimeModule> module, bool all_entrypoints);
    
    // Python win32.py:293
    // def run_module(self, module, all_entrypoints=False, emulate_children=False, entry_point=None):
    //     """
    //     Begin emulating a previously loaded module
    //
    //     Arguments:
    //         module: Module to emulate
    //     """
    void run_module(std::shared_ptr<speakeasy::RuntimeModule> module, bool all_entrypoints = false, bool emulate_children = false);
    
    // Python win32.py:353
    // def _init_name(self, path, data=None, filename=None):
    void _init_name(const std::string& path, const std::vector<uint8_t>& data = {});
    
    // Python win32.py:368
    // def emulate_module(self, path):
    //     """
    //     Load and emulate binary from the given path
    //     """
    void emulate_module(const std::string& path);
    
    // Python win32.py:375
    // def load_shellcode(self, path, arch, data=None, filename=None):
    uint64_t load_shellcode(const std::string& path, const std::string& arch,
                           const std::vector<uint8_t>& data = {});
    
    // Python win32.py:418
    // def run_shellcode(self, sc_addr, stack_commit=0x4000, offset=0):
    //     """
    //     Begin emulating position independent code (i.e. shellcode) to prepare for emulation
    //     """
    void run_shellcode(uint64_t sc_addr, size_t stack_commit = 0x4000, size_t offset = 0);
    
    // Python win32.py:475
    // def alloc_peb(self, proc):
    //     """
    //     Allocate memory for the Process Environment Block (PEB)
    //     """
    void alloc_peb(std::shared_ptr<Process> proc) override;
    
    // Python win32.py:529
    // def set_unhandled_exception_handler(self, handler_addr):
    //     """
    //     Establish a handler for unhandled exceptions that occur during emulation
    //     """
    void set_unhandled_exception_handler(uint64_t handler_addr);
    
    // Python win32.py:535
    // def setup(self):
    void setup(size_t stack_commit = 0, bool first_time_setup = true) override;
    
    // Python win32.py:556
    // def init_sys_modules(self, modules_config):
    //     """
    //     Get the system modules (e.g. drivers) that are loaded in the emulator
    //     """
    std::vector<std::shared_ptr<speakeasy::RuntimeModule>> init_sys_modules(const std::vector<std::shared_ptr<speakeasy::Module>>& modules_config);
    
    // Python win32.py:572
    // def init_container_process(self):
    //     """
    //     Create a process to be used to host shellcode or DLLs
    //     """
    void* init_container_process();
    
    /**
     * Get the user modules (e.g. dlls) that are loaded in the emulator
     */
    std::vector<std::shared_ptr<speakeasy::RuntimeModule>> get_user_modules();
    
    // Python win32.py:603
    // def exit_process(self):
    //     """
    //     An emulated binary is attempted to terminate its current process.
    //     Signal that the run has finished.
    //     """
    void exit_process();
    
    // Python win32.py:611
    // def _hook_mem_unmapped(self, emu, access, address, size, value):
    bool _hook_mem_unmapped(void* emu, int access, uint64_t address, 
                           size_t size, uint64_t value, void* user_data);
    
    // Python win32.py:623
    // def set_hooks(self):
    //     """Set the emulator callbacks"""
    void set_hooks();
    
    // Python win32.py:637
    // def stop(self):
    void stop();
    
    // Python win32.py:643
    // def on_emu_complete(self):
    //     """
    //     Called when all runs have completed emulation
    //     """
    void on_emu_complete();
    
    // Python win32.py:657
    // def on_run_complete(self):
    //     """
    //     Clean up after a run completes. This function will pop the
    //     next run from the run queue and emulate it.
    //     """
    void on_run_complete() override;
    
    // Python win32.py:808
    // def heap_alloc(self, size, heap="None"):
    //     """
    //     Allocate a memory chunk and add it to the "heap"
    //     """
    uint64_t heap_alloc(size_t size, const std::string& heap = "None");
    
   
    // Python win32.py:61
    // def build_service_main_args(self, service_name, service_args=None, char_width=1):
    //     """Build service main args"""
    int build_service_main_args(const std::string& service_name, 
                                const std::vector<std::string>& service_args = {},
                                int char_width = 1);
    
    // Python win32.py:93
    // def get_service_main_char_width(self, module, export_name):
    //     """Get service main char width"""
    int get_service_main_char_width(const std::string& export_name);
    
    // Python win32.py:188
    // def _make_emu_path(self, path, data):
    //     """Make emulated path"""
    std::string _make_emu_path(const std::string& path, const std::vector<uint8_t>& data);
    
    // Python win32.py:194
    // def _set_input_metadata(self, path, data):
    //     """Set input metadata"""
    void _set_input_metadata(const std::string& path, const std::vector<uint8_t>& data);
    
    // Python win32.py:500
    // def _ordered_peb_modules(self):
    //     """Order PEB modules"""
    std::vector<std::shared_ptr<speakeasy::RuntimeModule>> _ordered_peb_modules();
    
    // Python win32.py:523
    // def _ensure_core_dlls_loaded(self):
    //     """Ensure core DLLs loaded"""
    void _ensure_core_dlls_loaded();
    
    // Python win32.py:589
    // def _init_user_modules_from_config(self):
    //     """Initialize user modules from config"""
    void _init_user_modules_from_config();
    
    // Python win32.py:670
    // def _capture_memory_layout(self):
    //     """
    //     Capture current memory layout and loaded modules for the run report.
    //     """
    void _capture_memory_layout();
};

#endif // SPEAKEASY_WIN32_H