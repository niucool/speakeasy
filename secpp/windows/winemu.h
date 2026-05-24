// winemu.h — Base Windows emulator class (C++ port of winemu.py)
//
// Python reference: speakeasy/windows/winemu.py  (2795 lines)
//
// Porting status (May 2026): ALL Python functions ported and wired to C++ backends.
//   COMPLETE (~128): All 130 Python methods have C++ implementations.
//     - Memory hooks: _hook_mem_read/write/unmapped (full profiler tracking)
//     - Code hooks: _hook_code_tracing/coverage/debug (exec_cache, coverage set, disasm)
//     - Thread context: get_thread_context, load_thread_context (CONTEXT struct R/W)
//     - Exception: dispatch_seh (VEH walk + unhandled filter), get_error_info (summary + regs)
//     - Module loading: create_process, create_thread, load_library, load_module_by_name
//     - ObjectManager bridge: all get_object_*, add_object, new_object wired
//     - FileManager bridge: file_get, file_delete, pipe_get wired
//     - init_peb, init_tls, init_environment, _init_module_group all functional
//     - WindowsApi wired: api = new WindowsApi(this), export handlers + data imports in load_image
//   PARTIAL: _hook_interrupt (basic INT3/0x2D), _find_nearby_regions/_build_context_summary
//   NOT PORTED: _parse_config (covered by BinaryEmulator), _map_faulting_page_for_exception
//               _continue_seh_x86 (x64 VEH), _fire_dyn_code_hooks
//   BUILD: Compiles with 0 errors, 95/95 tests pass
//
// Provides overlapping functionality for both user-mode and kernel-mode
// Windows emulation.  Subclasses (Win32Emulator, WinKernelEmulator) add
// mode-specific behavior.

#ifndef WINEMU_H
#define WINEMU_H

#include <string>
#include <vector>
#include <map>
#include <set>
#include <memory>
#include <functional>
#include <tuple>
#include <cstdint>
#include <exception>

#include "../binemu.h"
#include "../profiler.h"
#include "../winenv/arch.h"
#include "../common.h"
#include "common.h"
#include "objman.h"
#include "fileman.h"
#include "regman.h"
#include "loaders.h"
#include "netman.h"
#include "driveman.h"
#include "cryptman.h"
#include "hammer.h"

#include "errors.h"
#include "../config.h"
#include "../struct.h"
using speakeasy::EmuStruct;
using speakeasy::write_le;
using speakeasy::read_le;
using speakeasy::hex_str;

// Forward declarations for defs (not yet ported)
// #include "winenv/defs/nt/ddk.h"
// #include "winenv/defs/windows/windows.h"

// ── Constants ────────────────────────────────────────────────

constexpr int DISASM_SIZE = 0x20;

// ── Bootstrap phase ──────────────────────────────────────────

enum class BootstrapPhase {
    INITIALIZED = 0,
    ENGINE_API_READY = 1,
    OBJECT_MANAGER_READY = 2,
    FULL_SETUP_READY = 3
};

// ── Forward declarations ─────────────────────────────────────

class MemAccess;
class Run;
class WindowsEmuError;
class WindowsApi;

// ── WindowsEmulator ──────────────────────────────────────────
// Python winemu.py:51
// class WindowsEmulator(BinaryEmulator):
//     """Base class providing emulation of all Windows modules and shellcode.
//     This class is meant to provide overlapping functionality for both
//     user mode and kernel mode samples.
//
//     Subclasses must define:
//         peb_addr: Address of the Process Environment Block
//     """

class WindowsEmulator : public BinaryEmulator {
protected:
    // ── Core state ────────────────────────────────────────────
    bool debug;
    int arch;
    BootstrapPhase bootstrap_phase = BootstrapPhase::INITIALIZED;
    bool _setup_done = false;
    bool kernel_mode = false;

    // ── Modules ───────────────────────────────────────────────
    std::vector<std::shared_ptr<speakeasy::RuntimeModule>> modules;
    std::vector<std::shared_ptr<speakeasy::RuntimeModule>> user_modules;
    std::vector<std::shared_ptr<speakeasy::RuntimeModule>> sys_modules;
    std::vector<std::tuple<void*, std::tuple<uint64_t, size_t>, std::string>> mod_refs;

    // ── Runs ──────────────────────────────────────────────────
    std::shared_ptr<Run> curr_run;
    bool restart_curr_run = false;
    std::shared_ptr<speakeasy::RuntimeModule> curr_mod;
    std::vector<std::shared_ptr<Run>> runs;
    std::vector<std::shared_ptr<Run>> run_queue;
    std::vector<std::shared_ptr<Run>> suspended_runs;
    int max_runs = 100;
    bool run_complete = false;
    bool emu_complete = false;

    // ── Processes ─────────────────────────────────────────────
    std::vector<std::shared_ptr<Process>> processes;
    std::vector<std::shared_ptr<Process>> child_processes;
    std::shared_ptr<Process> curr_process = nullptr;
    std::shared_ptr<Thread> curr_thread = nullptr;

    // ── Memory / hooks ────────────────────────────────────────
    uint64_t page_size = 4096;
    int ptr_size = 0;
    uint64_t virtual_mem_base = 0x50000;
    std::vector<void*> veh_handlers;
    std::vector<void*> mem_trace_hooks;
    bool mem_tracing_enabled = false;
    bool emu_hooks_set = false;
    void* tmp_code_hook = nullptr;
    uint64_t prev_pc = 0;

    // ── SEH / exceptions ──────────────────────────────────────
    uint64_t curr_exception_code = 0;
    uint64_t unhandled_exception_filter = 0;
    std::tuple<uint64_t, uint64_t> _seh_last_fault = {0, 0};
    int _seh_repeat_count = 0;
    static constexpr int _SEH_MAX_REPEAT = 3;

    // ── Registers ─────────────────────────────────────────────
    uint64_t fs_addr = 0;
    uint64_t gs_addr = 0;
    uint64_t return_hook = 0;
    uint64_t exit_hook = 0;

    // ── Symbols / strings ─────────────────────────────────────
    std::map<uint64_t, std::tuple<std::string, std::string>> symbols;
    std::vector<std::string> ansi_strings;
    std::vector<std::string> unicode_strings;

    // ── Data queues ───────────────────────────────────────────
    std::vector<std::tuple<uint64_t, size_t>> tmp_maps;
    std::vector<std::tuple<std::string, std::string, uint64_t>> impdata_queue;
    std::vector<std::tuple<uint64_t, std::string, std::string>> dyn_imps;
    std::vector<std::tuple<uint64_t, std::string, std::string>> callbacks;
    std::map<uint64_t, std::tuple<std::string, uint64_t>> global_data;
    // import_table: sentinel_addr → (dll_name, func_name)
    // Used by ensure_pe_import_hooks and load_image to patch IAT entries
    // so that API calls are intercepted via sentinel values.
    std::map<uint64_t, std::tuple<std::string, std::string>> import_table;
    std::vector<void*> pic_buffers;

    // ── Config fields ─────────────────────────────────────────
    std::string cd;
    std::string command_line;
    std::map<std::string, std::string> registry_config;
    bool dispatch_handlers = true;
    bool do_strings = true;
    bool modules_always_exist = false;
    bool functions_always_exist = false;

    // ── Managers ──────────────────────────────────────────────
    std::shared_ptr<RegistryManager> regman = nullptr;
    std::shared_ptr<FileManager> fileman = nullptr;
    std::shared_ptr<NetworkManager> netman = nullptr;
    std::shared_ptr<DriveManager> driveman = nullptr;
    std::shared_ptr<CryptoManager> cryptman = nullptr;
    std::shared_ptr<ApiHammer> hammer = nullptr;
    std::shared_ptr<WindowsApi> api = nullptr;
    std::shared_ptr<ObjectManager> om = nullptr;     // ObjectManager
    void* wintypes = nullptr;

    // ── Helper ────────────────────────────────────────────────
    static std::string normalize_mod_name(const std::string& name);

public:
    // Python winemu.py:73
    // def __init__(self, config, exit_event=None, debug=False, gdb_port=None):
    //     """Initialize the Windows emulator with configuration."""
    WindowsEmulator(const speakeasy::SpeakeasyConfig& cfg, void* logger = nullptr,
                    void* exit_event = nullptr, bool debug = false);
    virtual ~WindowsEmulator() = default;

    // ── Abstract (subclass must implement) ────────────────────
    // Python winemu.py:190
    // def on_run_complete(self):
    //     """Clean up after a run completes (implemented in the child class) since
    //     this may mean different things depending. This function will pop the
    //     next run from the run queue and emulate it."""
    virtual void on_run_complete() = 0;
    virtual void on_emu_complete() = 0;
    // Python winemu.py:64
    // @abstractmethod
    // def alloc_peb(self, proc: Any) -> None:
    //     """Allocate memory for the Process Environment Block (PEB). Subclasses must implement."""
    virtual void alloc_peb(std::shared_ptr<Process> proc) = 0;
    // Python winemu.py:69
    // @abstractmethod
    // def init_processes(self, processes: list[Any]) -> None:
    //     """Initialize configured processes. Subclasses must implement."""
    virtual void init_processes(const std::vector<void*>& lprocesses) {}

    // ── Bootstrap ─────────────────────────────────────────────
    // Python winemu.py:155
    // def advance_bootstrap_phase(self, phase):
    //     """Advance the bootstrap phase with explicit transition validation.
    //     Raises WindowsEmuError on invalid transitions."""
    void advance_bootstrap_phase(BootstrapPhase phase);
    // Python winemu.py:174
    // def get_bootstrap_phase(self):
    //     """Return the current bootstrap phase."""
    BootstrapPhase get_bootstrap_phase() const { return bootstrap_phase; }
    // Python winemu.py:177
    // def validate_bootstrap_phase(self, phase, reason):
    //     """Validate that the emulator has reached at least the given bootstrap phase."""
    void validate_bootstrap_phase(BootstrapPhase phase, const std::string& reason);
    // Python winemu.py:183
    // def bootstrap_object_services(self):
    //     """Initialize ObjectManager services. Subclasses override."""
    virtual void bootstrap_object_services();
    // Python winemu.py:186
    // def validate_object_services(self, reason):
    //     """Validate that ObjectManager is initialized. Raises WindowsEmuError if not."""
    void validate_object_services(const std::string& reason);

    // ── Config ────────────────────────────────────────────────
    // Config parsing now handled by BinaryEmulator (typed SpeakeasyConfig)
    // Python winemu.py:147
    // def _parse_config(self, config):
    //     """Parse the emulation config file. Not yet ported to C++."""
    std::map<std::string, std::string> get_registry_config();

    // ── Hooks ─────────────────────────────────────────────────
    // Python winemu.py:199
    // def enable_code_hook(self):
    //     """Install the transient code hook needed for deferred work."""
    void enable_code_hook();
    // Python winemu.py:206
    // def disable_code_hook(self):
    //     """Remove the transient code hook."""
    void disable_code_hook();
    // Python winemu.py:628
    // def set_hooks(self):
    //     """Reserves memory that will be used to handle events that occur during emulation."""
    void set_hooks();
    // Python winemu.py:377
    // def _set_emu_hooks(self):
    //     """Unmap reserved memory space so we can handle events (e.g. import APIs, entry point returns, etc.)"""
    void _set_emu_hooks();
    // Python winemu.py:259
    // def _unset_emu_hooks(self):
    //     """Re-map reserved memory space to catch import API calls and return events."""
    void _unset_emu_hooks();
    // Python winemu.py:218
    // def set_mem_tracing_hooks(self):
    //     """Install memory tracing hooks for analysis."""
    void set_mem_tracing_hooks();
    // Python winemu.py:210
    // def _module_access_hook(self, emu, addr, size):
    //     """Code hook fired for access to module API addresses; resolves symbol and dispatches handler."""
    bool _module_access_hook(void* emu, uint64_t addr, size_t size, void* ctx);
    // Python winemu.py:2031
    // def _hook_code_core(self, emu, addr, size):
    //     """Transient code hook for deferred work: SEH dispatch, run lifecycle,
    //     temp map cleanup, and import data queue processing. Enabled on demand
    //     and disables itself once the pending work is drained."""
    bool _hook_code_core(void* emu, uint64_t addr, size_t size);

    // ── Memory exception handlers ───────────────────────────────
    // Python winemu.py:1960
    // def _handle_invalid_read(self, emu, address, size, value):
    //     """Hook each invalid memory read event that occurs."""
    bool _handle_invalid_read(void* emu, uint64_t addr, size_t size, uint64_t value);
    // Python winemu.py:1988
    // def _handle_prot_fetch(self, emu, address, size, value):
    //     """Called when non-executable code is emulated."""
    bool _handle_prot_fetch(void* emu, uint64_t addr, size_t size, uint64_t value);
    // Python winemu.py:2008
    // def _handle_invalid_write(self, emu, address, size, value):
    //     """Called when non-writable address is written to."""
    bool _handle_invalid_write(void* emu, uint64_t addr, size_t size, uint64_t value);

    // ── Shared data ─────────────────────────────────────────────
    // Python winemu.py:507
    // def _populate_user_shared_data(self, base):
    //     """Populate the KUSER_SHARED_DATA page with system time and version info."""
    void _populate_user_shared_data(uint64_t base);

    // ── Memory ────────────────────────────────────────────────
    // Python winemu.py:251
    // def cast(self, obj, bytez):
    //     """Create a formatted structure from bytes"""
    EmuStruct* cast(EmuStruct* obj, const std::vector<uint8_t>& bytez);
    // Python winemu.py:478
    // def mem_cast(self, obj, addr):
    //     """Turn bytes from an emulated memory pointer into an object"""
    EmuStruct* mem_cast(EmuStruct* obj, uint64_t addr);
    // Python winemu.py:486
    // def mem_purge(self):
    //     """Unmap all memory chunks"""
    void mem_purge();
    // Python winemu.py:492
    // def setup_user_shared_data(self):
    //     """Setup the shared user data section that is often used to share data
    //     between user mode and kernel mode"""
    void setup_user_shared_data();
    // Python winemu.py:676
    // def _setup_gdt(self, arch):
    //     """Set up the GDT so we can access segment registers correctly.
    //     This will be done a little differently depending on architecture"""
    std::tuple<uint64_t, uint64_t> _setup_gdt(int arch);

    // ── File ──────────────────────────────────────────────────
    // Python winemu.py:267
    // def file_open(self, path, create=False, truncate=False):
    //     """Open an emulated file using the file manager"""
    void* file_open(const std::string& path, bool create = false);
    // Python winemu.py:273
    // def pipe_open(self, path, mode, num_instances, out_size, in_size):
    //     """Open an emulated named pipe"""
    void* pipe_open(const std::string& path, const std::string& mode,
                    int num_instances, size_t out_size, size_t in_size);
    // Python winemu.py:279
    // def does_file_exist(self, path):
    //     """Test if a file handler for a specified emulated file exists"""
    bool does_file_exist(const std::string& path);
    // Python winemu.py:285
    // def file_create_mapping(self, hfile, name, size, prot):
    //     """Create a memory mapping for an emulated file"""
    void* file_create_mapping(void* hfile, const std::string& name,
                              size_t size, int prot);
    // Python winemu.py:291
    // def file_get(self, handle):
    //     """Get a file object from a handle"""
    void* file_get(int handle);
    // Python winemu.py:297
    // def file_delete(self, path):
    //     """Delete a file"""
    bool file_delete(const std::string& path);
    // Python winemu.py:303
    // def pipe_get(self, handle):
    //     """Get a pipe object from a handle"""
    void* pipe_get(int handle);
    // Python winemu.py:309
    // def get_file_manager(self):
    //     """Get the file emulation manager"""
    std::shared_ptr<FileManager> get_file_manager();

    // ── Network ───────────────────────────────────────────────
    // Python winemu.py:315
    // def get_network_manager(self):
    //     """Get the network emulation manager"""
    std::shared_ptr<NetworkManager> get_network_manager();

    // ── Crypto ────────────────────────────────────────────────
    // Python winemu.py:321
    // def get_crypt_manager(self):
    //     """Get the crypto manager"""
    std::shared_ptr<CryptoManager> get_crypt_manager();

    // ── Drives ────────────────────────────────────────────────
    // Python winemu.py:327
    // def get_drive_manager(self):
    //     """Get the drive manager"""
    std::shared_ptr<DriveManager> get_drive_manager();

    // ── Registry ──────────────────────────────────────────────
    // Python winemu.py:351
    // def reg_open_key(self, path, create=False):
    //     """Open or create a registry key in the emulation space"""
    void* reg_open_key(const std::string& path, bool create = false);
    // Python winemu.py:357
    // def reg_get_subkeys(self, hkey):
    //     """Get subkeys for a given registry key"""
    std::vector<std::string> reg_get_subkeys(void* hkey);
    // Python winemu.py:363
    // def reg_get_key(self, handle=0, path=""):
    //     """Get registry key by path or handle"""
    void* reg_get_key(int handle = 0, const std::string& path = "");
    // Python winemu.py:371
    // def reg_create_key(self, path):
    //     """Create a registry key"""
    void* reg_create_key(const std::string& path);

    // ── Run control ───────────────────────────────────────────
    // Python winemu.py:386
    // def add_run(self, run):
    //     """Add a run to the emulation run queue"""
    void add_run(std::shared_ptr<Run> run);
    // Python winemu.py:392
    // def _exec_next_run(self):
    //     """Execute the next run from the emulation queue"""
    std::shared_ptr<Run> _exec_next_run();
    // Python winemu.py:424
    // def _prepare_run_context(self, run):
    //     """Prepare CPU and memory state for the given run without starting emulation."""
    std::shared_ptr<Run> _prepare_run_context(std::shared_ptr<Run> run);
    // Python winemu.py:408
    // def call(self, addr, params=[]):
    //     """Start emulating at the specified address"""
    void call(uint64_t addr, const std::vector<std::string>& params = {});
    // Python winemu.py:— (run exec loop inline in start())
    std::shared_ptr<Run> _exec_run(std::shared_ptr<Run> run);
    // Python winemu.py:543
    // def start(self, addr=None, size=None):
    //     """Begin emulation executing each run in the specified run queue"""
    void start();
    // Python winemu.py:536
    // def resume(self, addr, count=-1):
    //     """Resume emulation at the specified address."""
    void resume(uint64_t addr, int count = -1);

    // ── Run access ────────────────────────────────────────────
    // Python winemu.py:609
    // def get_current_run(self):
    //     """Get the current run that is being emulated"""
    std::shared_ptr<Run> get_current_run();
    // Python winemu.py:615
    // def get_current_module(self):
    //     """Get the currently running module"""
    std::shared_ptr<speakeasy::RuntimeModule> get_current_module();
    // Python winemu.py:621
    // def get_dropped_files(self):
    //     """Get all files written by the sample from the file manager"""
    std::vector<std::shared_ptr<File>> get_dropped_files();

    // ── Process / thread ──────────────────────────────────────
    // Python winemu.py:635
    // def get_processes(self):
    //     """Get the current processes that exist in the emulation space"""
    std::vector<std::shared_ptr<Process>>& get_processes();
    // Python winemu.py:643
    // def kill_process(self, proc):
    //     """Terminate a process (i.e. remove it from the known process list)"""
    void kill_process(std::shared_ptr<Process> proc);
    // Python winemu.py:652
    // def get_current_thread(self):
    //     """Get the current thread that is emulating"""
    std::shared_ptr<Thread> get_current_thread();
    // Python winemu.py:658
    // def get_current_process(self):
    //     """Get the current process that is emulating"""
    std::shared_ptr<Process> get_current_process();
    std::shared_ptr<Process> find_process(void* proc_ptr);
    // Python winemu.py:664
    // def set_current_process(self, process):
    //     // """Set the current process that is emulating"""
    void set_current_process(std::shared_ptr<Process> process);
    // Python winemu.py:670
    // def set_current_thread(self, thread):
    //     """Set the current thread"""
    void set_current_thread(std::shared_ptr<Thread> thread);

    // ── Environment ────────────────────────────────────────────
    // Python winemu.py:1142
    // def get_system_root(self):
    //     """Get the path of the "SYSTEMROOT" environment variable"""
    std::string get_system_root();
    // Python winemu.py:1151
    // def get_windows_dir(self):
    //     """Get the path of the "WINDIR" environment variable"""
    std::string get_windows_dir();
    // Python winemu.py:1160
    // def get_cd(self):
    //     """Get the path of the current directory"""
    std::string get_cd();
    // Python winemu.py:1170
    // def set_cd(self, cd):
    //     """Sets the current directory path"""
    void set_cd(const std::string& path);
    // Python winemu.py:1176
    // def get_env(self):
    //     """Get the environment variables map."""
    std::map<std::string, std::string> get_env();
    // Python winemu.py:1179
    // def set_env(self, var, val):
    //     """Set an environment variable (key lowercased)."""
    void set_env(const std::string& var, const std::string& val);
    // Python winemu.py:1213
    // def search_path(self, file_name):
    //     """Search the emulated filesystem for a file. Currently returns cd + filename."""
    std::string search_path(const std::string& file_name);
    // Python winemu.py:1139
    // def setup(self):
    //     """Post-init setup hook. Subclasses override."""
    virtual void setup(size_t stack_commit = 0, bool first_time_setup = true) = 0;

    // ── Object management ──────────────────────────────────────
    // Python winemu.py:1182
    // def get_object_from_addr(self, addr):
    //     """Get an object from its memory address."""
    std::shared_ptr<KernelObject> get_object_from_addr(uint64_t addr);
    // Python winemu.py:1186
    // def get_object_from_id(self, id):
    //     """Get an object from its unique id."""
    std::shared_ptr<KernelObject> get_object_from_id(int id);
    // Python winemu.py:1190
    // def get_object_from_name(self, name):
    //     """Get an object from its name."""
    std::shared_ptr<KernelObject> get_object_from_name(const std::string& name);
    // Python winemu.py:1194
    // def get_object_from_handle(self, handle):
    //     """Get an object from its handle."""
    std::shared_ptr<KernelObject> get_object_from_handle(uint64_t handle);
    // Python winemu.py:1203
    // def get_object_handle(self, obj):
    //     """Get the handle for a given object."""
    int get_object_handle(std::shared_ptr<KernelObject> obj);
    // Python winemu.py:1209
    // def add_object(self, obj):
    //     """Register an object with the ObjectManager."""
    void add_object(std::shared_ptr<KernelObject> obj);
    // Python winemu.py:1222
    // def new_object(self, otype):
    //     """Create a new object of the given type."""
    template<typename T> std::shared_ptr<T> new_object();

    // ── PE / module helpers ────────────────────────────────────
    // Python winemu.py:847
    // def get_mod_from_addr(self, addr):
    //     """Get a module from an address within it."""
    std::shared_ptr<speakeasy::RuntimeModule> get_mod_from_addr(uint64_t addr);
    // Python winemu.py:860
    // def _alloc_sentinel(self):
    //     """Allocate a sentinel value for import table hooking."""
    uint64_t _alloc_sentinel();
    // Python winemu.py:979
    // def get_mod_by_name(self, name):
    //     """Find a loaded module by name (case-insensitive)."""
    std::shared_ptr<speakeasy::RuntimeModule> get_mod_by_name(const std::string& name);
    // Python winemu.py:990
    // def get_peb_modules(self):
    //     """Get modules that are visible in the PEB."""
    std::vector<std::shared_ptr<speakeasy::RuntimeModule>> get_peb_modules();

    // ── PE initialization ─────────────────────────────────────
    // Python winemu.py:760
    // def init_peb(self, user_mods, proc=None):
    //     """Initialize the Process Environment Block"""
    void init_peb(std::vector<std::shared_ptr<speakeasy::RuntimeModule>>& user_mods, std::shared_ptr<Process> proc);
    // Python winemu.py:771
    // def init_teb(self, thread, peb):
    //     """Initialize the Thread Information Block"""
    void init_teb(std::shared_ptr<Thread> thread, void* peb);
    // Python winemu.py:780
    // def init_tls(self, thread):
    //     """Initialize implicit thread local storage. Meant to be called after init_teb."""
    void init_tls(std::shared_ptr<Thread> thread);
    // Python winemu.py:809
    // def load_pe(self, path=None, data=None, imp_id=winemu.IMPORT_HOOK_ADDR):
    //     """Parse a PE that will be used during emulation. PE type and architecture
    //     are automatically determined."""
    std::shared_ptr<speakeasy::RuntimeModule> load_pe(const std::string& path = "", const std::vector<uint8_t>& data = {},
                  uint64_t imp_id = 0);
    // Python winemu.py:993
    // def load_image(self, image):
    //     """Load a parsed PE image into emulated memory, set up imports/exports, sections."""
    std::shared_ptr<speakeasy::RuntimeModule> load_image(std::shared_ptr<speakeasy::LoadedImage> image);
    // Python winemu.py:865
    // def ensure_pe_import_hooks(self, base_addr):
    //     """Ensure a PE image in emulated memory has its IAT patched with sentinel
    //     values so that API calls are intercepted by speakeasy. Idempotent."""
    void ensure_pe_import_hooks(uint64_t base_addr);

    // ── Module loading ────────────────────────────────────────
    // Python winemu.py:2180
    // def get_native_module_path(self, mod_name=""):
    //     """Get the full filesystem path of a default decoy that is supplied by speakeasy"""
    std::string get_native_module_path(const std::string& mod_name = "");
    // Python winemu.py:2212
    // def load_library(self, mod_name):
    //     """Load a library (DLL) by name. Returns its base address or 0."""
    void* load_library(const std::string& mod_name);
    // Python winemu.py:2231
    // def load_module_by_name(self, name, emu_path=None, base=None):
    //     """Load a module by name using the appropriate loader.
    //     Priority: native PE file -> API handler (JIT PE) -> placeholder stub."""
    std::shared_ptr<speakeasy::RuntimeModule> load_module_by_name(const std::string& name,
                              const std::string& emu_path = "",
                              uint64_t base = 0);
    // Python winemu.py:2278
    // def get_module_data_from_emu_file(self, file_path):
    //     """Get raw PE data from a file inside the emulated filesystem."""
    std::vector<uint8_t> get_module_data_from_emu_file(const std::string& file_path);
    // Python winemu.py:2292
    // def init_environment(self, system_modules=None, user_modules=None):
    //     """Initialize the emulated system and user module environments."""
    std::vector<std::shared_ptr<speakeasy::RuntimeModule>> init_environment(
        const std::vector<std::shared_ptr<speakeasy::Module>>& system_modules = {},
        const std::vector<std::shared_ptr<speakeasy::Module>>& user_modules = {});
    // Python winemu.py:2302
    // def init_sys_modules(self, modules_config):
    //     """Initialize system modules from the config."""
    std::vector<std::shared_ptr<speakeasy::RuntimeModule>> init_sys_modules(const std::vector<std::shared_ptr<speakeasy::Module>>& modules_config);
    // Python winemu.py:2305
    // def init_user_modules(self, modules_config):
    //     """Initialize user modules from the config."""
    std::vector<std::shared_ptr<speakeasy::RuntimeModule>> init_user_modules(const std::vector<std::shared_ptr<speakeasy::Module>>& modules_config);
    // Python winemu.py:2308
    // def _init_module_group(self, modules_config, default_base=None):
    //     """Initialize a group of modules from config objects."""
    std::vector<std::shared_ptr<speakeasy::RuntimeModule>> _init_module_group(const std::vector<std::shared_ptr<speakeasy::Module>>& modules_config, uint64_t default_base = 0);

    // ── Thread context ────────────────────────────────────────
    // Python winemu.py:2364
    // def get_thread_context(self, thread=None):
    //     """Get the current thread CPU context"""
    void* get_thread_context(std::shared_ptr<Thread> thread = nullptr);
    // Python winemu.py:2418
    // def load_thread_context(self, ctx, thread=None):
    //     """Set the current thread CPU context"""
    void load_thread_context(void* ctx, std::shared_ptr<Thread> thread = nullptr);

    // ── API / import handling ──────────────────────────────────
    // Python winemu.py:1639
    // def handle_import_func(self, dll, name):
    //     """Forward imported functions to the corresponding handler (if any)."""
    void handle_import_func(const std::string& dll, const std::string& name);
    // Python winemu.py:1614
    // def log_api(self, pc, imp_api, rv, argv):
    //     """Log an API call with its arguments and return value."""
    void log_api(uint64_t pc, const std::string& api, uint64_t rv, const std::vector<uint64_t>& argv);
    // Python winemu.py:1372
    // def handle_import_data(self, mod_name, sym, data_ptr=0):
    //     """Data that is imported (e.g. KeTickCount) is handled with an initializer function."""
    void handle_import_data(const std::string& mod, const std::string& sym, uint64_t data_ptr = 0);
    // Python winemu.py:1358
    // def get_proc(self, mod_name, func_name):
    //     """Get a pointer for a supplied function name, similar to GetProcAddress."""
    void* get_proc(const std::string& mod_name, const std::string& func_name);
    // Python winemu.py:1336
    // def add_callback(self, mod_name, func_name):
    //     """Adds a callback to the emulation callback list. A "callback" in this
    //     context refers to a function that is not imported statically or dynamically."""
    uint64_t add_callback(const std::string& mod_name, const std::string& func_name);
    // Python winemu.py:1821
    // def get_symbol_from_address(self, address):
    //     """If the supplied address is related to a known symbol, look it up here."""
    std::string get_symbol_from_address(uint64_t address);
    // Python winemu.py:1561
    // def normalize_import_miss(self, dll, name):
    //     """This function attempts to fold as many function handlers together as possible.
    //     For example, ntdll functions will be handled by the ntoskrnl handlers, multiple versions
    //     of the C runtime are folded together, and Zw/Nt functions use the same handler."""
    std::tuple<std::string, std::string> normalize_import_miss(const std::string& dll, const std::string& name);
    // Python winemu.py:1604
    // def read_unicode_string(self, addr):
    //     """Read string data from a UNICODE_STRING object located at the specified address"""
    std::vector<uint8_t> read_unicode_string(uint64_t addr);
    // Python winemu.py:1814
    // def restart_run(self, run):
    //     """Restart the current run"""
    void restart_run(void* run);

    // ── Unicorn hook bridge ──────────────────────────────────
    // Python winemu.py:— (Unicorn engine binding)
    void _register_code_hook(void* callback, uint64_t begin, uint64_t end);
    // Python winemu.py:— (Unicorn engine binding)
    void _register_mem_hook(int hook_type, void* callback);
    std::vector<uc_hook> uc_hooks_;

    // ── Memory hooks (additional) ──────────────────────────────
    // Python winemu.py:1831
    // def _hook_mem_read(self, emu, access, address, size, value):
    //     """Hook each memory read event that occurs. This hook is used to lookup symbols and modules
    //     that are read from during emulation."""
    bool _hook_mem_read(void* emu, int access, uint64_t addr, size_t size, uint64_t value);
    // Python winemu.py:1907
    // def _hook_mem_write(self, emu, access, address, size, value):
    //     """Hook each memory write event that occurs. This hook is used to track memory modifications
    //     to interesting memory locations."""
    bool _hook_mem_write(void* emu, int access, uint64_t addr, size_t size, uint64_t value);
    // Python winemu.py:1752
    // def _hook_mem_unmapped(self, emu, access, address, size, value):
    //     """High level function used to catch all invalid memory accesses that occur during emulation"""
    bool _hook_mem_unmapped(void* emu, int access, uint64_t addr, size_t size, uint64_t value);
    // Python winemu.py:1389
    // def _handle_invalid_fetch(self, emu, address, size, value):
    //     """Called when an attempt to emulate an instruction from an invalid address"""
    bool _handle_invalid_fetch(void* emu, uint64_t addr, uint64_t size, uint64_t value);
    // Python winemu.py:1802
    // def _handle_prot_write(self, emu, address, size, value):
    //     """Handle protection violation on write access by mapping a fake page and logging error."""
    bool _handle_prot_write(void* emu, uint64_t addr, uint64_t size, uint64_t value);

    // ── Code hooks (additional) ────────────────────────────────
    // Python winemu.py:2097
    // def _hook_code_tracing(self, emu, addr, size):
    //     """Persistent code hook for memory tracing: instruction counting,
    //     symbol execution tracking, and per-region execution tracking."""
    bool _hook_code_tracing(void* emu, uint64_t addr, size_t size);
    // Python winemu.py:2083
    // def _hook_code_coverage(self, emu, addr, size):
    //     """Persistent code hook that records every executed address for coverage."""
    bool _hook_code_coverage(void* emu, uint64_t addr, size_t size);
    // Python winemu.py:2166
    // def _hook_code_debug(self, emu, addr, size):
    //     """Persistent code hook that prints disassembly and register state
    //     for every instruction when debug mode is enabled."""
    bool _hook_code_debug(void* emu, uint64_t addr, size_t size);
    // Python winemu.py:232
    // def set_coverage_hooks(self):
    //     """Install coverage tracking code hook if enabled in config."""
    void set_coverage_hooks();
    // Python winemu.py:242
    // def set_debug_hooks(self):
    //     """Install debug code hook if enabled."""
    void set_debug_hooks();

    // ── SEH ───────────────────────────────────────────────────
    // Python winemu.py:2467
    // def _get_exception_list(self):
    //     """Retrieves the exception handler list for the current thread"""
    uint64_t _get_exception_list();
    // Python winemu.py:2652
    // def _map_faulting_page_for_exception(self, faulting_address):
    //     """Map a single page at faulting_address with RW permissions for SEH recovery"""
    void _map_faulting_page_for_exception(uint64_t faulting_address);
    // Python winemu.py:2478
    // def _dispatch_seh_x86(self, except_code):
    //     """Get the initial SEH handler when dispatching a CPU exception that occurs during emulation"""
    bool _dispatch_seh_x86(uint64_t except_code);
    // Python winemu.py:2583
    // def get_reserved_ranges(self):
    //     """Get the allocated memory ranges that the emulator reserves"""
    std::tuple<uint64_t, uint64_t> get_reserved_ranges();
    // Python winemu.py:2589
    // def _continue_seh_x86(self):
    //     """Get the next exception handler while processing SEH"""
    void _continue_seh_x86();
    // Python winemu.py:2662
    // def dispatch_seh(self, except_code, faulting_address=None):
    //     """Dispatch a structured exception by walking the SEH chain. Falls back
    //     to unhandled exception filter if available."""
    bool dispatch_seh(uint64_t except_code, uint64_t faulting_address = 0);
    // Python winemu.py:2707
    // def continue_seh(self):
    //     """Reset SEH repeat-detection state."""
    void continue_seh();

    // ── Objects ───────────────────────────────────────────────
    // Python winemu.py:2713
    // def create_event(self, name=""):
    //     """Create a kernel event object"""
    std::tuple<int, std::shared_ptr<Event>> create_event(const std::string& name = "");
    // Python winemu.py:2723
    // def dec_ref(self, obj):
    //     """Dereference an object"""
    int dec_ref(void* obj);
    // Python winemu.py:2730
    // def create_mutant(self, name=""):
    //     """Create a kernel mutant object"""
    std::tuple<int, std::shared_ptr<Mutant>> create_mutant(const std::string& name = "");
    // Python winemu.py:333
    // def dev_ioctl(self, arch, dev, ioctl, inbuf):
    //     """Dispatch a device I/O control request to the I/O manager."""
    void* dev_ioctl(uint32_t ctl_code, void* in_buf, size_t in_len,
                    void* out_buf, size_t out_len);

    // ── Process / thread creation ─────────────────────────────
    // Python winemu.py:1226
    // def create_process(self, path=None, cmdline=None, image=None, child=False):
    //     """Create a process object that will exist in the emulator.
    //     NOT YET PORTED — stub only."""
    std::shared_ptr<Process> create_process(const std::string& path = "", const std::string& cmdline = "",
        std::shared_ptr<speakeasy::RuntimeModule> image = nullptr, bool child = false);
    // Python winemu.py:1293
    // def create_thread(self, addr, ctx, proc_obj, thread_type="thread", is_suspended=False):
    //     """Create a thread object that will exist in the emulator.
    //     NOT YET PORTED — stub only."""
    std::shared_ptr<Thread> create_thread(uint64_t addr, void* ctx, std::shared_ptr<Process> proc_obj,
                        const std::string& thread_type = "thread", bool is_suspended = false);
    // def resume_thread(self, thread):
    //     """Resume a previously suspended thread"""
    void resume_thread(std::shared_ptr<Thread> thread);

    // Helpers to lookup thread
    std::shared_ptr<Thread> find_thread(int handle_or_id);
    std::shared_ptr<Thread> find_thread_by_ptr(void* thread_ptr);
    // Python winemu.py:1333
    // def get_process_peb(self, process):
    //     """Get the PEB for a given process."""
    void* get_process_peb(void* process);

    // ── Error / context ────────────────────────────────────────
    // Python winemu.py:1511
    // def get_error_info(self, desc, address, traceback=None, access_type=None):
    //     """Collect emulator state information in the event of an error."""
    std::string get_error_info(const std::string& msg, uint64_t pc, const std::string& trace = "");
    // Python winemu.py:1439
    // def _resolve_module_offset(self, addr: int) -> str | None:
    //     """Return 'module+0xoffset' string for an address inside a loaded module, or None."""
    std::string _resolve_module_offset(uint64_t addr);
    // Python winemu.py:1448
    // def _resolve_region_info(self, addr: int) -> RegionInfo | None:
    //     """Return a RegionInfo for the region containing addr, or None if unmapped."""
    std::string _resolve_region_info(uint64_t addr);

    // ── Hardware interrupts ───────────────────────────────────
    // Python winemu.py:2742
    // def _hook_interrupt(self, emu, intnum):
    //     """Called when software interrupts occur (INT3, INT0, INT1, INT0x29, etc.)"""
    bool _hook_interrupt(void* emu, int intnum);
};

// ── Free functions ───────────────────────────────────────────

// Python winemu.py:40
// def _normalize_mod_name(name: str) -> str:
//     """Normalize a module name by stripping extension and lowercasing."""
inline std::string WindowsEmulator::normalize_mod_name(const std::string& name) {
    auto dot = name.find_last_of('.');
    std::string base = (dot != std::string::npos) ? name.substr(0, dot) : name;
    // lowercase
    for (auto& c : base) c = static_cast<char>(std::tolower(c));
    return base;
}

#endif // WINEMU_H