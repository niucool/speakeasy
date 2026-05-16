// winemu.h — Base Windows emulator class
//
// Maps to: speakeasy/windows/winemu.py
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
#include "errors.h"
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

// ── WindowsEmulator ──────────────────────────────────────────

class WindowsEmulator : public BinaryEmulator {
protected:
    // ── Core state ────────────────────────────────────────────
    bool debug;
    int arch;
    BootstrapPhase bootstrap_phase = BootstrapPhase::INITIALIZED;
    bool _setup_done = false;
    bool kernel_mode = false;

    // ── Modules ───────────────────────────────────────────────
    std::vector<void*> modules;
    std::vector<void*> user_modules;
    std::vector<void*> sys_modules;
    std::vector<std::tuple<void*, std::tuple<uint64_t, size_t>, std::string>> mod_refs;

    // ── Runs ──────────────────────────────────────────────────
    std::shared_ptr<Run> curr_run;
    bool restart_curr_run = false;
    void* curr_mod = nullptr;
    std::vector<std::shared_ptr<Run>> runs;
    std::vector<std::shared_ptr<Run>> run_queue;
    std::vector<std::shared_ptr<Run>> suspended_runs;
    int max_runs = 100;
    bool run_complete = false;
    bool emu_complete = false;

    // ── Processes ─────────────────────────────────────────────
    std::vector<void*> processes;
    std::vector<void*> child_processes;
    void* curr_process = nullptr;
    void* curr_thread = nullptr;

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
    void* regman = nullptr;
    void* fileman = nullptr;
    void* netman = nullptr;
    void* driveman = nullptr;
    void* cryptman = nullptr;
    void* hammer = nullptr;
    void* api = nullptr;
    void* om = nullptr;         // ObjectManager
    void* wintypes = nullptr;

    // ── Helper ────────────────────────────────────────────────
    static std::string normalize_mod_name(const std::string& name);

public:
    WindowsEmulator(const std::string& config, void* logger = nullptr,
                    void* exit_event = nullptr, bool debug = false);
    virtual ~WindowsEmulator() = default;

    // ── Abstract (subclass must implement) ────────────────────
    virtual void on_run_complete() = 0;
    virtual void on_emu_complete() = 0;
    virtual void alloc_peb(void* proc) {}
    virtual void init_processes(const std::vector<void*>& processes) {}

    // ── Bootstrap ─────────────────────────────────────────────
    void advance_bootstrap_phase(BootstrapPhase phase);
    BootstrapPhase get_bootstrap_phase() const { return bootstrap_phase; }
    void validate_bootstrap_phase(BootstrapPhase phase, const std::string& reason);
    virtual void bootstrap_object_services();
    void validate_object_services(const std::string& reason);

    // ── Config ────────────────────────────────────────────────
    void _parse_config(const std::string& config);
    std::map<std::string, std::string> get_registry_config();

    // ── Hooks ─────────────────────────────────────────────────
    void enable_code_hook();
    void disable_code_hook();
    void set_hooks();
    void _set_emu_hooks();
    void _unset_emu_hooks();
    void set_mem_tracing_hooks();
    bool _module_access_hook(void* emu, uint64_t addr, size_t size, void* ctx);
    bool _hook_code_core(void* emu, uint64_t addr, size_t size);

    // ── Memory exception handlers ───────────────────────────────
    bool _handle_invalid_read(void* emu, uint64_t addr, size_t size, uint64_t value);
    bool _handle_prot_fetch(void* emu, uint64_t addr, size_t size, uint64_t value);
    bool _handle_invalid_write(void* emu, uint64_t addr, size_t size, uint64_t value);

    // ── Shared data ─────────────────────────────────────────────
    void _populate_user_shared_data(uint64_t base);

    // ── Memory ────────────────────────────────────────────────
    EmuStruct* cast(EmuStruct* obj, const std::vector<uint8_t>& bytez);
    EmuStruct* mem_cast(EmuStruct* obj, uint64_t addr);
    void mem_purge();
    void setup_user_shared_data();
    std::tuple<uint64_t, uint64_t> _setup_gdt(int arch);

    // ── File ──────────────────────────────────────────────────
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

    // ── Network ───────────────────────────────────────────────
    void* get_network_manager();

    // ── Crypto ────────────────────────────────────────────────
    void* get_crypt_manager();

    // ── Drives ────────────────────────────────────────────────
    void* get_drive_manager();

    // ── Registry ──────────────────────────────────────────────
    void* reg_open_key(const std::string& path, bool create = false);
    std::vector<std::string> reg_get_subkeys(void* hkey);
    void* reg_get_key(int handle = 0, const std::string& path = "");
    void* reg_create_key(const std::string& path);

    // ── Run control ───────────────────────────────────────────
    void add_run(std::shared_ptr<Run> run);
    std::shared_ptr<Run> _exec_next_run();
    std::shared_ptr<Run> _prepare_run_context(std::shared_ptr<Run> run);
    void call(uint64_t addr, const std::vector<std::string>& params = {});
    std::shared_ptr<Run> _exec_run(std::shared_ptr<Run> run);
    void start();
    void resume(uint64_t addr, int count = -1);

    // ── Run access ────────────────────────────────────────────
    std::shared_ptr<void> get_current_run();
    void* get_current_module();
    std::vector<void*> get_dropped_files();

    // ── Process / thread ──────────────────────────────────────
    std::vector<void*> get_processes();
    void kill_process(void* proc);
    void* get_current_thread();
    void* get_current_process();
    void set_current_process(void* process);
    void set_current_thread(void* thread);

    // ── Environment ────────────────────────────────────────────
    std::string get_system_root();
    std::string get_windows_dir();
    std::string get_cd();
    void set_cd(const std::string& path);
    std::map<std::string, std::string> get_env();
    void set_env(const std::string& var, const std::string& val);
    std::string search_path(const std::string& file_name);
    void setup() {}

    // ── Object management ──────────────────────────────────────
    void* get_object_from_addr(uint64_t addr);
    void* get_object_from_id(int id);
    void* get_object_from_name(const std::string& name);
    void* get_object_from_handle(int handle);
    int get_object_handle(void* obj);
    void add_object(void* obj);
    void* new_object(void* otype);

    // ── PE / module helpers ────────────────────────────────────
    void* get_mod_from_addr(uint64_t addr);
    uint64_t _alloc_sentinel();
    void* get_mod_by_name(const std::string& name);
    std::vector<void*> get_peb_modules();

    // ── PE initialization ─────────────────────────────────────
    void init_peb(void* user_mods, void* proc = nullptr);
    void init_teb(void* thread, void* peb);
    void init_tls(void* thread);
    void* load_pe(const std::string& path = "", const std::vector<uint8_t>& data = {},
                  uint64_t imp_id = 0);
    void* load_image(void* image);
    void ensure_pe_import_hooks(uint64_t base_addr);

    // ── Module loading ────────────────────────────────────────
    std::string get_native_module_path(const std::string& mod_name = "");
    void* load_library(const std::string& mod_name);
    void* load_module_by_name(const std::string& name,
                              const std::string& emu_path = "",
                              uint64_t base = 0);
    std::vector<uint8_t> get_module_data_from_emu_file(const std::string& file_path);
    std::vector<void*> init_environment(
        const std::vector<void*>& system_modules = {},
        const std::vector<void*>& user_modules = {});
    std::vector<void*> init_sys_modules(const std::vector<void*>& modules_config);
    std::vector<void*> init_user_modules(const std::vector<void*>& modules_config);
    std::vector<void*> _init_module_group(const std::vector<void*>& modules_config, uint64_t default_base = 0);

    // ── Thread context ────────────────────────────────────────
    void* get_thread_context(void* thread = nullptr);
    void load_thread_context(void* ctx, void* thread = nullptr);

    // ── API / import handling ──────────────────────────────────
    void handle_import_func(const std::string& dll, const std::string& name);
    void log_api(uint64_t pc, const std::string& api, uint64_t rv, const std::vector<uint64_t>& argv);
    void handle_import_data(const std::string& mod, const std::string& sym, uint64_t data_ptr = 0);
    void* get_proc(const std::string& mod_name, const std::string& func_name);
    uint64_t add_callback(const std::string& mod_name, const std::string& func_name);
    std::string get_symbol_from_address(uint64_t address);
    std::tuple<std::string, std::string> normalize_import_miss(const std::string& dll, const std::string& name);
    std::vector<uint8_t> read_unicode_string(uint64_t addr);
    void restart_run(void* run);

    // ── Unicorn hook bridge ──────────────────────────────────
    void _register_code_hook(void* callback, uint64_t begin, uint64_t end);
    void _register_mem_hook(int hook_type, void* callback);
    std::vector<uc_hook> uc_hooks_;

    // ── Memory hooks (additional) ──────────────────────────────
    bool _hook_mem_read(void* emu, int access, uint64_t addr, size_t size, uint64_t value);
    bool _hook_mem_write(void* emu, int access, uint64_t addr, size_t size, uint64_t value);
    bool _hook_mem_unmapped(void* emu, int access, uint64_t addr, size_t size, uint64_t value);
    bool _handle_invalid_fetch(void* emu, uint64_t addr, size_t size, uint64_t value);
    bool _handle_prot_write(void* emu, uint64_t addr, size_t size, uint64_t value);

    // ── Code hooks (additional) ────────────────────────────────
    bool _hook_code_tracing(void* emu, uint64_t addr, size_t size);
    bool _hook_code_coverage(void* emu, uint64_t addr, size_t size);
    bool _hook_code_debug(void* emu, uint64_t addr, size_t size);
    void set_coverage_hooks();
    void set_debug_hooks();

    // ── SEH ───────────────────────────────────────────────────
    uint64_t _get_exception_list();
    bool _dispatch_seh_x86(uint64_t except_code);
    std::tuple<uint64_t, uint64_t> get_reserved_ranges();
    void _continue_seh_x86();
    bool dispatch_seh(uint64_t except_code, uint64_t faulting_address = 0);
    void continue_seh();

    // ── Objects ───────────────────────────────────────────────
    std::tuple<int, void*> create_event(const std::string& name = "");
    int dec_ref(void* obj);
    std::tuple<int, void*> create_mutant(const std::string& name = "");
    void* dev_ioctl(uint32_t ctl_code, void* in_buf, size_t in_len,
                    void* out_buf, size_t out_len);

    // ── Process / thread creation ─────────────────────────────
    void* create_process(const std::string& path = "", const std::string& cmdline = "",
                         void* image = nullptr, bool child = false);
    void* create_thread(uint64_t addr, void* ctx, void* proc_obj,
                        const std::string& thread_type = "thread", bool is_suspended = false);
    void resume_thread(void* thread);
    void* get_process_peb(void* process);

    // ── Error / context ────────────────────────────────────────
    std::string get_error_info(const std::string& msg, uint64_t pc, const std::string& trace = "");
    std::string _resolve_module_offset(uint64_t addr);
    std::string _resolve_region_info(uint64_t addr);

    // ── Concrete implementations of BinaryEmulator pure virtuals ─
    std::tuple<uint64_t, size_t> get_valid_ranges(size_t size, uint64_t addr = 0) override;
    std::vector<void*> get_mem_maps() override;
    std::string get_address_tag(uint64_t ptr) override;
    void* get_address_map(uint64_t addr) override;
    void mem_reserve(size_t size, uint64_t base = 0) override;

    // ── Hardware interrupts ───────────────────────────────────
    bool _hook_interrupt(void* emu, int intnum);
};

// ── Free functions ───────────────────────────────────────────

inline std::string WindowsEmulator::normalize_mod_name(const std::string& name) {
    auto dot = name.find_last_of('.');
    std::string base = (dot != std::string::npos) ? name.substr(0, dot) : name;
    // lowercase
    for (auto& c : base) c = static_cast<char>(std::tolower(c));
    return base;
}

#endif // WINEMU_H