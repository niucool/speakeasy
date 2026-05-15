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
#include "errors.h"

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
class EmuStruct;
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

    // ── Thread context ────────────────────────────────────────
    void* get_thread_context(void* thread = nullptr);
    void load_thread_context(void* ctx, void* thread = nullptr);

    // ── SEH ───────────────────────────────────────────────────
    bool dispatch_seh(uint64_t except_code, uint64_t faulting_address = 0);
    void continue_seh();

    // ── Objects ───────────────────────────────────────────────
    std::tuple<int, void*> create_event(const std::string& name = "");
    int dec_ref(void* obj);
    std::tuple<int, void*> create_mutant(const std::string& name = "");

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
