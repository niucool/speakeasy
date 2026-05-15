// winemu.cpp — Windows Emulator base class implementation
//
// Maps to: speakeasy/windows/winemu.py

#include "winemu.h"
#include <algorithm>
#include <cctype>
#include <filesystem>

namespace fs = std::filesystem;

// ── Constructor ──────────────────────────────────────────────

WindowsEmulator::WindowsEmulator(const std::string& config, void* logger,
                                  void* evt, bool dbg)
    : BinaryEmulator(config, logger), debug(dbg), arch(0),
      page_size(4096), ptr_size(0),
      max_runs(100), kernel_mode(false), virtual_mem_base(0x50000),
      mem_tracing_enabled(false), tmp_code_hook(nullptr),
      run_complete(false), emu_complete(false),
      curr_exception_code(0), prev_pc(0), unhandled_exception_filter(0),
      fs_addr(0), gs_addr(0) {

    _parse_config(config);

    // return_hook = EMU_RETURN_ADDR;
    // exit_hook  = EXIT_RETURN_ADDR;
}

// ── Bootstrap ────────────────────────────────────────────────

void WindowsEmulator::advance_bootstrap_phase(BootstrapPhase phase) {
    if (static_cast<int>(phase) <= static_cast<int>(bootstrap_phase)) return;

    // Allowed transitions
    static const std::map<BootstrapPhase, std::set<BootstrapPhase>> transitions = {
        {BootstrapPhase::INITIALIZED,       {BootstrapPhase::ENGINE_API_READY}},
        {BootstrapPhase::ENGINE_API_READY,  {BootstrapPhase::OBJECT_MANAGER_READY,
                                              BootstrapPhase::FULL_SETUP_READY}},
        {BootstrapPhase::OBJECT_MANAGER_READY, {BootstrapPhase::FULL_SETUP_READY}},
        {BootstrapPhase::FULL_SETUP_READY,  {}}
    };

    auto it = transitions.find(bootstrap_phase);
    if (it != transitions.end() && it->second.count(phase)) {
        bootstrap_phase = phase;
        return;
    }
    throw WindowsEmuError("Invalid bootstrap transition");
}

void WindowsEmulator::validate_bootstrap_phase(BootstrapPhase phase,
                                                const std::string& reason) {
    if (static_cast<int>(bootstrap_phase) < static_cast<int>(phase)) {
        throw WindowsEmuError(
            reason + " requires higher bootstrap phase");
    }
}

void WindowsEmulator::bootstrap_object_services() {
    // Base implementation: no-op. Subclasses override.
}

void WindowsEmulator::validate_object_services(const std::string& reason) {
    if (!om) {
        throw WindowsEmuError(reason + " requires initialized object services");
    }
}

// ── Config ───────────────────────────────────────────────────

void WindowsEmulator::_parse_config(const std::string& config) {
    BinaryEmulator::_parse_config(config);
    // cd = this->config.current_dir;
    // command_line = this->config.command_line;
}

std::map<std::string, std::string> WindowsEmulator::get_registry_config() {
    return registry_config;
}

// ── Hooks ────────────────────────────────────────────────────

void WindowsEmulator::enable_code_hook() {
    // TODO: tmp_code_hook = add_code_hook(cb=_hook_code_core)
}

void WindowsEmulator::disable_code_hook() {
    // TODO
}

void WindowsEmulator::set_hooks() {
    // TODO: set emu-level hooks
}

void WindowsEmulator::_set_emu_hooks() {
    // TODO
}

void WindowsEmulator::_unset_emu_hooks() {
    // TODO
}

void WindowsEmulator::set_mem_tracing_hooks() {
    // TODO
}

bool WindowsEmulator::_module_access_hook(void* emu, uint64_t addr,
                                           size_t size, void* ctx) {
    // TODO
    return false;
}

// ── Memory ───────────────────────────────────────────────────

EmuStruct* WindowsEmulator::cast(EmuStruct* obj,
                                  const std::vector<uint8_t>& bytez) {
    // TODO
    return obj;
}

EmuStruct* WindowsEmulator::mem_cast(EmuStruct* obj, uint64_t addr) {
    // TODO
    return obj;
}

void WindowsEmulator::mem_purge() {
    // TODO
}

void WindowsEmulator::setup_user_shared_data() {
    // TODO
}

std::tuple<uint64_t, uint64_t> WindowsEmulator::_setup_gdt(int arch) {
    // TODO
    return {0, 0};
}

// ── File ─────────────────────────────────────────────────────

void* WindowsEmulator::file_open(const std::string& path, bool create) {
    // TODO
    return nullptr;
}

void* WindowsEmulator::pipe_open(const std::string& path, const std::string& mode,
                                  int num_instances, size_t out_size, size_t in_size) {
    return nullptr;
}

bool WindowsEmulator::does_file_exist(const std::string& path) {
    return false;
}

void* WindowsEmulator::file_create_mapping(void* hfile, const std::string& name,
                                            size_t size, int prot) {
    return nullptr;
}

void* WindowsEmulator::file_get(int handle) { return nullptr; }
bool WindowsEmulator::file_delete(const std::string& path) { return false; }
void* WindowsEmulator::pipe_get(int handle) { return nullptr; }
void* WindowsEmulator::get_file_manager() { return fileman; }

// ── Network / Crypto / Drives ────────────────────────────────

void* WindowsEmulator::get_network_manager() { return netman; }
void* WindowsEmulator::get_crypt_manager()   { return cryptman; }
void* WindowsEmulator::get_drive_manager()   { return driveman; }

// ── Registry ─────────────────────────────────────────────────

void* WindowsEmulator::reg_open_key(const std::string& path, bool create) {
    return nullptr;
}

std::vector<std::string> WindowsEmulator::reg_get_subkeys(void* hkey) {
    return {};
}

void* WindowsEmulator::reg_get_key(int handle, const std::string& path) {
    return nullptr;
}

void* WindowsEmulator::reg_create_key(const std::string& path) {
    return nullptr;
}

// ── Run control ──────────────────────────────────────────────

void WindowsEmulator::add_run(std::shared_ptr<Run> run) {
    runs.push_back(run);
}

std::shared_ptr<Run> WindowsEmulator::_exec_next_run() {
    if (run_queue.empty()) return nullptr;
    auto run = run_queue.front();
    run_queue.erase(run_queue.begin());
    return _exec_run(run);
}

void WindowsEmulator::call(uint64_t addr, const std::vector<std::string>& params) {
    // TODO
}

std::shared_ptr<Run> WindowsEmulator::_exec_run(std::shared_ptr<Run> run) {
    curr_run = run;
    // TODO: actually execute
    return run;
}

void WindowsEmulator::start() {
    // TODO
}

void WindowsEmulator::resume(uint64_t addr, int count) {
    // TODO
}

// ── Run access ───────────────────────────────────────────────

std::shared_ptr<void> WindowsEmulator::get_current_run() {
    return curr_run;
}

void* WindowsEmulator::get_current_module() {
    return curr_mod;
}

std::vector<void*> WindowsEmulator::get_dropped_files() {
    return {};
}

// ── Process / thread ─────────────────────────────────────────

std::vector<void*> WindowsEmulator::get_processes() {
    return processes;
}

void WindowsEmulator::kill_process(void* proc) {
    // TODO
}

void* WindowsEmulator::get_current_thread() { return curr_thread; }
void* WindowsEmulator::get_current_process() { return curr_process; }
void WindowsEmulator::set_current_process(void* process) { curr_process = process; }
void WindowsEmulator::set_current_thread(void* thread) { curr_thread = thread; }

// ── Module loading ───────────────────────────────────────────

std::string WindowsEmulator::get_native_module_path(const std::string& mod_name) {
    std::string name = mod_name;
    for (auto& c : name) c = static_cast<char>(std::tolower(c));

    // Determine decoy directory by architecture
    const char* subdir = (arch == ARCH_AMD64) ? "amd64" : "x86";
    fs::path decoy_path = fs::path("secpp") / "winenv" / "decoys" / subdir;

    if (fs::exists(decoy_path)) {
        for (const auto& entry : fs::directory_iterator(decoy_path)) {
            if (!entry.is_regular_file()) continue;
            std::string fn = entry.path().filename().string();
            std::string base = fn;
            auto dot = base.find_last_of('.');
            if (dot != std::string::npos) base = base.substr(0, dot);
            for (auto& c : base) c = static_cast<char>(std::tolower(c));
            if (base == name) return entry.path().string();
        }
    }
    return "";
}

void* WindowsEmulator::load_library(const std::string& mod_name) {
    std::string lib = normalize_mod_name(mod_name);

    // TODO: check existing module
    // auto* existing = get_mod_by_name(lib);
    // if (existing) return existing->base;

    if (!modules_always_exist) return nullptr;

    return load_module_by_name(lib);
}

void* WindowsEmulator::load_module_by_name(const std::string& name,
                                            const std::string& emu_path,
                                            uint64_t base) {
    if (base == 0) base = 0x6F000000;

    std::string ep = emu_path;
    if (ep.empty()) {
        ep = cd.empty() ? "C:\\Windows\\system32\\" : cd;
        ep += name + ".dll";
    }

    std::string native_path = get_native_module_path(name);
    // TODO: PeLoader / ApiModuleLoader / DecoyLoader
    return nullptr;
}

std::vector<uint8_t> WindowsEmulator::get_module_data_from_emu_file(
    const std::string& file_path) {
    if (!does_file_exist(file_path)) return {};
    // TODO
    return {};
}

std::vector<void*> WindowsEmulator::init_environment(
    const std::vector<void*>& system_modules,
    const std::vector<void*>& user_modules) {
    auto sm = system_modules;
    auto um = user_modules;
    // TODO
    return {};
}

std::vector<void*> WindowsEmulator::init_sys_modules(
    const std::vector<void*>& modules_config) {
    return {};
}

std::vector<void*> WindowsEmulator::init_user_modules(
    const std::vector<void*>& modules_config) {
    return {};
}

// ── Thread context ───────────────────────────────────────────

void* WindowsEmulator::get_thread_context(void* thread) {
    // TODO
    return nullptr;
}

void WindowsEmulator::load_thread_context(void* ctx, void* thread) {
    // TODO
}

// ── SEH ──────────────────────────────────────────────────────

bool WindowsEmulator::dispatch_seh(uint64_t except_code, uint64_t faulting_address) {
    // Check for repeated faults at same location
    auto fault_key = std::make_tuple(prev_pc, faulting_address);
    if (fault_key == _seh_last_fault) {
        _seh_repeat_count++;
        if (_seh_repeat_count >= _SEH_MAX_REPEAT) return false;
    } else {
        _seh_last_fault = fault_key;
        _seh_repeat_count = 1;
    }

    bool rv = false;
    // TODO: x86 SEH dispatch
    // TODO: unhandled exception filter

    return rv;
}

void WindowsEmulator::continue_seh() {
    _seh_last_fault = {0, 0};
    _seh_repeat_count = 0;
}

// ── Objects ──────────────────────────────────────────────────

std::tuple<int, void*> WindowsEmulator::create_event(const std::string& name) {
    validate_object_services("event creation");
    // TODO
    return {0, nullptr};
}

int WindowsEmulator::dec_ref(void* obj) {
    validate_object_services("object dereference");
    // TODO
    return 0;
}

std::tuple<int, void*> WindowsEmulator::create_mutant(const std::string& name) {
    validate_object_services("mutant creation");
    // TODO
    return {0, nullptr};
}

// ── Hardware interrupts ──────────────────────────────────────

bool WindowsEmulator::_hook_interrupt(void* emu, int intnum) {
    // TODO
    return false;
}
