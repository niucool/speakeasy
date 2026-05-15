// winemu.cpp — Windows Emulator base class implementation
//
// Maps to: speakeasy/windows/winemu.py

#include "winemu.h"
#include "binemu.h"
#include "profiler.h"
#include <algorithm>
#include <cctype>
#include <filesystem>
#include <chrono>

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
}

// ── Bootstrap ────────────────────────────────────────────────

void WindowsEmulator::advance_bootstrap_phase(BootstrapPhase phase) {
    if (static_cast<int>(phase) <= static_cast<int>(bootstrap_phase)) return;

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
        throw WindowsEmuError(reason + " requires higher bootstrap phase");
    }
}

void WindowsEmulator::bootstrap_object_services() {
    // Subclasses override
}

void WindowsEmulator::validate_object_services(const std::string& reason) {
    if (!om) throw WindowsEmuError(reason + " requires initialized object services");
}

// ── Config ───────────────────────────────────────────────────

void WindowsEmulator::_parse_config(const std::string& config) {
    BinaryEmulator::_parse_config(config);
}

std::map<std::string, std::string> WindowsEmulator::get_registry_config() {
    return registry_config;
}

// ── Hooks ────────────────────────────────────────────────────

void WindowsEmulator::enable_code_hook() {
    if (!tmp_code_hook && !mem_tracing_enabled) {
        // TODO: tmp_code_hook = add_code_hook(cb=_hook_code_core)
    }
}

void WindowsEmulator::disable_code_hook() {
    // TODO: if (tmp_code_hook) tmp_code_hook->disable();
}

void WindowsEmulator::set_hooks() {
    // TODO: subclass may override
}

void WindowsEmulator::_set_emu_hooks() {
    if (!emu_hooks_set) {
        // Reserve memory region for return/exit hooks
        // TODO: emu_eng->mem_map(EMU_RETURN_ADDR, EMU_RESERVE_SIZE);
        emu_hooks_set = true;
    }
}

void WindowsEmulator::_unset_emu_hooks() {
    if (emu_hooks_set) {
        // TODO: remap reserved region
        emu_hooks_set = false;
    }
}

void WindowsEmulator::set_mem_tracing_hooks() {
    if (mem_trace_hooks.empty()) {
        // TODO: add_code_hook(cb=_hook_code_tracing)
        // TODO: add_mem_read_hook
        // TODO: add_mem_write_hook
    }
}

bool WindowsEmulator::_module_access_hook(void* emu, uint64_t addr,
                                           size_t size, void* ctx) {
    // TODO: get symbol from address, handle import function
    return false;
}

// ── Code hook core ───────────────────────────────────────────

bool WindowsEmulator::_hook_code_core(void* emu, uint64_t addr, size_t size) {
    // SEH dispatch
    if (curr_exception_code != 0) {
        dispatch_seh(curr_exception_code);
        curr_exception_code = 0;
        disable_code_hook();
        return true;
    }

    // Restart current run
    if (restart_curr_run) {
        // TODO: set_pc(curr_run->start_addr);
        restart_curr_run = false;
        return false;
    }

    // Run complete / return hook hit
    if (addr == return_hook || run_complete) {
        on_run_complete();
        return false;
    }

    // Clean up temporary maps
    for (auto& [base, sz] : tmp_maps) {
        // TODO: mem_unmap(base, sz);
    }
    tmp_maps.clear();

    // Process import data queue
    if (!impdata_queue.empty()) {
        auto imp = impdata_queue.front();
        impdata_queue.erase(impdata_queue.begin());
        // TODO: write import data
        return true;
    }

    _set_emu_hooks();
    disable_code_hook();
    return true;
}

// ── Memory ───────────────────────────────────────────────────

EmuStruct* WindowsEmulator::cast(EmuStruct* obj,
                                  const std::vector<uint8_t>& bytez) {
    if (!obj) throw WindowsEmuError("Invalid object for cast");
    obj->from_bytes(bytez);
    return obj;
}

EmuStruct* WindowsEmulator::mem_cast(EmuStruct* obj, uint64_t addr) {
    size_t sz = obj->sizeof_obj();
    auto data = mem_read(addr, sz);
    return cast(obj, data);
}

void WindowsEmulator::mem_purge() {
    purge_memory();
}

void WindowsEmulator::setup_user_shared_data() {
    constexpr uint64_t KUSER_SHARED_X86  = 0xFFDF0000;
    constexpr uint64_t KUSER_SHARED_AMD64 = 0xFFFFF78000000000ULL;
    constexpr uint64_t KUSER_READONLY     = 0x7FFE0000;

    if (arch == ARCH_X86) {
        mem_map(page_size, KUSER_SHARED_X86, PERM_MEM_RW, "emu.struct.KUSER_SHARED_DATA");
    } else {
        mem_map(page_size, KUSER_SHARED_AMD64, PERM_MEM_RW, "emu.struct.KUSER_SHARED_DATA");
    }
    mem_map(page_size, KUSER_READONLY, PERM_MEM_RW, "emu.struct.KUSER_SHARED_DATA");
    _populate_user_shared_data(KUSER_READONLY);
}

void WindowsEmulator::_populate_user_shared_data(uint64_t base) {
    using namespace std::chrono;
    auto now = system_clock::now();
    auto dur = now.time_since_epoch();
    auto ns100 = duration_cast<nanoseconds>(dur).count() / 100 + 116444736000000000LL;

    std::vector<uint8_t> data(0x400, 0);

    // InterruptTime at offset 0x008
    write_le(data, 0x008, static_cast<uint32_t>(ns100 & 0xFFFFFFFF), 4);
    write_le(data, 0x00C, static_cast<uint32_t>(ns100 >> 32), 4);
    write_le(data, 0x010, static_cast<uint32_t>(ns100 >> 32), 4);

    // SystemTime at offset 0x014
    write_le(data, 0x014, static_cast<uint32_t>(ns100 & 0xFFFFFFFF), 4);
    write_le(data, 0x018, static_cast<uint32_t>(ns100 >> 32), 4);
    write_le(data, 0x01C, static_cast<uint32_t>(ns100 >> 32), 4);

    // OS version at offset 0x260
    write_le(data, 0x260, 6, 4);  // NtMajorVersion
    write_le(data, 0x264, 1, 4);  // NtMinorVersion
    write_le(data, 0x268, 7601, 4);  // NtBuildNumber

    mem_write(base, data);
}

std::tuple<uint64_t, uint64_t> WindowsEmulator::_setup_gdt(int arch) {
    // TODO: GDT setup
    return {0, 0};
}

// ── Memory exception handlers ────────────────────────────────

bool WindowsEmulator::_handle_invalid_read(void* emu, uint64_t address,
                                            size_t size, uint64_t value) {
    // Check if address is in a known module
    // TODO: auto* mod = get_mod_from_addr(address);
    // if (mod) return true;

    if (address >= EMU_RESERVED && address <= (EMU_RESERVED + EMU_RESERVE_SIZE)) {
        _unset_emu_hooks();
        return true;
    }

    if (dispatch_handlers) {
        bool rv = dispatch_seh(0xC0000005 /* STATUS_ACCESS_VIOLATION */, address);
        if (rv) return true;
    }

    // Fake a page mapping at the faulting address
    uint64_t fakeout = address & 0xFFFFFFFFFFFFF000ULL;
    mem_map(page_size, fakeout, PERM_MEM_RW, "emu.page.tmp", 0, false);

    tmp_maps.push_back({fakeout, page_size});
    on_run_complete();
    return true;
}

bool WindowsEmulator::_handle_prot_fetch(void* emu, uint64_t address,
                                          size_t size, uint64_t value) {
    // TODO: get symbol from address, handle import function
    return true;
}

bool WindowsEmulator::_handle_invalid_write(void* emu, uint64_t address,
                                             size_t size, uint64_t value) {
    if (address >= EMU_RESERVED && address <= (EMU_RESERVED + EMU_RESERVE_SIZE))
        return true;

    if (dispatch_handlers) {
        bool rv = dispatch_seh(0xC0000005, address);
        if (rv) return true;
    }

    uint64_t fakeout = address & 0xFFFFFFFFFFFFF000ULL;
    mem_map(page_size, fakeout, PERM_MEM_RW, "emu.page.tmp", 0, false);

    tmp_maps.push_back({fakeout, page_size});
    on_run_complete();
    return true;
}

// ── File ─────────────────────────────────────────────────────

void* WindowsEmulator::file_open(const std::string& path, bool create) {
    // Delegate to FileManager when it's initialized
    if (fileman) return nullptr; // TODO: return fileman->file_open(path, create)
    return nullptr;
}

void* WindowsEmulator::pipe_open(const std::string& path, const std::string& mode,
                                  int num_instances, size_t out_size, size_t in_size) {
    if (fileman) return nullptr; // TODO: return fileman->pipe_open(...)
    return nullptr;
}

bool WindowsEmulator::does_file_exist(const std::string& path) {
    if (fileman) return false; // TODO: return fileman->does_file_exist(path)
    return false;
}

void* WindowsEmulator::file_create_mapping(void* hfile, const std::string& name,
                                            size_t size, int prot) {
    if (fileman) return nullptr; // TODO: return fileman->file_create_mapping(...)
    return nullptr;
}

void* WindowsEmulator::file_get(int handle) { return fileman ? nullptr : nullptr; }
bool WindowsEmulator::file_delete(const std::string& path) { return fileman ? false : false; }
void* WindowsEmulator::pipe_get(int handle) { return fileman ? nullptr : nullptr; }
void* WindowsEmulator::get_file_manager() { return fileman; }

// ── Network / Crypto / Drives ────────────────────────────────

void* WindowsEmulator::get_network_manager() { return netman; }
void* WindowsEmulator::get_crypt_manager()   { return cryptman; }
void* WindowsEmulator::get_drive_manager()   { return driveman; }

// ── Registry ─────────────────────────────────────────────────

void* WindowsEmulator::reg_open_key(const std::string& path, bool create) {
    if (regman) return nullptr; // TODO: return regman->reg_open_key(path, create)
    return nullptr;
}

std::vector<std::string> WindowsEmulator::reg_get_subkeys(void* hkey) {
    if (regman) return {}; // TODO: return regman->reg_get_subkeys(hkey)
    return {};
}

void* WindowsEmulator::reg_get_key(int handle, const std::string& path) {
    if (regman) return nullptr; // TODO: return regman->reg_get_key(handle, path)
    return nullptr;
}

void* WindowsEmulator::reg_create_key(const std::string& path) {
    if (regman) return nullptr; // TODO: return regman->reg_create_key(path)
    return nullptr;
}

// ── Run control ──────────────────────────────────────────────

void WindowsEmulator::add_run(std::shared_ptr<Run> run) {
    run_queue.push_back(run);
}

std::shared_ptr<Run> WindowsEmulator::_exec_next_run() {
    if (run_queue.empty()) {
        on_emu_complete();
        return nullptr;
    }

    auto run = run_queue.front();
    run_queue.erase(run_queue.begin());

    run_complete = false;
    _seh_last_fault = {0, 0};
    _seh_repeat_count = 0;

    // reset_stack done by base class
    return _prepare_run_context(run);
}

void WindowsEmulator::call(uint64_t addr, const std::vector<std::string>& params) {

    auto run = std::make_shared<Run>();
    run->type = "call_0x" + std::to_string(addr);
    run->start_addr = addr;
    // run->args = params;

    if (run_queue.empty()) {
        add_run(run);
        start();
    } else {
        add_run(run);
    }
}

std::shared_ptr<Run> WindowsEmulator::_prepare_run_context(std::shared_ptr<Run> run) {
    curr_run = run;

    runs.push_back(curr_run);

    // Set up stack for return; subclass handles args
    uint64_t stk_ptr = get_stack_ptr();
    (void)stk_ptr;

    // Switch process context if needed
    if (run->process_context &&
        run->process_context != get_current_process()) {
        alloc_peb(run->process_context);
        set_current_process(run->process_context);
    }

    // Reset SEH state
    _seh_last_fault = {0, 0};
    _seh_repeat_count = 0;

    // Unmap reserved region if entry point is there
    if (run->start_addr >= EMU_RESERVED &&
        run->start_addr <= EMU_RESERVED_END) {
        // mem_unmap(EMU_RESERVED, EMU_RESERVE_SIZE);
        emu_hooks_set = true;
    }

    set_pc(run->start_addr);
    return run;
}

void WindowsEmulator::start() {
    if (run_queue.empty()) return;

    auto run = run_queue.front();
    run_queue.erase(run_queue.begin());

    run_complete = false;
    set_hooks();
    _set_emu_hooks();
    _prepare_run_context(run);

    // Begin emulation via engine
    if (emu_eng) {
        emu_eng->start(curr_run->start_addr, 0, 0);
    }
}

void WindowsEmulator::resume(uint64_t addr, int count) {
    if (emu_eng) {
        emu_eng->start(addr, count, 0);
    }
}

// ── Run access ───────────────────────────────────────────────

std::shared_ptr<void> WindowsEmulator::get_current_run() { return curr_run; }
void* WindowsEmulator::get_current_module() { return curr_mod; }
std::vector<void*> WindowsEmulator::get_dropped_files() { return {}; }

// ── Process / thread ─────────────────────────────────────────

std::vector<void*> WindowsEmulator::get_processes() { return processes; }
void WindowsEmulator::kill_process(void* proc) { /* TODO */ }

// ── Environment ──────────────────────────────────────────────

std::string WindowsEmulator::get_system_root() {
    auto it = env.find("systemroot");
    std::string root = (it != env.end()) ? it->second : "C:\\WINDOWS\\system32";
    if (!root.empty() && root.back() != '\\') root += '\\';
    return root;
}

std::string WindowsEmulator::get_windows_dir() {
    auto it = env.find("windir");
    std::string dir = (it != env.end()) ? it->second : "C:\\WINDOWS";
    if (!dir.empty() && dir.back() != '\\') dir += '\\';
    return dir;
}

std::string WindowsEmulator::get_cd() {
    if (cd.empty()) {
        auto it = env.find("cd");
        cd = (it != env.end()) ? it->second : "C:\\WINDOWS\\system32";
        if (!cd.empty() && cd.back() != '\\') cd += '\\';
    }
    return cd;
}

void WindowsEmulator::set_cd(const std::string& path) { cd = path; }

std::map<std::string, std::string> WindowsEmulator::get_env() { return env; }

void WindowsEmulator::set_env(const std::string& var, const std::string& val) {
    std::string key = var;
    for (auto& c : key) c = static_cast<char>(std::tolower(c));
    env[key] = val;
}

std::string WindowsEmulator::search_path(const std::string& file_name) {
    if (file_name.find('\\') != std::string::npos) return file_name;
    std::string fp = get_cd();
    if (!fp.empty() && fp.back() != '\\') fp += '\\';
    return fp + file_name;
}

// ── Object management ────────────────────────────────────────

void* WindowsEmulator::get_object_from_addr(uint64_t addr) {
    validate_object_services("object lookup by address");
    (void)addr;
    return nullptr; // om->get_object_from_addr(addr) when ObjectManager is complete
}

void* WindowsEmulator::get_object_from_id(int id) {
    validate_object_services("object lookup by id");
    (void)id;
    return nullptr; // om->get_object_from_id(id)
}

void* WindowsEmulator::get_object_from_name(const std::string& name) {
    validate_object_services("object lookup by name");
    (void)name;
    return nullptr; // om->get_object_from_name(name)
}

void* WindowsEmulator::get_object_from_handle(int handle) {
    validate_object_services("object lookup by handle");
    (void)handle;
    return nullptr; // om->get_object_from_handle(handle) || fileman->get_object_from_handle(handle)
}

int WindowsEmulator::get_object_handle(void* obj) {
    validate_object_services("object handle lookup");
    (void)obj;
    return 0; // om->get_handle(obj)
}

void WindowsEmulator::add_object(void* obj) {
    validate_object_services("object registration");
    (void)obj; // om->add_object(obj)
}

void* WindowsEmulator::new_object(void* otype) {
    validate_object_services("object creation");
    (void)otype;
    return nullptr; // om->new_object(otype)
}

// ── PE / module helpers ──────────────────────────────────────

void* WindowsEmulator::get_mod_from_addr(uint64_t addr) {
    if (curr_mod) {
        // TODO: check if addr in curr_mod range
    }
    for (auto* m : modules) {
        // TODO: check if addr in module range
    }
    return nullptr;
}

uint64_t WindowsEmulator::_alloc_sentinel() {
    static uint64_t next = virtual_mem_base + 0x10000;
    uint64_t addr = next;
    next += static_cast<uint64_t>(ptr_size > 0 ? ptr_size : 4);
    return addr;
}

void* WindowsEmulator::get_mod_by_name(const std::string& name) {
    std::string nl = name;
    for (auto& c : nl) c = static_cast<char>(std::tolower(c));

    for (auto* m : modules) {
        // TODO: match by emu_path basename or module name
        (void)m;
    }
    return nullptr;
}

std::vector<void*> WindowsEmulator::get_peb_modules() {
    std::vector<void*> result;
    for (auto* m : modules) {
        // TODO: filter by visible_in_peb
        result.push_back(m);
    }
    return result;
}

// ── PE initialization ───────────────────────────────────────

void WindowsEmulator::init_peb(void* user_mods, void* proc) {
    void* p = proc ? proc : curr_process;
    if (!p) return;
    // TODO: p->init_peb(user_mods)
    // TODO: mem_write(peb_addr, p->peb->address);
    (void)user_mods;
}

void WindowsEmulator::init_teb(void* thread, void* peb) {
    if (!thread) return;
    if (arch == ARCH_X86) {
        // TODO: thread->init_teb(fs_addr, peb->address)
    } else {
        // TODO: thread->init_teb(gs_addr, peb->address)
    }
    (void)peb;
}

void WindowsEmulator::init_tls(void* thread) {
    if (!thread || !curr_run) return;
    // TODO: get module, read TLS directory, thread->init_tls
    (void)thread;
}

void* WindowsEmulator::load_pe(const std::string& path,
                                const std::vector<uint8_t>& data,
                                uint64_t imp_id) {
    // TODO: _PeParser pe(path, data, imp_id)
    // Determine pe_type (driver/dll/exe) and arch
    // Record input metadata for profiler
    (void)path; (void)data; (void)imp_id;
    return nullptr;
}

void* WindowsEmulator::load_image(void* image) {
    if (!image) return nullptr;
    // TODO: determine arch, init engine, set up API
    // mem_map each region, mem_write data
    // patch IAT entries with sentinels
    // set section permissions
    // register module in self.modules
    return nullptr;
}

void WindowsEmulator::ensure_pe_import_hooks(uint64_t base_addr) {
    // TODO: read PE header from emulated memory
    // patch IAT entries with sentinel values
    (void)base_addr;
}

void* WindowsEmulator::get_current_thread() { return curr_thread; }
void* WindowsEmulator::get_current_process() { return curr_process; }
void WindowsEmulator::set_current_process(void* process) { curr_process = process; }
void WindowsEmulator::set_current_thread(void* thread) { curr_thread = thread; }

// ── Module loading ───────────────────────────────────────────

std::string WindowsEmulator::get_native_module_path(const std::string& mod_name) {
    std::string name = mod_name;
    for (auto& c : name) c = static_cast<char>(std::tolower(c));

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
    // TODO: PeLoader / ApiModuleLoader / DecoyLoader selection
    return nullptr;
}

std::vector<uint8_t> WindowsEmulator::get_module_data_from_emu_file(
    const std::string& file_path) {
    if (!does_file_exist(file_path)) return {};
    return {};
}

std::vector<void*> WindowsEmulator::init_environment(
    const std::vector<void*>& system_modules,
    const std::vector<void*>& user_modules) {
    (void)system_modules;
    (void)user_modules;
    return {};
}

std::vector<void*> WindowsEmulator::init_sys_modules(
    const std::vector<void*>& modules_config) {
    return _init_module_group(modules_config, 0);
}

std::vector<void*> WindowsEmulator::init_user_modules(
    const std::vector<void*>& modules_config) {
    return _init_module_group(modules_config, 0x6F000000);
}

std::vector<void*> WindowsEmulator::_init_module_group(
    const std::vector<void*>& modules_config, uint64_t default_base) {
    std::vector<void*> rtmods;
    for (auto* mc : modules_config) {
        // TODO: for each module config, choose PeLoader/ApiModuleLoader/DecoyLoader
        // Loader* loader = ...
        // auto image = loader->make_image();
        // auto* rtmod = load_image(image);
        // rtmods.push_back(rtmod);
        (void)mc;
    }
    return rtmods;
}

// ── Thread context ───────────────────────────────────────────

void* WindowsEmulator::get_thread_context(void* thread) {
    (void)thread;
    return nullptr;
}

void WindowsEmulator::load_thread_context(void* ctx, void* thread) {
    (void)ctx; (void)thread;
}

// ── SEH ──────────────────────────────────────────────────────

bool WindowsEmulator::dispatch_seh(uint64_t except_code, uint64_t faulting_address) {
    auto fault_key = std::make_tuple(prev_pc, faulting_address);
    if (fault_key == _seh_last_fault) {
        _seh_repeat_count++;
        if (_seh_repeat_count >= _SEH_MAX_REPEAT) return false;
    } else {
        _seh_last_fault = fault_key;
        _seh_repeat_count = 1;
    }

    bool rv = false;
    // TODO: x86 SEH dispatch via _dispatch_seh_x86
    // TODO: unhandled exception filter handling

    return rv;
}

void WindowsEmulator::continue_seh() {
    _seh_last_fault = {0, 0};
    _seh_repeat_count = 0;
}

// ── Objects ──────────────────────────────────────────────────

std::tuple<int, void*> WindowsEmulator::create_event(const std::string& name) {
    validate_object_services("event creation");
    // TODO: auto* evt = new_object<Event>(); evt->name = name;
    // int hnd = om->get_handle(evt);
    return {0, nullptr};
}

int WindowsEmulator::dec_ref(void* obj) {
    validate_object_services("object dereference");
    // TODO: return om->dec_ref(obj);
    (void)obj;
    return 0;
}

std::tuple<int, void*> WindowsEmulator::create_mutant(const std::string& name) {
    validate_object_services("mutant creation");
    // TODO
    (void)name;
    return {0, nullptr};
}

// ── API / import handling ───────────────────────────────────

void WindowsEmulator::handle_import_func(const std::string& dll, const std::string& name) {
    // TODO: dispatch to API handler
    (void)dll; (void)name;
}

void WindowsEmulator::log_api(uint64_t pc, const std::string& api,
                               uint64_t rv, const std::vector<uint64_t>& argv) {
    // TODO: log API call to profiler
    (void)pc; (void)api; (void)rv; (void)argv;
}

void WindowsEmulator::handle_import_data(const std::string& mod, const std::string& sym,
                                          uint64_t data_ptr) {
    (void)mod; (void)sym; (void)data_ptr;
}

void* WindowsEmulator::get_proc(const std::string& mod_name, const std::string& func_name) {
    (void)mod_name; (void)func_name;
    return nullptr;
}

void WindowsEmulator::add_callback(const std::string& mod_name, const std::string& func_name) {
    callbacks.push_back({0, mod_name, func_name});
}

std::string WindowsEmulator::get_symbol_from_address(uint64_t address) {
    auto it = symbols.find(address);
    if (it != symbols.end()) {
        return std::get<0>(it->second) + "." + std::get<1>(it->second);
    }
    return "";
}

std::tuple<std::string, std::string> WindowsEmulator::normalize_import_miss(
    const std::string& dll, const std::string& name) {
    // TODO: normalize common import name variations
    return {dll, name};
}

std::vector<uint8_t> WindowsEmulator::read_unicode_string(uint64_t addr) {
    std::vector<uint8_t> result;
    // TODO: read UTF-16 string from emulated memory
    (void)addr;
    return result;
}

void WindowsEmulator::restart_run(void* run) {
    (void)run;
    restart_curr_run = true;
}

// ── Memory hooks (additional) ───────────────────────────────

bool WindowsEmulator::_hook_mem_read(void* emu, int access, uint64_t addr,
                                      size_t size, uint64_t value) {
    (void)emu; (void)access; (void)addr; (void)size; (void)value;
    return false;
}

bool WindowsEmulator::_hook_mem_write(void* emu, int access, uint64_t addr,
                                       size_t size, uint64_t value) {
    (void)emu; (void)access; (void)addr; (void)size; (void)value;
    return false;
}

bool WindowsEmulator::_hook_mem_unmapped(void* emu, int access, uint64_t addr,
                                          size_t size, uint64_t value) {
    (void)emu; (void)access; (void)addr; (void)size; (void)value;
    return false;
}

bool WindowsEmulator::_handle_invalid_fetch(void* emu, uint64_t addr,
                                             size_t size, uint64_t value) {
    (void)emu; (void)addr; (void)size; (void)value;
    return false;
}

bool WindowsEmulator::_handle_prot_write(void* emu, uint64_t addr,
                                          size_t size, uint64_t value) {
    (void)emu; (void)addr; (void)size; (void)value;
    return false;
}

// ── Code hooks (additional) ─────────────────────────────────

bool WindowsEmulator::_hook_code_tracing(void* emu, uint64_t addr, size_t size) {
    (void)emu; (void)addr; (void)size;
    return true;
}

bool WindowsEmulator::_hook_code_coverage(void* emu, uint64_t addr, size_t size) {
    (void)emu; (void)addr; (void)size;
    return true;
}

bool WindowsEmulator::_hook_code_debug(void* emu, uint64_t addr, size_t size) {
    (void)emu; (void)addr; (void)size;
    return true;
}

void WindowsEmulator::set_coverage_hooks() {
    // TODO: coverage_hook = add_code_hook(cb=_hook_code_coverage)
}

void WindowsEmulator::set_debug_hooks() {
    // TODO: debug_hook = add_code_hook(cb=_hook_code_debug)
}

// ── SEH internals ───────────────────────────────────────────

uint64_t WindowsEmulator::_get_exception_list() {
    return 0; // TODO
}

bool WindowsEmulator::_dispatch_seh_x86(uint64_t except_code) {
    (void)except_code;
    return false; // TODO
}

std::tuple<uint64_t, uint64_t> WindowsEmulator::get_reserved_ranges() {
    return {0, 0}; // TODO
}

void WindowsEmulator::_continue_seh_x86() {
    // TODO
}

// ── Process / thread creation ───────────────────────────────

void* WindowsEmulator::create_process(const std::string& path, const std::string& cmdline,
                                       void* image, bool child) {
    validate_object_services("process creation");
    (void)path; (void)cmdline; (void)image; (void)child;
    // TODO: full implementation
    return nullptr;
}

void* WindowsEmulator::create_thread(uint64_t addr, void* ctx, void* proc_obj,
                                      const std::string& thread_type, bool is_suspended) {
    validate_object_services("thread creation");
    (void)addr; (void)ctx; (void)proc_obj; (void)thread_type; (void)is_suspended;
    // TODO: full implementation
    return nullptr;
}

void WindowsEmulator::resume_thread(void* thread) {
    (void)thread;
    // TODO: resume thread execution
}

void* WindowsEmulator::get_process_peb(void* process) {
    (void)process;
    return nullptr; // TODO
}

// ── Error / context ─────────────────────────────────────────

std::string WindowsEmulator::get_error_info(const std::string& msg, uint64_t pc,
                                             const std::string& trace) {
    (void)trace;
    return msg + " at 0x" + hex_str(pc);
}

std::string WindowsEmulator::_resolve_module_offset(uint64_t addr) {
    (void)addr;
    return "";
}

std::string WindowsEmulator::_resolve_region_info(uint64_t addr) {
    (void)addr;
    return "";
}

// ── Concrete BinaryEmulator overrides ────────────────────────

std::tuple<uint64_t, size_t> WindowsEmulator::get_valid_ranges(size_t size, uint64_t addr) {
    (void)size; (void)addr;
    return {0, 0};
}

std::vector<void*> WindowsEmulator::get_mem_maps() {
    return {};
}

std::string WindowsEmulator::get_address_tag(uint64_t ptr) {
    (void)ptr;
    return "";
}

void* WindowsEmulator::get_address_map(uint64_t addr) {
    (void)addr;
    return nullptr;
}

void WindowsEmulator::mem_reserve(size_t size, uint64_t base) {
    (void)size; (void)base;
}

// ── Hardware interrupts ──────────────────────────────────────

bool WindowsEmulator::_hook_interrupt(void* emu, int intnum) {
    (void)emu; (void)intnum;
    return false;
}