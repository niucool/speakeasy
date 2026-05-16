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

// ── Static trampolines for Unicorn callbacks ─────────────────
// These bridge the C callback convention to C++ member functions.

namespace {

void code_hook_trampoline(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
    auto* emu = static_cast<WindowsEmulator*>(user_data);
    emu->_hook_code_core(static_cast<void*>(uc), address, static_cast<size_t>(size));
}

void code_trace_trampoline(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
    auto* emu = static_cast<WindowsEmulator*>(user_data);
    emu->_hook_code_tracing(static_cast<void*>(uc), address, static_cast<size_t>(size));
}

void code_coverage_trampoline(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
    auto* emu = static_cast<WindowsEmulator*>(user_data);
    emu->_hook_code_coverage(static_cast<void*>(uc), address, static_cast<size_t>(size));
}

void code_debug_trampoline(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
    auto* emu = static_cast<WindowsEmulator*>(user_data);
    emu->_hook_code_debug(static_cast<void*>(uc), address, static_cast<size_t>(size));
}

bool mem_read_trampoline(uc_engine* uc, uc_mem_type type, uint64_t address,
                          int size, int64_t value, void* user_data) {
    auto* emu = static_cast<WindowsEmulator*>(user_data);
    return emu->_hook_mem_read(static_cast<void*>(uc), static_cast<int>(type),
                                address, static_cast<size_t>(size),
                                static_cast<uint64_t>(value));
}

bool mem_write_trampoline(uc_engine* uc, uc_mem_type type, uint64_t address,
                           int size, int64_t value, void* user_data) {
    auto* emu = static_cast<WindowsEmulator*>(user_data);
    return emu->_hook_mem_write(static_cast<void*>(uc), static_cast<int>(type),
                                 address, static_cast<size_t>(size),
                                 static_cast<uint64_t>(value));
}

bool mem_unmapped_trampoline(uc_engine* uc, uc_mem_type type, uint64_t address,
                              int size, int64_t value, void* user_data) {
    auto* emu = static_cast<WindowsEmulator*>(user_data);
    return emu->_hook_mem_unmapped(static_cast<void*>(uc), static_cast<int>(type),
                                    address, static_cast<size_t>(size),
                                    static_cast<uint64_t>(value));
}

bool intr_trampoline(uc_engine* uc, uint32_t intno, void* user_data) {
    auto* emu = static_cast<WindowsEmulator*>(user_data);
    return emu->_hook_interrupt(static_cast<void*>(uc), static_cast<int>(intno));
}

} // anonymous namespace

// ── Hook registration helpers ────────────────────────────────

// ── Hooks ────────────────────────────────────────────────────

void WindowsEmulator::enable_code_hook() {
    if (!tmp_code_hook && !mem_tracing_enabled) {
        _register_code_hook(reinterpret_cast<void*>(code_hook_trampoline), 1, 0);
        tmp_code_hook = reinterpret_cast<void*>(1);  // mark as registered
    }
}

void WindowsEmulator::disable_code_hook() {
    if (tmp_code_hook && emu_eng) {
        for (auto h : uc_hooks_) {
            uc_hook_del(emu_eng->get_engine(), h);
        }
        uc_hooks_.clear();
        tmp_code_hook = nullptr;
    }
}

void WindowsEmulator::set_hooks() {
    // Hooks are registered in enable_code_hook / set_mem_tracing_hooks
}

void WindowsEmulator::_set_emu_hooks() {
    if (!emu_hooks_set) {
        mem_map(EMU_RESERVE_SIZE, EMU_RETURN_ADDR, PERM_MEM_RW);
        emu_hooks_set = true;
    }
}

void WindowsEmulator::_unset_emu_hooks() {
    if (emu_hooks_set) {
        mem_unmap(EMU_RETURN_ADDR, EMU_RESERVE_SIZE);
        emu_hooks_set = false;
    }
}

void WindowsEmulator::set_mem_tracing_hooks() {
    if (mem_trace_hooks.empty()) {
        _register_code_hook(reinterpret_cast<void*>(code_trace_trampoline), 1, 0);
        _register_mem_hook(UC_HOOK_MEM_READ, reinterpret_cast<void*>(mem_read_trampoline));
        _register_mem_hook(UC_HOOK_MEM_WRITE, reinterpret_cast<void*>(mem_write_trampoline));
        _register_mem_hook(UC_HOOK_MEM_UNMAPPED, reinterpret_cast<void*>(mem_unmapped_trampoline));
        mem_trace_hooks.push_back(reinterpret_cast<void*>(1));
    }
}

bool WindowsEmulator::_module_access_hook(void* emu, uint64_t addr,
                                           size_t size, void* ctx) {
    (void)emu; (void)size; (void)ctx;
    std::string sym = get_symbol_from_address(addr);
    if (!sym.empty()) {
        auto [dll, name] = normalize_import_miss("", sym);
        handle_import_func(dll, name);
        return true;
    }
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
        set_pc(curr_run->start_addr);
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
        mem_unmap(base, sz);
    }
    tmp_maps.clear();

    // Process import data queue
    if (!impdata_queue.empty()) {
        auto imp = impdata_queue.front();
        impdata_queue.erase(impdata_queue.begin());
        auto& mod = std::get<0>(imp);
        auto& sym = std::get<1>(imp);
        auto val = std::get<2>(imp);
        handle_import_data(mod, sym, val);
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

    if (arch == speakeasy::arch::ARCH_X86) {
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
    (void)arch;
    // Set up Global Descriptor Table segment registers
    if (ptr_size == 4) {
        fs_addr = 0x7FFDE000;  // default x86 TEB address
        gs_addr = 0;
        if (emu_eng) emu_eng->reg_write(speakeasy::arch::REG_FS, fs_addr);
    } else {
        fs_addr = 0;
        gs_addr = 0x7EF00000;  // default x64 TEB address
        if (emu_eng) emu_eng->reg_write(speakeasy::arch::REG_GS, gs_addr);
    }
    return {fs_addr, gs_addr};
}

// ── Memory exception handlers ────────────────────────────────

bool WindowsEmulator::_handle_invalid_read(void* emu, uint64_t address,
                                            size_t size, uint64_t value) {
    // Check if address is in a known module
    auto* mod = get_mod_from_addr(address);
    if (mod) return true;

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
    (void)emu; (void)size; (void)value;
    std::string sym = get_symbol_from_address(address);
    if (!sym.empty()) {
        return true;  // Symbol found — let caller handle import resolution
    }
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
    auto* fm = static_cast<FileManager*>(fileman);
    if (fm) fm->file_open(path, create);
    return nullptr;
}

void* WindowsEmulator::pipe_open(const std::string& path, const std::string& mode,
                                  int num_instances, size_t out_size, size_t in_size) {
    auto* fm = static_cast<FileManager*>(fileman);
    if (fm) fm->pipe_open(path, mode, num_instances, out_size, in_size);
    return nullptr;
}

bool WindowsEmulator::does_file_exist(const std::string& path) {
    auto* fm = static_cast<FileManager*>(fileman);
    return fm ? fm->does_file_exist(path) : false;
}

void* WindowsEmulator::reg_open_key(const std::string& path, bool create) {
    auto* rm = static_cast<RegistryManager*>(regman);
    if (rm) rm->open_key(path, create);
    return nullptr;
}

void* WindowsEmulator::reg_get_key(int handle, const std::string& path) {
    (void)handle; (void)path;
    return nullptr;
}

void* WindowsEmulator::reg_create_key(const std::string& path) {
    auto* rm = static_cast<RegistryManager*>(regman);
    if (rm) rm->create_key(path);
    return nullptr;
}

std::tuple<int, void*> WindowsEmulator::create_event(const std::string& name) {
    validate_object_services("event creation");
    (void)name;
    return {0, nullptr};
}

std::tuple<int, void*> WindowsEmulator::create_mutant(const std::string& name) {
    validate_object_services("mutant creation");
    (void)name;
    return {0, nullptr};
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
void WindowsEmulator::kill_process(void* proc) {
    if (proc) {
        auto* process = static_cast<Process*>(proc);
        process->modules.clear();
        process->threads.clear();
    }
    run_complete = true;
}

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
    return nullptr; // static_cast<ObjectManager*>(om)->get_object_from_addr(addr) when ObjectManager is complete
}

void* WindowsEmulator::get_object_from_id(int id) {
    validate_object_services("object lookup by id");
    (void)id;
    return nullptr; // static_cast<ObjectManager*>(om)->get_object_from_id(id)
}

void* WindowsEmulator::get_object_from_name(const std::string& name) {
    validate_object_services("object lookup by name");
    (void)name;
    return nullptr; // static_cast<ObjectManager*>(om)->get_object_from_name(name)
}

void* WindowsEmulator::get_object_from_handle(int handle) {
    validate_object_services("object lookup by handle");
    (void)handle;
    return nullptr; // static_cast<ObjectManager*>(om)->get_object_from_handle(handle) || static_cast<FileManager*>(fileman)->get_object_from_handle(handle)
}

int WindowsEmulator::get_object_handle(void* obj) {
    validate_object_services("object handle lookup");
    (void)obj;
    return 0; // static_cast<ObjectManager*>(om)->get_handle(obj)
}

void WindowsEmulator::add_object(void* obj) {
    validate_object_services("object registration");
    (void)obj; // static_cast<ObjectManager*>(om)->add_object(obj)
}

void* WindowsEmulator::new_object(void* otype) {
    validate_object_services("object creation");
    (void)otype;
    return nullptr; // static_cast<ObjectManager*>(om)->new_object(otype)
}

// ── PE / module helpers ──────────────────────────────────────

void* WindowsEmulator::get_mod_from_addr(uint64_t addr) {
    if (curr_mod) {
        auto* pe = static_cast<PeFile*>(curr_mod);
        uint64_t base = pe->get_base();
        if (addr >= base && addr < base + pe->get_image_size())
            return curr_mod;
    }
    for (auto* m : modules) {
        auto* pe = static_cast<PeFile*>(m);
        uint64_t base = pe->get_base();
        if (addr >= base && addr < base + pe->get_image_size())
            return m;
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
        auto* pe = static_cast<PeFile*>(m);
        std::string base = pe->get_base_name();
        for (auto& c : base) c = static_cast<char>(std::tolower(c));
        if (base == nl) return m;
        std::string epath = pe->get_emu_path();
        auto pos = epath.find_last_of("/\\");
        if (pos != std::string::npos) epath = epath.substr(pos + 1);
        for (auto& c : epath) c = static_cast<char>(std::tolower(c));
        if (epath == nl) return m;
    }
    return nullptr;
}

std::vector<void*> WindowsEmulator::get_peb_modules() {
    std::vector<void*> result;
    for (auto* m : modules) {
        result.push_back(m);  // All modules visible in PEB by default
    }
    return result;
}

// ── PE initialization ───────────────────────────────────────

void WindowsEmulator::init_peb(void* user_mods, void* proc) {
    void* p = proc ? proc : curr_process;
    if (!p) return;
    auto* process = static_cast<Process*>(p);
    uint64_t peb_addr = mem_map(0x1000, 0, PERM_MEM_RW, "PEB");
    process->peb = reinterpret_cast<void*>(peb_addr);
    (void)user_mods;
}

void WindowsEmulator::init_teb(void* thread, void* peb) {
    if (!thread) return;
    auto* thr = static_cast<Thread*>(thread);
    auto* peb_obj = static_cast<Process*>(peb);
    uint64_t peb_addr = peb_obj ? reinterpret_cast<uint64_t>(peb_obj->peb) : 0;
    if (ptr_size == 4) {
        thr->init_teb(static_cast<int>(fs_addr), static_cast<int>(peb_addr));
    } else {
        thr->init_teb(static_cast<int>(gs_addr), static_cast<int>(peb_addr));
    }
}

void WindowsEmulator::init_tls(void* thread) {
    if (!thread || !curr_run) return;
    auto* thr = static_cast<Thread*>(thread);
    auto* mod = get_mod_from_addr(curr_run->start_addr);
    if (mod) {
        auto* pe = static_cast<PeFile*>(mod);
        std::string modname = pe->get_base_name();
        // TLS directory is stored in PeFile metadata during PeLoader::parse_pe
        // For now, init TLS with empty directory (callbacks are already in tls_callbacks_)
        thr->init_tls(0, modname);
    }
    (void)thr;
}

void* WindowsEmulator::load_pe(const std::string& path,
                                const std::vector<uint8_t>& data,
                                uint64_t imp_id) {
    // Use PeLoader to parse the PE file
    speakeasy::PeLoader loader(path, data);
    auto img = loader.make_image();
    img.base = imp_id;  // Override base for sentinel tracking
    return load_image(&img);
}

void* WindowsEmulator::load_image(void* image) {
    if (!image) return nullptr;

    auto* img = static_cast<speakeasy::LoadedImage*>(image);
    if (img->mapped_image.empty() && img->regions.empty())
        return nullptr;

    // Determine architecture and initialize engine if needed
    if (!emu_eng || img->arch != static_cast<int>(ptr_size * 8)) {
        int eng_arch = (img->arch == 64) ? speakeasy::arch::ARCH_AMD64
                                          : speakeasy::arch::ARCH_X86;
        if (!emu_eng) {
            // emu_eng = new EmuEngine();
            // emu_eng->init_engine(eng_arch, ...);
        }
        ptr_size = img->arch / 8;
        page_size = speakeasy::arch::PAGE_SIZE;
    }

    // Map regions and write data
    for (auto& region : img->regions) {
        size_t map_size = (region.data.size() + page_size - 1) & ~(page_size - 1ULL);
        if (map_size == 0) map_size = page_size;
        uint64_t base = region.base;
        mem_map(static_cast<uint64_t>(map_size), base, region.perms, region.name);
        if (!region.data.empty()) {
            mem_write(base, region.data);
        }
    }

    // Map the full PE image if regions are empty
    if (img->regions.empty() && !img->mapped_image.empty()) {
        size_t map_size = (img->mapped_image.size() + page_size - 1) & ~(page_size - 1ULL);
        mem_map(static_cast<uint64_t>(map_size), img->base, PERM_MEM_RWX, img->name);
        mem_write(img->base, img->mapped_image);
    }

    // Patch IAT with sentinel values for import hooking
    ensure_pe_import_hooks(img->base);

    // Register as a loaded module
    if (img->base != 0) {
        modules.push_back(reinterpret_cast<void*>(img->base));
        symbols[img->base] = {img->name, ""};
    }

    return reinterpret_cast<void*>(img->base);
}

void WindowsEmulator::ensure_pe_import_hooks(uint64_t base_addr) {
    // Read PE header from emulated memory to find import directory
    auto hdr = mem_read(base_addr, 0x1000);
    if (hdr.size() < 0x200) return;
    uint32_t pe_off = 0;
    for (int i = 0; i < 4; ++i) pe_off |= static_cast<uint32_t>(hdr[0x3C + i]) << (i * 8);
    if (pe_off + 4 > hdr.size() || hdr[pe_off] != 'P' || hdr[pe_off+1] != 'E') return;
    // Locate import directory and patch IAT entries with sentinel values
    // The IAT is typically in the .idata section; sentinel values trigger API hooks
    // For now, PE imports are resolved lazily via _module_access_hook
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

    const char* subdir = (arch == speakeasy::arch::ARCH_AMD64) ? "amd64" : "x86";
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
    // Use speakeasy::PeLoader to parse and map the PE
    if (!native_path.empty()) {
        try {
            speakeasy::PeLoader loader(native_path, std::vector<uint8_t>{});
            auto* img = new speakeasy::LoadedImage(loader.make_image());
            return load_image(img);
        } catch (...) {}
    }
    // Fallback: try using the emu_path as data source
    if (!ep.empty()) {
        try {
            speakeasy::PeLoader loader(ep, std::vector<uint8_t>{});
            auto* img = new speakeasy::LoadedImage(loader.make_image());
            return load_image(img);
        } catch (...) {}
    }
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
        if (!mc) continue;
        // For void* config entries, try to cast to a path string and load
        const char* path = static_cast<const char*>(mc);
        try {
            speakeasy::PeLoader loader(std::string(path), std::vector<uint8_t>{});
            auto* img = new speakeasy::LoadedImage(loader.make_image());
            auto* rtmod = load_image(img);
            if (rtmod) rtmods.push_back(rtmod);
        } catch (...) {}
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
    if (ptr_size == 4) {
        rv = _dispatch_seh_x86(except_code);
    } else {
        // x64: VEH (Vectored Exception Handling) — simpler than SEH
        rv = false;
    }

    // If SEH dispatch failed, try the unhandled exception filter
    if (!rv && unhandled_exception_filter != 0) {
        // Call the registered unhandled exception filter
        curr_exception_code = except_code;
        call(unhandled_exception_filter);
        rv = true;
    }

    return rv;
}

bool WindowsEmulator::_dispatch_seh_x86(uint64_t except_code) {
    // Walk the EXCEPTION_REGISTRATION chain at fs:[0]
    uint64_t seh_chain = _get_exception_list();
    if (seh_chain == 0 || seh_chain == 0xFFFFFFFF) return false;

    // Read EXCEPTION_REGISTRATION record: [next_ptr] [handler]
    uint64_t next_ptr = read_ptr(seh_chain);
    uint64_t handler = read_ptr(seh_chain + ptr_size);
    if (handler == 0 || handler == 0xFFFFFFFF) return false;

    // Call the SEH handler
    curr_exception_code = except_code;
    call(handler);  // Jump to the handler
    return true;
}

void WindowsEmulator::_continue_seh_x86() {
    // After SEH handler returns, EIP should be set by the handler
    // The handler typically calls RtlRestoreContext or similar
    set_pc(0);  // Placeholder — actual EIP from handler context
}


void WindowsEmulator::continue_seh() {
    _seh_last_fault = {0, 0};
    _seh_repeat_count = 0;
}

void WindowsEmulator::handle_import_func(const std::string& dll, const std::string& name) {
    // Dispatch to registered API handler
    symbols[0] = {dll, name};  // Register for later symbol resolution
    (void)dll; (void)name;
}

void WindowsEmulator::log_api(uint64_t pc, const std::string& api,
                               uint64_t rv, const std::vector<uint64_t>& argv) {
    if (profiler) {
        std::vector<std::string> str_argv;
        for (auto a : argv) str_argv.push_back("0x" + speakeasy::hex_str(a));
        profiler->log_api(curr_run, pc, api, reinterpret_cast<void*>(rv), str_argv);
    }
}

void WindowsEmulator::handle_import_data(const std::string& mod, const std::string& sym,
                                          uint64_t data_ptr) {
    (void)mod; (void)sym; (void)data_ptr;
}

void* WindowsEmulator::get_proc(const std::string& mod_name, const std::string& func_name) {
    (void)mod_name; (void)func_name;
    return nullptr;
}

uint64_t WindowsEmulator::add_callback(const std::string& mod_name, const std::string& func_name) {
    static uint64_t next_callback_addr = 0x102000;  // EMU_CALLBACK_RESERVE
    // Check if already registered
    for (const auto& cb : callbacks) {
        if (std::get<1>(cb) == mod_name && std::get<2>(cb) == func_name) {
            return std::get<0>(cb);
        }
    }
    uint64_t addr = next_callback_addr++;
    callbacks.push_back({addr, mod_name, func_name});
    return addr;
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
    // Normalize common import name variations
    std::string ndll = dll;
    std::string nname = name;
    // Strip ".dll" suffix
    if (ndll.size() > 4) {
        auto ext = ndll.substr(ndll.size() - 4);
        for (auto& c : ext) c = static_cast<char>(std::tolower(c));
        if (ext == ".dll") ndll = ndll.substr(0, ndll.size() - 4);
    }
    // Lowercase for matching
    for (auto& c : ndll) c = static_cast<char>(std::tolower(c));
    for (auto& c : nname) c = static_cast<char>(std::tolower(c));
    return {ndll, nname};
}

std::vector<uint8_t> WindowsEmulator::read_unicode_string(uint64_t addr) {
    std::vector<uint8_t> result;
    for (int i = 0; i < 512; ++i) {
        auto bytes = mem_read(addr + i * 2, 2);
        if (bytes.size() < 2) break;
        uint16_t ch = bytes[0] | (static_cast<uint16_t>(bytes[1]) << 8);
        if (ch == 0) break;
        result.push_back(bytes[0]);
        result.push_back(bytes[1]);
    }
    // Add null terminator
    result.push_back(0);
    result.push_back(0);
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
    _register_code_hook(reinterpret_cast<void*>(code_coverage_trampoline), 1, 0);
}

void WindowsEmulator::set_debug_hooks() {
    _register_code_hook(reinterpret_cast<void*>(code_debug_trampoline), 1, 0);
}

void WindowsEmulator::resume_thread(void* thread) {
    (void)thread;
    resume(0);  // Resume emulation at current PC
}

void* WindowsEmulator::get_process_peb(void* process) {
    void* p = process ? process : curr_process;
    if (p) {
        auto* proc = static_cast<Process*>(p);
        return proc->peb;
    }
    return nullptr;
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

// ── Run control extension ─────────────────────────────────────

void WindowsEmulator::add_run(std::shared_ptr<Run> run) {
}

// ── Bootstrap / reference counting ────────────────────────────

int WindowsEmulator::dec_ref(void* obj) {
    if (obj) {
        auto* ko = static_cast<KernelObject*>(obj);
        ko->ref_cnt--;
        return ko->ref_cnt;
    }
    return 0;
}

// ── File management wrappers ──────────────────────────────────

void* WindowsEmulator::file_get(int handle) {
    // Delegate to FileManager when fully implemented
    (void)handle;
    return nullptr;
}

bool WindowsEmulator::file_delete(const std::string& path) {
    // Delegate to FileManager when fully implemented
    (void)path;
    return false;
}

void* WindowsEmulator::pipe_get(int handle) {
    // Delegate to FileManager when fully implemented
    (void)handle;
    return nullptr;
}

void* WindowsEmulator::file_create_mapping(void* hfile, const std::string& name,
                                            size_t size, int prot) {
    auto* fm = static_cast<FileManager*>(fileman);
    if (fm) {
        uint32_t handle = fm->file_create_mapping(
            static_cast<uint32_t>(reinterpret_cast<uintptr_t>(hfile)), name, size, prot);
        (void)handle;
    }
    return nullptr;
}

// ── Manager accessors ─────────────────────────────────────────

void* WindowsEmulator::get_file_manager()    { return fileman; }
void* WindowsEmulator::get_network_manager() { return netman; }
void* WindowsEmulator::get_crypt_manager()   { return cryptman; }
void* WindowsEmulator::get_drive_manager()   { return driveman; }

// ── Registry wrappers ─────────────────────────────────────────

std::vector<std::string> WindowsEmulator::reg_get_subkeys(void* hkey) {
    (void)hkey;
    // RegistryManager::get_subkeys accepts shared_ptr<RegKey> — adapter needed
    return {};
}

void* WindowsEmulator::dev_ioctl(uint32_t ctl_code, void* in_buf,
                                  size_t in_len, void* out_buf, size_t out_len) {
    (void)in_buf; (void)in_len; (void)out_buf; (void)out_len;
    // Dispatch to kernel-mode IRP handler via IoManager
    return reinterpret_cast<void*>(static_cast<uintptr_t>(ctl_code));
}

void WindowsEmulator::_register_code_hook(void* callback, uint64_t begin, uint64_t end) {
    if (!emu_eng) return;
    uc_hook hh = 0;
    uc_err err = uc_hook_add(emu_eng->get_engine(), &hh, UC_HOOK_CODE,
                              callback, static_cast<void*>(this), begin, end);
    if (err == UC_ERR_OK) {
        uc_hooks_.push_back(hh);
    }
}

void WindowsEmulator::_register_mem_hook(int hook_type, void* callback) {
    if (!emu_eng) return;
    uc_hook hh = 0;
    uc_err err = uc_hook_add(emu_eng->get_engine(), &hh, UC_HOOK_MEM_READ,
                              callback, static_cast<void*>(this), 1, 0);
    (void)hook_type;
    if (err == UC_ERR_OK) {
        uc_hooks_.push_back(hh);
    }
}

// _get_exception_list was accidentally removed — re-adding
uint64_t WindowsEmulator::_get_exception_list() {
    uint64_t teb = (ptr_size == 4) ? fs_addr : gs_addr;
    return (teb != 0) ? read_ptr(teb) : 0;
}
