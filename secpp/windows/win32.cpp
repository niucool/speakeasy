// win32.cpp
#include "win32.h"
#include <algorithm>
#include <cstring>
#include <sstream>
#include "../config.h"

// Python win32.py:34
// def __init__(self, config, argv=None, debug=False, exit_event=None, gdb_port=None):
//     """User Mode Windows Emulator Class"""
// Constructor implementation
Win32Emulator::Win32Emulator(const speakeasy::SpeakeasyConfig& cfg, const std::vector<std::string>& argv,
                             bool debug, void* logger, void* exit_event)
    : WindowsEmulator(cfg, logger, exit_event, debug),
      last_error(0), peb_addr(0), argv(argv), sessman(nullptr), 
      com(nullptr), stack_base(0) {
    // Populate from typed config
    for (const auto& proc : cfg.processes) {
        nlohmann::json j;
        j["name"] = proc.name;
        j["base_addr"] = proc.base_addr;
        j["path"] = proc.path;
        j["pid"] = proc.pid;
        j["command_line"] = proc.command_line;
        j["is_main_exe"] = proc.is_main_exe;
        config_processes.push_back(j);
    }
    for (const auto& mod : cfg.modules.system_modules) {
        nlohmann::json j;
        j["name"] = mod.name;
        j["base_addr"] = mod.base_addr;
        j["path"] = mod.path;
        config_system_modules.push_back(j);
    }
    for (const auto& mod : cfg.modules.user_modules) {
        nlohmann::json j;
        j["name"] = mod.name;
        j["base_addr"] = mod.base_addr;
        j["path"] = mod.path;
        config_user_modules.push_back(j);
    }
}

// Python win32.py:44
// def get_argv(self):
//     """
//     Get command line arguments (if any) that are being passed
//     to the emulated process. (e.g. main(argv))
//     """
std::vector<std::string> Win32Emulator::get_argv() {
    std::vector<std::string> out;
    std::string argv0 = "";
    
    if (!this->argv.empty()) {
        for (auto* m : modules) {
            auto* img = static_cast<speakeasy::LoadedImage*>(m);
            if (!img->emu_path.empty()) argv0 = img->emu_path;
            else argv0 = img->name;
        }
        out.push_back(argv0);
        out.insert(out.end(), this->argv.begin(), this->argv.end());
    } else if (!command_line.empty()) {
        std::istringstream iss(command_line);
        std::string token;
        while (iss >> token) out.push_back(token);
        if (out.empty()) out.push_back(command_line);
    }
    return out;
}

// Python win32.py:100
// def set_last_error(self, code):
//     """
//     Set the last error code for the current thread
//     """
void Win32Emulator::set_last_error(int code) {
    last_error = code;
}

// Python win32.py:107
// def get_last_error(self):
//     """
//     Get the last error code for the current thread
//     """
int Win32Emulator::get_last_error() {
    return last_error;
}

// Python win32.py:114
// def get_session_manager(self):
//     """
//     Get the session manager for the emulator. This will manage things like desktops,
//     windows, and session isolation
//     """
SessionManager* Win32Emulator::get_session_manager() {
    return sessman;
}

// Python win32.py:121
// def add_vectored_exception_handler(self, first, handler):
//     """
//     Add a vectored exception handler that will be executed on an exception
//     """
void Win32Emulator::add_vectored_exception_handler(bool first, uint64_t handler) {
    // Check if handler already exists
    if (std::find(veh_handlers.begin(), veh_handlers.end(), 
                  reinterpret_cast<void*>(handler)) == veh_handlers.end()) {
        veh_handlers.push_back(reinterpret_cast<void*>(handler));
    }
}

// Python win32.py:128
// def remove_vectored_exception_handler(self, handler):
//     """
//     Remove a vectored exception handler
//     """
void Win32Emulator::remove_vectored_exception_handler(uint64_t handler) {
    auto it = std::find(veh_handlers.begin(), veh_handlers.end(), 
                        reinterpret_cast<void*>(handler));
    if (it != veh_handlers.end()) {
        veh_handlers.erase(it);
    }
}

// Python win32.py:135
// def get_processes(self):
std::vector<void*> Win32Emulator::get_processes() {
    if (processes.size() <= 1) {
        init_processes(config_processes);
    }
    return std::vector<void*>(processes.begin(), processes.end());
}

// Python win32.py:140
// def init_processes(self, processes):
//     """
//     Initialize configured processes set in the emulator config
//     """
void Win32Emulator::init_processes(const std::vector<nlohmann::json>& processes) {
    for (const auto& proc : processes) {
        auto name = proc.value("name", "");
        auto path = proc.value("path", "");
        uint64_t base = proc.value("base_addr", 0ULL);
        int pid = proc.value("pid", 0);
        int session = proc.value("session", 0);
        auto pos = path.find_last_of("/\\");
        auto image = (pos != std::string::npos) ? path.substr(pos + 1) : path;
        auto* p = new Process(this);
        // p->name = name;  // protected
        p->path = path;
        p->base = base;
        p->id = pid;
        p->session = session;
        p->image = image;
        this->processes.push_back(p);
    }
}

// Python win32.py:162
// def load_module(self, path=None, data=None, filename=None):
speakeasy::LoadedImage* Win32Emulator::load_module(const std::string& path, const std::vector<uint8_t>& data,
                                 bool first_time_setup) {
    _init_name(path, data);
    uint64_t import_id = 0x41410000;
    speakeasy::LoadedImage* pe = load_pe(path, data, import_id);
    if (!pe) return nullptr;
    if (!arch) { 
        arch = pe->arch; 
        set_ptr_size(arch); 
    }
    return pe;
}


// Python win32.py:223
// def prepare_module_for_emulation(self, module, all_entrypoints, entry_point=None):
void Win32Emulator::prepare_module_for_emulation(speakeasy::LoadedImage* module, bool all_entrypoints) {
    if (!module) return;
    auto* img = static_cast<speakeasy::LoadedImage*>(module);
    auto tls = img->tls_callbacks;
    for (size_t i = 0; i < tls.size(); ++i) {
        uint64_t cb_addr = tls[i];
        if (cb_addr > img->base && cb_addr < img->base + img->image_size) {
            auto run = std::make_shared<Run>();
            run->start_addr = cb_addr;
            run->type = "tls_callback_" + std::to_string(i);
            add_run(run);
        }
    }
    auto run = std::make_shared<Run>();
    run->start_addr = img->base + img->ep;
    run->type = img->is_driver ? "driver_entry" : "module_entry";
    if (!img->is_driver) user_modules.insert(user_modules.begin(), module);
    add_run(run);
    if (all_entrypoints) {
        static const size_t MAX_EXPORTS = 100;
        auto exports = img->exports;
        if (exports.size() > MAX_EXPORTS) exports.resize(MAX_EXPORTS);
        for (auto& exp : exports) {
            if (exp.name == "DllMain") continue;
            auto erun = std::make_shared<Run>();
            erun->type = "export." + exp.name;
            erun->start_addr = exp.address;
            add_run(erun);
        }
    }
}


// Python win32.py:293
// def run_module(self, module, all_entrypoints=False, emulate_children=False, entry_point=None):
//     """
//     Begin emulating a previously loaded module
//
//     Arguments:
//         module: Module to emulate
//     """
void Win32Emulator::run_module(speakeasy::LoadedImage* module, bool all_entrypoints, bool emulate_children) {
    prepare_module_for_emulation(module, all_entrypoints);
    if (processes.empty()) {
        auto* p = new Process(this, module);
        p->path = module->emu_path;
        p->base = module->base;
        curr_process = p;
        processes.push_back(p);
    }
    auto* t = new Thread(this);
    
    if (curr_process) 
        curr_process->threads.push_back(*t);
    curr_thread = t;
    alloc_peb(curr_process);
    init_teb(t, curr_process);
    start();
    while (emulate_children && !child_processes.empty()) {
        auto child = child_processes.front();
        child_processes.erase(child_processes.begin());
        prepare_module_for_emulation((speakeasy::LoadedImage *)child, all_entrypoints);
        curr_process = static_cast<Process*>(child);
        curr_thread = nullptr;  // child process thread deferred
        start();
    }
}

// Python win32.py:353
// def _init_name(self, path, data=None, filename=None):
void Win32Emulator::_init_name(const std::string& path, const std::vector<uint8_t>& data) {
    if (data.empty()) {
        // Extract filename from path (platform independent)
        size_t lastSlash = path.find_last_of("/\\");
        file_name = (lastSlash == std::string::npos) ? path : path.substr(lastSlash + 1);
        
        size_t lastDot = file_name.find_last_of('.');
        mod_name = (lastDot == std::string::npos) ? file_name : file_name.substr(0, lastDot);
    } else {
        mod_name = "unknown_hash";
        file_name = mod_name + ".exe";
    }
    // Extract base name
    size_t lastSlash = file_name.find_last_of("/\\");
    bin_base_name = (lastSlash == std::string::npos) ? file_name : file_name.substr(lastSlash + 1);
}

// Python win32.py:368
// def emulate_module(self, path):
//     """
//     Load and emulate binary from the given path
//     """
void Win32Emulator::emulate_module(const std::string& path) {
    speakeasy::LoadedImage* mod = load_module(path, {}, true);
    if (mod) 
        run_module(mod);
}

// Python win32.py:375
// def load_shellcode(self, path, arch, data=None, filename=None):
uint64_t Win32Emulator::load_shellcode(const std::string& path, const std::string& arch,
                                       const std::vector<uint8_t>& data) {
    _init_name(path, data);
    this->arch = (arch == "x64" || arch == "amd64") ? 64 : 32;
    std::vector<uint8_t> sc = data;
    std::string sc_hash = "unknown_hash";
    uint64_t sc_addr = mem_map(sc.size(), 0ULL, PERM_MEM_RW, "emu.shellcode." + sc_hash);
    if (!sc.empty()) mem_write(sc_addr, sc);
    return sc_addr;
}

// Python win32.py:418
// def run_shellcode(self, sc_addr, stack_commit=0x4000, offset=0):
//     """
//     Begin emulating position independent code (i.e. shellcode) to prepare for emulation
//     """
void Win32Emulator::run_shellcode(uint64_t sc_addr, size_t stack_commit, size_t offset) {
    auto stack_info = alloc_stack(stack_commit);
    stack_base = std::get<0>(stack_info);
    auto run = std::make_shared<Run>();
    run->type = "shellcode";
    run->start_addr = sc_addr + offset;
    add_run(run);
    if (processes.empty()) {
        auto* p = new Process(this);
        processes.push_back(p);
        curr_process = p;
    }
    auto* t = new Thread();
    
    
    if (curr_process) static_cast<Process*>(curr_process)->threads.push_back(*t);
    curr_thread = t;
    start();
}

// Python win32.py:475
// def alloc_peb(self, proc):
//     """
//     Allocate memory for the Process Environment Block (PEB)
//     """
void Win32Emulator::alloc_peb(void* proc) {
    if (!proc) return;
    auto* p = static_cast<Process*>(proc);
    if (p->is_peb_active) return;
    p->is_peb_active = true;
    size_t peb_size = 0x1000;
    auto [res, sz] = get_valid_ranges(peb_size, 0);
    // mem_reserve for PEB deferred
    p->peb = reinterpret_cast<void*>(res);
}

// Python win32.py:529
// def set_unhandled_exception_handler(self, handler_addr):
//     """
//     Establish a handler for unhandled exceptions that occur during emulation
//     """
void Win32Emulator::set_unhandled_exception_handler(uint64_t handler_addr) {
    unhandled_exception_filter = handler_addr;
}

// Python win32.py:535
// def setup(self):
void Win32Emulator::setup(size_t stack_commit, bool first_time_setup) {
    (void)stack_commit; (void)first_time_setup;
    int my_arch = get_arch();
    _setup_gdt(my_arch);
    setup_user_shared_data();
    set_ptr_size(this->arch);
    peb_addr = (my_arch == 32) ? fs_addr + 0x30 : gs_addr + 0x60;
}

// Python win32.py:556
// def init_sys_modules(self, modules_config):
//     """
//     Get the system modules (e.g. drivers) that are loaded in the emulator
//     """
std::vector<void*> Win32Emulator::init_sys_modules(const std::vector<nlohmann::json>& modules_config) {
    std::vector<void*> sys_mods;
    
    // for (auto& modconf : modules_config) {
    //     // DecoyModule creation deferred
    //     // w32common.DecoyModule mod;
    //     // mod.name = modconf["name"];
    //     // uint64_t base = modconf.value("base_addr", 0);
    //     // if (base.is_string()) {
    //     //     base = std::stoull(base.get<std::string>(), nullptr, 16);
    //     // }
    //     // mod.decoy_base = base;
    //     // mod.decoy_path = modconf["path"];
    //     // 
    //     // auto drv = modconf.find("driver");
    //     // if (drv != modconf.end()) {
    //     //     auto devs = drv->find("devices");
    //     //     if (devs != drv->end()) {
    //     //         for (auto& dev : devs->get<std::vector<nlohmann::json>>()) {
    //     //             std::string name = dev.value("name", "");
    //     //             Device* dobj = static_cast<Device*>(new_object("Device"));
    //     //             dobj->name = name;
    //     //         }
    //     //     }
    //     // }
    //     // 
    //     // sys_mods.push_back(mod);
    // }
    
    return sys_mods;
}

// Python win32.py:572
// def init_container_process(self):
//     """
//     Create a process to be used to host shellcode or DLLs
//     """
void* Win32Emulator::init_container_process() {
    // for (auto& p : config_processes) {
    //     if (p.value("is_main_exe", false)) {
    //         std::string name = p.value("name", "");
    //         std::string emu_path = p.value("path", "");
    //         uint64_t base = p.value("base_addr", 0);
    //         if (base.is_string()) {
    //             base = std::stoull(base.get<std::string>(), nullptr, 0);
    //         }
    //         std::string cmd_line = p.value("command_line", "");
    //         
    //         // Process creation deferred
    //         // Process* proc = new Process(this, name=name,
    //         //                             path=emu_path, base=base, cmdline=cmd_line);
    //         // return proc;
    //     }
    // }
    return nullptr;
}

std::vector<void*> Win32Emulator::get_user_modules() {
    // Generate the decoy user module list
    if (user_modules.size() < 2) {
        // Check if we have a host process configured
        nlohmann::json proc_mod;
        // for (auto& p : config_processes) {
        //     if (user_modules.empty() && p.value("is_main_exe", false)) {
        //         proc_mod = p;
        //         break;
        //     }
        // }
        // 
        // if (!proc_mod.empty()) {
        //     std::vector<nlohmann::json> all_user_mods;
        //     all_user_mods.push_back(proc_mod);
        //     all_user_mods.insert(all_user_mods.end(), config_user_modules.begin(), config_user_modules.end());
        //     auto user_modules_result = init_user_modules(all_user_mods);
        //     user_modules.insert(user_modules.end(), user_modules_result.begin(), user_modules_result.end());
        // } else {
        //     auto user_modules_result = init_user_modules(config_user_modules);
        //     user_modules.insert(user_modules.end(), user_modules_result.begin(), user_modules_result.end());
        // }
        // 
        // // add sample to user modules list if it is a dll
        // if (!modules.empty() && !std::get<0>(modules[0])->is_exe()) {
        //     user_modules.push_back(std::get<0>(modules[0]));
        // }
    }
    
    return user_modules;
}

// Python win32.py:603
// def exit_process(self):
//     """
//     An emulated binary is attempted to terminate its current process.
//     Signal that the run has finished.
//     """
void Win32Emulator::exit_process() {
    enable_code_hook();
    run_complete = true;
}

// Python win32.py:611
// def _hook_mem_unmapped(self, emu, access, address, size, value):
bool Win32Emulator::_hook_mem_unmapped(void* emu, int access, uint64_t address, 
                                      size_t size, uint64_t value, void* user_data) {
    // memory unmapped hook routed to base class
    // std::string _access = emu_eng.mem_access.get(access);
    // 
    // if (_access == "INVALID_MEM_READ") {
    //     void* p = get_current_process();
    //     void* pld = p->get_peb_ldr();
    //     if (address > pld->address && address < (pld->address + pld->sizeof())) {
    //         mem_map_reserve(pld->address);
    //         auto user_mods = get_user_modules();
    //         init_peb(user_mods);
    //         return;
    //     }
    // }
    // return WindowsEmulator::_hook_mem_unmapped(emu, access, address, size, value, user_data);
    return false;
}

// Python win32.py:623
// def set_hooks(self):
//     """Set the emulator callbacks"""
void Win32Emulator::set_hooks() {
    WindowsEmulator::set_hooks();
    set_mem_tracing_hooks();
}

void Win32Emulator::add_run(std::shared_ptr<Run> run) {
    WindowsEmulator::add_run(run);
}


void Win32Emulator::init_teb(void* thread, void* peb) {
    WindowsEmulator::init_teb(thread, peb);
}

void Win32Emulator::start() {
    WindowsEmulator::start();
}

std::vector<uint8_t> Win32Emulator::mem_read(uint64_t addr, size_t size) {
    return WindowsEmulator::mem_read(addr, size);
}

void Win32Emulator::mem_write(uint64_t addr, const std::vector<uint8_t>& data) {
    WindowsEmulator::mem_write(addr, data);
}

std::tuple<uint64_t, uint64_t> Win32Emulator::alloc_stack(size_t size) {
    return WindowsEmulator::alloc_stack(size);
}

// Python win32.py:637
// def stop(self):
void Win32Emulator::stop() {
    run_complete = true;
    // _unset_emu_hooks();
    // unset_hooks();
    WindowsEmulator::stop();
}

// Python win32.py:643
// def on_emu_complete(self):
//     """
//     Called when all runs have completed emulation
//     """
void Win32Emulator::on_emu_complete() {
    if (!emu_complete) { emu_complete = true; stop(); }
}

// Python win32.py:657
// def on_run_complete(self):
//     """
//     Clean up after a run completes. This function will pop the
//     next run from the run queue and emulate it.
//     """
void Win32Emulator::on_run_complete() {
    run_complete = true;
}

// Python win32.py:808
// def heap_alloc(self, size, heap="None"):
//     """
//     Allocate a memory chunk and add it to the "heap"
//     """
uint64_t Win32Emulator::heap_alloc(size_t size, const std::string& heap) {
    uint64_t addr = mem_map(size, 0ULL, PERM_MEM_RW, "api.heap." + heap);
    heap_allocs.push_back({addr, size, heap});
    return addr;
}

// Python win32.py:61
// def build_service_main_args(self, service_name, service_args=None, char_width=1):
int Win32Emulator::build_service_main_args(const std::string& service_name,
                                           const std::vector<std::string>& service_args,
                                           int char_width) {
    // STUB: Not yet implemented
    (void)service_name; (void)service_args; (void)char_width;
    return 0;
}

// Python win32.py:93
// def get_service_main_char_width(self, module, export_name):
int Win32Emulator::get_service_main_char_width(const std::string& export_name) {
    // STUB: Not yet implemented
    if (!export_name.empty() && export_name.back() == 'A') return 1;
    if (!export_name.empty() && export_name.back() == 'W') return 2;
    return 2;
}

// Python win32.py:188
// def _make_emu_path(self, path, data):
std::string Win32Emulator::_make_emu_path(const std::string& path, const std::vector<uint8_t>& data) {
    // STUB: Not yet implemented
    (void)data;
    return path;
}

// Python win32.py:194
// def _set_input_metadata(self, path, data):
void Win32Emulator::_set_input_metadata(const std::string& path, const std::vector<uint8_t>& data) {
    // STUB: Not yet implemented
    (void)path; (void)data;
}

// Python win32.py:500
// def _ordered_peb_modules(self):
std::vector<void*> Win32Emulator::_ordered_peb_modules() {
    // STUB: Not yet implemented
    return {};
}

// Python win32.py:523
// def _ensure_core_dlls_loaded(self):
void Win32Emulator::_ensure_core_dlls_loaded() {
    // STUB: Not yet implemented
}

// Python win32.py:589
// def _init_user_modules_from_config(self):
void Win32Emulator::_init_user_modules_from_config() {
    // STUB: Not yet implemented
}

// Python win32.py:670
// def _capture_memory_layout(self):
//     """
//     Capture current memory layout and loaded modules for the run report.
//     """
void Win32Emulator::_capture_memory_layout() {
    // STUB: Not yet implemented
}

void* Win32Emulator::get_address_map(uint64_t) { return nullptr; }
std::tuple<uint64_t, size_t> Win32Emulator::get_valid_ranges(size_t, uint64_t) { return {0,0}; }
uint64_t Win32Emulator::mem_map(uint64_t n, uint64_t base, uint32_t perms, const std::string& tag) {
    return MemoryManager::mem_map(n, base, perms, tag);
}
