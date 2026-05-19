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
        j["base_addr"] = proc.base;
        j["path"] = proc.path;
        j["pid"] = proc.pid;
        j["command_line"] = proc.command_line;
        j["is_main_exe"] = proc.is_main_exe;
        config_processes.push_back(j);
    }
    for (const auto& mod : cfg.modules.system_modules) {
        nlohmann::json j;
        j["name"] = mod.name;
        j["base_addr"] = mod.base;
        j["path"] = mod.path;
        config_system_modules.push_back(j);
    }
    for (const auto& mod : cfg.modules.user_modules) {
        nlohmann::json j;
        j["name"] = mod.name;
        j["base_addr"] = mod.base;
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
// Full: Python win32.py:162
speakeasy::LoadedImage* Win32Emulator::load_module(const std::string& path, const std::vector<uint8_t>& data,
                                 bool first_time_setup) {
    _init_name(path, data);
    
    // Read data from file if not provided
    std::vector<uint8_t> file_data = data;
    std::string resolved_path = path;
    if (file_data.empty()) {
        FILE* fp = fopen(path.c_str(), "rb");
        if (fp) {
            fseek(fp, 0, SEEK_END);
            long sz = ftell(fp);
            fseek(fp, 0, SEEK_SET);
            if (sz > 0) {
                file_data.resize(sz);
                fread(file_data.data(), 1, sz, fp);
            }
            fclose(fp);
        }
    }
    
    // Set up emu path and register file
    std::string emu_path = _make_emu_path(path, file_data);
    if (fileman) fileman->add_existing_file(emu_path, file_data);
    
    // Set input metadata
    _set_input_metadata(path, file_data);
    
    // Load PE
    uint64_t import_id = 0x41410000;
    speakeasy::LoadedImage* pe = load_pe(path, file_data, import_id);
    if (!pe) return nullptr;
    
    pe->name = mod_name;
    pe->emu_path = emu_path;
    
    if (!arch) { 
        arch = pe->arch; 
        set_ptr_size(arch); 
    }
    
    // Set function args
    set_func_args(stack_base, get_ret_address(), {});
    
    // Track input metadata
    if (!input.empty()) {
        input["image_base"] = std::to_string(pe->base);
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
void Win32Emulator::alloc_peb(Process* proc) {
    if (!proc) return;
    if (proc->is_peb_active) return;

    // Map PEB memory (0x1000 bytes)
    uint64_t peb_addr_val = mem_map(0x1000, 0, PERM_MEM_RW, "emu.struct.PEB");
    proc->peb = reinterpret_cast<void*>(peb_addr_val);
    this->peb_addr = peb_addr_val;

    proc->is_peb_active = true;

    // Write PEB structure fields
    int psz = get_ptr_size();
    if (psz == 0) psz = (ptr_size == 4) ? 4 : 8;

    // +0x002: BeingDebug = 0 (1 byte)
    std::vector<uint8_t> debug_byte = {0x00};
    mem_write(peb_addr_val + 0x002, debug_byte);

    // +0x00C: Ldr = proc->peb_ldr_data (pointer)
    uint64_t ldr_ptr = reinterpret_cast<uint64_t>(proc->peb_ldr_data);
    size_t ptr_sz = (psz == 4) ? 4 : 8;
    std::vector<uint8_t> ldr_bytes(ptr_sz);
    for (size_t i = 0; i < ptr_sz; i++) {
        ldr_bytes[i] = static_cast<uint8_t>((ldr_ptr >> (i * 8)) & 0xFF);
    }
    mem_write(peb_addr_val + 0x00C, ldr_bytes);

    // +0x010 (x86) or +0x020 (x64): ProcessParameters (set to 0 for now)
    uint64_t pp_offset = (psz == 4) ? 0x010 : 0x020;
    std::vector<uint8_t> pp_bytes(ptr_sz, 0);
    mem_write(peb_addr_val + pp_offset, pp_bytes);

    // +0x018: SessionId = 1 (4 bytes, int32)
    std::vector<uint8_t> sid_bytes = {0x01, 0x00, 0x00, 0x00};
    mem_write(peb_addr_val + 0x018, sid_bytes);
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
    int my_arch = get_arch();
    _setup_gdt(my_arch);
    setup_user_shared_data();
    set_ptr_size(this->arch);
    peb_addr = (my_arch == 32) ? fs_addr + 0x30 : gs_addr + 0x60;

    if (stack_commit > 0) {
        auto stack_info = alloc_stack(stack_commit);
        stack_base = std::get<0>(stack_info);
    }

    if (first_time_setup) {
        _ensure_core_dlls_loaded();
        init_sys_modules(config_system_modules);
        _init_user_modules_from_config();
        set_hooks();
    }
}

// Python win32.py:556
// def init_sys_modules(self, modules_config):
//     """
//     Get the system modules (e.g. drivers) that are loaded in the emulator
//     """
std::vector<void*> Win32Emulator::init_sys_modules(const std::vector<nlohmann::json>& modules_config) {
    // Delegate to base class (WindowsEmulator) which properly parses JSON config objects
    auto sys_mods = WindowsEmulator::init_sys_modules(modules_config);

    // Handle driver devices from config (Python win32.py:562-568)
    for (auto& modconf : modules_config) {
        auto drv_it = modconf.find("driver");
        if (drv_it != modconf.end() && !drv_it->is_null()) {
            auto devs_it = drv_it->find("devices");
            if (devs_it != drv_it->end() && devs_it->is_array()) {
                for (auto& dev : *devs_it) {
                    std::string name = dev.value("name", "");
                    auto* dobj = new Device(this);
                    dobj->init_device(name, 0, 0, nullptr);
                    // Device objects tracked by ObjectManager if needed
                }
            }
        }
    }

    return sys_mods;
}

// Python win32.py:572
// def init_container_process(self):
//     """
//     Create a process to be used to host shellcode or DLLs
//     """
void* Win32Emulator::init_container_process() {
    for (auto& p : config_processes) {
        if (p.value("is_main_exe", false)) {
            std::string name = p.value("name", "");
            std::string emu_path = p.value("path", "");
            uint64_t base = p.value("base_addr", uint64_t(0));
            // Handle string hex base (e.g. "0x10000")
            if (p["base_addr"].is_string()) {
                std::string base_str = p["base_addr"].get<std::string>();
                base = std::stoull(base_str, nullptr, 0);
            }
            std::string cmd_line = p.value("command_line", "");

            auto* proc = new Process(this, nullptr, {}, name, emu_path, cmd_line, (int)base, 0);
            return proc;
        }
    }
    return nullptr;
}

std::vector<void*> Win32Emulator::get_user_modules() {
    // Generate the decoy user module list
    if (user_modules.size() < 2) {
        // Check if we have a host process configured
        nlohmann::json proc_mod;
        for (auto& p : config_processes) {
            if (user_modules.empty() && p.value("is_main_exe", false)) {
                proc_mod = p;
                break;
            }
        }
        
        if (!proc_mod.empty()) {
            std::vector<nlohmann::json> all_user_mods;
            all_user_mods.push_back(proc_mod);
            all_user_mods.insert(all_user_mods.end(), config_user_modules.begin(), config_user_modules.end());
            auto user_modules_result = init_user_modules(all_user_mods);
            user_modules.insert(user_modules.end(), user_modules_result.begin(), user_modules_result.end());
        } else {
            auto user_modules_result = init_user_modules(config_user_modules);
            user_modules.insert(user_modules.end(), user_modules_result.begin(), user_modules_result.end());
        }
        
        // Add sample to user modules list if it is a dll (not an exe)
        if (!modules.empty()) {
            auto* img = static_cast<speakeasy::LoadedImage*>(modules[0]);
            bool is_exe_mod = false;
            if (!img->is_driver) {
                std::string lemu = img->emu_path;
                for (auto& c : lemu) c = (char)tolower(c);
                if (lemu.size() >= 4 && lemu.substr(lemu.size() - 4) == ".exe")
                    is_exe_mod = true;
                std::string lname = img->name;
                for (auto& c : lname) c = (char)tolower(c);
                if (lname.size() >= 4 && lname.substr(lname.size() - 4) == ".exe")
                    is_exe_mod = true;
            }
            if (!is_exe_mod) {
                user_modules.push_back(modules[0]);
            }
        }
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
    // Check if invalid read falls within PEB LDR data range (needs re-init)
    if (access == INVALID_MEM_READ) {
        Process* proc = get_current_process();
        if (proc && proc->peb_ldr_data) {
            uint64_t pld_addr = reinterpret_cast<uint64_t>(proc->peb_ldr_data);
            // PEB_LDR_DATA struct size varies by arch (~45 bytes x86, ~81 x64)
            // Use a page-based range check for safety
            if (address > pld_addr && address < pld_addr + page_size) {
                mem_map_reserve(pld_addr);
                auto mods = _ordered_peb_modules();
                init_peb(&mods);
                return true;
            }
        }
    }
    return WindowsEmulator::_hook_mem_unmapped(emu, access, address, size, value);
}

// Python win32.py:623
// def set_hooks(self):
//     """Set the emulator callbacks"""
void Win32Emulator::set_hooks() {
    WindowsEmulator::set_hooks();
    set_mem_tracing_hooks();
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
// Python win32.py:657
void Win32Emulator::on_run_complete() {
    run_complete = true;
    if (curr_run) {
        curr_run->ret_val = reinterpret_cast<void*>(static_cast<uintptr_t>(get_return_val()));
    }
    if (profiler) {
        // Record dropped files - win32 Python uses get_dropped_files()
        profiler->record_dropped_files_event(curr_run, get_dropped_files());
        _capture_memory_layout();
    }
    _exec_next_run();
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
    int ptr_sz = get_ptr_size();
    std::vector<std::string> args;
    args.push_back(service_name);
    args.insert(args.end(), service_args.begin(), service_args.end());

    std::string codec;
    if (char_width == 1) codec = "utf-8";
    else if (char_width == 2) codec = "utf-16le";
    else return 0;

    std::vector<std::vector<uint8_t>> enc_args;
    size_t total_str_size = 0;
    for (auto& arg : args) {
        std::string null_term = arg + "\x00";
        if (codec == "utf-16le") {
            std::vector<uint8_t> bytes;
            for (char c : null_term) {
                bytes.push_back((uint8_t)c);
                bytes.push_back(0);
            }
            enc_args.push_back(bytes);
        } else {
            enc_args.push_back(std::vector<uint8_t>(null_term.begin(), null_term.end()));
        }
        total_str_size += enc_args.back().size();
    }

    size_t ptr_count = enc_args.size() + 1;
    size_t total_size = ptr_count * ptr_sz + total_str_size;
    uint64_t argv_ptr = mem_map(total_size, 0x41420000, PERM_MEM_RW, "emu.service_main_argv");

    uint64_t str_ptr = argv_ptr + (ptr_count * ptr_sz);
    for (size_t i = 0; i < enc_args.size(); i++) {
        write_ptr(argv_ptr + (i * ptr_sz), str_ptr);
        mem_write(str_ptr, enc_args[i]);
        str_ptr += enc_args[i].size();
    }
    write_ptr(argv_ptr + (enc_args.size() * ptr_sz), 0);
    return (int)enc_args.size();
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
    (void)path; (void)data;
    std::string cd = get_cd();
    if (!cd.empty() && cd.back() != '\\') cd += '\\';
    // Extract basename from file_name
    std::string base;
    auto pos = file_name.find_last_of("/\\");
    base = (pos != std::string::npos) ? file_name.substr(pos + 1) : file_name;
    return cd + base;
}

// Python win32.py:194
// def _set_input_metadata(self, path, data):
void Win32Emulator::_set_input_metadata(const std::string& path, const std::vector<uint8_t>& data) {
    if (!profiler) return;
    
    input.clear();
    try {
        PeFile pe(path, data, IMPORT_HOOK_ADDR, 4, "", true);
        std::string pe_type = "unknown";
        if (pe.is_driver()) {
            pe_type = "driver";
        } else {
            // Use path extension to guess dll vs exe
            std::string ext;
            auto dot = path.find_last_of('.');
            if (dot != std::string::npos) ext = path.substr(dot);
            for (auto& c : ext) c = (char)tolower(c);
            if (ext == ".exe") pe_type = "exe";
            else pe_type = "dll";
        }
        std::string arch_str = "unknown";
        if (pe.get_ptr_size() == 8) arch_str = "x64";
        else if (pe.get_ptr_size() == 4) arch_str = "x86";
        
        std::string hash_val = pe._hash_pe(path, data);
        
        input["path"] = path;
        input["sha256"] = hash_val;
        input["size"] = std::to_string(data.size());
        input["arch"] = arch_str;
        input["filetype"] = pe_type;
        input["emu_version"] = get_emu_version();
        input["os_run"] = get_osver_string();
    } catch (...) {
        input["path"] = path;
        input["size"] = std::to_string(data.size());
        input["emu_version"] = get_emu_version();
        input["os_run"] = get_osver_string();
    }
    profiler->add_input_metadata(input);
}

// Python win32.py:500
// def _ordered_peb_modules(self):
std::vector<void*> Win32Emulator::_ordered_peb_modules() {
    const std::map<std::string, int> CORE_ORDER = {
        {"ntdll", 0}, {"kernel32", 1}, {"kernelbase", 2}
    };
    auto mods = get_peb_modules();
    std::vector<void*> exe_mods;
    std::vector<std::pair<int, void*>> core_mods;
    std::vector<void*> other_mods;
    
    for (void* m : mods) {
        auto* img = static_cast<speakeasy::LoadedImage*>(m);
        // Check if this is an EXE: not a driver and has an .exe extension or was loaded as main module
        std::string lname = img->name;
        for (auto& c : lname) c = (char)tolower(c);
        std::string lemu = img->emu_path;
        for (auto& c : lemu) c = (char)tolower(c);
        
        bool is_exe_mod = false;
        if (!img->is_driver) {
            if (lemu.size() >= 4 && lemu.substr(lemu.size() - 4) == ".exe")
                is_exe_mod = true;
            if (lname.size() >= 4 && lname.substr(lname.size() - 4) == ".exe")
                is_exe_mod = true;
        }
        
        if (is_exe_mod) {
            exe_mods.push_back(m);
            continue;
        }
        
        std::string bn = lname;
        if (bn.empty()) {
            auto pos = lemu.find_last_of("/\\");
            std::string base = (pos != std::string::npos) ? lemu.substr(pos + 1) : lemu;
            auto dot = base.find_last_of('.');
            bn = (dot != std::string::npos) ? base.substr(0, dot) : base;
        } else {
            auto dot = bn.find_last_of('.');
            bn = (dot != std::string::npos) ? bn.substr(0, dot) : bn;
        }
        
        auto it = CORE_ORDER.find(bn);
        if (it != CORE_ORDER.end()) {
            core_mods.push_back({it->second, m});
        } else {
            other_mods.push_back(m);
        }
    }
    
    std::sort(core_mods.begin(), core_mods.end(),
              [](const auto& a, const auto& b) { return a.first < b.first; });
    
    std::vector<void*> result = exe_mods;
    for (auto& cm : core_mods) result.push_back(cm.second);
    result.insert(result.end(), other_mods.begin(), other_mods.end());
    return result;
}

// Python win32.py:523
// def _ensure_core_dlls_loaded(self):
void Win32Emulator::_ensure_core_dlls_loaded() {
    const std::vector<std::string> CORE_DLLS = {"ntdll", "kernel32", "kernelbase"};
    for (auto& dll : CORE_DLLS) {
        if (!get_mod_by_name(dll)) {
            load_module_by_name(dll);
        }
    }
}

// Python win32.py:589
// def _init_user_modules_from_config(self):
void Win32Emulator::_init_user_modules_from_config() {
    nlohmann::json proc_mod;
    for (auto& p : config_processes) {
        if (p.value("is_main_exe", false)) {
            proc_mod = p;
            break;
        }
    }
    std::vector<nlohmann::json> all_user_mods;
    if (!proc_mod.empty()) {
        all_user_mods.push_back(proc_mod);
        all_user_mods.insert(all_user_mods.end(), config_user_modules.begin(), config_user_modules.end());
    } else {
        all_user_mods = config_user_modules;
    }
    init_user_modules(all_user_mods);
}

// Python win32.py:670
// def _capture_memory_layout(self):
//     """
//     Capture current memory layout and loaded modules for the run report.
//     """
void Win32Emulator::_capture_memory_layout() {
    if (!curr_run) return;
    const std::string EXCLUDED_TAG_PREFIXES[] = {"emu.stack", "api.heap", "emu.process_heap"};
    
    auto prot_to_string = [](uint32_t prot) -> std::string {
        if (prot == 0) return "---";
        std::string s;
        s += (prot & PERM_MEM_READ) ? 'r' : '-';
        s += (prot & PERM_MEM_WRITE) ? 'w' : '-';
        s += (prot & PERM_MEM_EXEC) ? 'x' : '-';
        return s;
    };
    
    // Build modules_by_base map
    std::map<uint64_t, speakeasy::LoadedImage*> modules_by_base;
    for (void* m : modules) {
        auto* img = static_cast<speakeasy::LoadedImage*>(m);
        if (img->image_size > 0) {
            modules_by_base[img->base] = img;
        }
    }
    
    auto mmaps = MemoryManager::get_mem_maps();
    
    for (auto& mm : mmaps) {
        std::string prot = prot_to_string(mm->get_prot());
        uint64_t mm_base = mm->get_base();
        uint64_t mm_size = mm->get_size();
        std::string tag = mm->get_tag();
        
        auto mod_it = modules_by_base.find(mm_base);
        speakeasy::LoadedImage* mod = nullptr;
        if (mod_it != modules_by_base.end() && tag.find("emu.module.") == 0) {
            mod = mod_it->second;
        }
        
        if (mod && !mod->sections.empty()) {
            std::string mod_name = mod->name.empty() ? "unknown" : mod->name;
            
            // Headers region
            uint32_t first_section_rva = mod->sections[0].virtual_address;
            uint64_t hdr_size = (first_section_rva > 0 && first_section_rva < mm_size) 
                                ? first_section_rva : mm_size;
            std::string hdr_tag = "emu.module." + mod_name + ".headers.0x" + 
                                  std::to_string(mm_base);
            
            std::map<std::string,std::string> hdr_dict;
            hdr_dict["tag"] = hdr_tag;
            hdr_dict["address"] = std::to_string(mm_base);
            hdr_dict["size"] = std::to_string(hdr_size);
            hdr_dict["prot"] = "r--";
            hdr_dict["is_free"] = mm->is_free() ? "true" : "false";
            curr_run->memory_regions.push_back(hdr_dict);
            
            // Section regions
            for (auto& sect : mod->sections) {
                uint64_t sec_addr = (uint64_t)sect.virtual_address + mm_base;
                std::string sec_prot = prot_to_string(sect.perms);
                std::string sec_tag = "emu.module." + mod_name + "." + sect.name + 
                                      ".0x" + std::to_string(sec_addr);
                std::map<std::string,std::string> sec_dict;
                sec_dict["tag"] = sec_tag;
                sec_dict["address"] = std::to_string(sec_addr);
                sec_dict["size"] = std::to_string((uint64_t)sect.virtual_size);
                sec_dict["prot"] = sec_prot;
                sec_dict["is_free"] = mm->is_free() ? "true" : "false";
                curr_run->memory_regions.push_back(sec_dict);
            }
        } else {
            std::map<std::string,std::string> region_dict;
            region_dict["tag"] = tag;
            region_dict["address"] = std::to_string(mm_base);
            region_dict["size"] = std::to_string(mm_size);
            region_dict["prot"] = prot;
            region_dict["is_free"] = mm->is_free() ? "true" : "false";
            curr_run->memory_regions.push_back(region_dict);
        }
    }
    
    // Add loaded modules
    for (void* m : modules) {
        auto* img = static_cast<speakeasy::LoadedImage*>(m);
        if (img->image_size == 0) continue;
        std::string mod_name = img->name;
        if (mod_name.empty()) {
            auto pos = img->emu_path.find_last_of("/\\");
            mod_name = (pos != std::string::npos) ? img->emu_path.substr(pos + 1) : img->emu_path;
            if (mod_name.empty()) mod_name = "unknown";
        }
        
        std::vector<std::map<std::string,std::string>> segments;
        for (auto& sect : img->sections) {
            std::map<std::string,std::string> seg;
            seg["name"] = sect.name;
            seg["address"] = std::to_string((uint64_t)sect.virtual_address + img->base);
            seg["size"] = std::to_string((uint64_t)sect.virtual_size);
            seg["prot"] = prot_to_string(sect.perms);
            segments.push_back(seg);
        }
        
        std::map<std::string,std::string> mod_entry;
        mod_entry["name"] = mod_name;
        mod_entry["path"] = img->emu_path;
        mod_entry["base"] = std::to_string(img->base);
        mod_entry["size"] = std::to_string(img->image_size);
        mod_entry["segments"] = ""; // segments stored separately above
        curr_run->loaded_modules.push_back(mod_entry);
    }
}

