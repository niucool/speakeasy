// win32.cpp
#include "win32.h"
#include "../helper.h"
#include <algorithm>
#include <cstring>
#include <sstream>
#include "../config.h"
#include "../winenv/defs/nt/ntoskrnl.h"

// Python win32.py:34
// def __init__(self, config, argv=None, debug=False, exit_event=None, gdb_port=None):
//     """User Mode Windows Emulator Class"""
// Constructor implementation
Win32Emulator::Win32Emulator(const speakeasy::SpeakeasyConfig& cfg, const std::vector<std::string>& argv,
                             bool debug, void* logger, void* exit_event)
    : WindowsEmulator(cfg, logger, exit_event, debug),
      last_error_(0), peb_addr_(0), argv_(argv) {
    com_ = std::make_shared<COM>(cfg);
    sessman_ = std::make_shared<SessionManager>(cfg);
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
    
    if (!this->argv_.empty()) {
        for (auto m : modules) {
            auto img = m->image();
            if (!img->emu_path.empty()) argv0 = img->emu_path;
            else argv0 = img->name;
        }
        out.push_back(argv0);
        out.insert(out.end(), this->argv_.begin(), this->argv_.end());
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
    last_error_ = code;
}

// Python win32.py:107
// def get_last_error(self):
//     """
//     Get the last error code for the current thread
//     """
int Win32Emulator::get_last_error() {
    return last_error_;
}

// Python win32.py:114
// def get_session_manager(self):
//     """
//     Get the session manager for the emulator. This will manage things like desktops,
//     windows, and session isolation
//     """
std::shared_ptr<SessionManager> Win32Emulator::get_session_manager() {
    return sessman_;
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
        init_processes(config_.processes);
    }
    std::vector<void*> result;
    result.reserve(processes.size());
    for (const auto& proc : processes) {
        result.push_back(proc.get());
    }
    return result;
}

// Python win32.py:140
// def init_processes(self, processes):
//     """
//     Initialize configured processes set in the emulator config
//     """
void Win32Emulator::init_processes(const std::vector<speakeasy::ProcessEntry>& processes) {
    // Python win32.py:140-160  initialize configured processes from emulator config
    for (const auto& proc : processes) {
        auto p = std::make_shared<Process>(reinterpret_cast<void*>(this));
        add_object(p);
        
        // p->name set via Process constructor
        if (proc.pid) p->id = proc.pid;
        if (!proc.base.empty()) {
            p->base = std::stoull(proc.base, nullptr, 16);
        } else {
            p->base = 0;
        }
        p->path = proc.path;
        p->session = proc.session ? proc.session : 0;
        auto pos = proc.path.find_last_of("/\\");
        p->image = (pos != std::string::npos) ? proc.path.substr(pos + 1) : proc.path;
        
        this->processes.push_back(p);
    }
}

// Python win32.py:162
// Full: Python win32.py:162
std::shared_ptr<speakeasy::RuntimeModule> Win32Emulator::load_module(const std::string& path, const std::vector<uint8_t>& data,
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
    //uint64_t import_id = 0x41410000;
    auto pe = load_pe(path, file_data);
    if (!pe) return nullptr;
    
    pe->name = mod_name_;
    pe->emu_path = emu_path;
    
    if (!arch) { 
        arch = pe->arch; 
        set_ptr_size(arch); 
    }
    
    // Set function args
    set_func_args(stack_base_, get_ret_address(), {});
    
    // Track input metadata
    if (!input_.empty()) {
        input_["image_base"] = std::to_string(pe->base);
    }
    
    return pe;
}


// Python win32.py:223
// def prepare_module_for_emulation(self, module, all_entrypoints, entry_point=None):
void Win32Emulator::prepare_module_for_emulation(std::shared_ptr<speakeasy::RuntimeModule> module, bool all_entrypoints, const std::optional<uint64_t>& entry_point) {
    if (!module) {
        stop();
        throw Win32EmuError("Module not found");
    }

    auto img = module;
    
    // Check if any TLS callbacks exist, these run before the module's entry point
    auto tls = img->get_tls_callbacks();
    for (size_t i = 0; i < tls.size(); ++i) {
        uint64_t cb_addr = tls[i];
        if (cb_addr > img->base && cb_addr < img->base + img->image_size) {
            auto run = std::make_shared<Run>();
            run->start_addr = cb_addr;
            run->type = "tls_callback_" + std::to_string(i);
            run->args_values = {img->base, static_cast<uint64_t>(DLL_PROCESS_ATTACH), 0};
            run->args = {hex_str(img->base, true), std::to_string(DLL_PROCESS_ATTACH), "0"};
            add_run(run);
        }
    }

    uint64_t ep;
    if (entry_point.has_value()) {
        ep = img->base + entry_point.value();
    } else {
        ep = img->base + img->ep;
    }

    auto run = std::make_shared<Run>();
    run->start_addr = ep;

    if (!img->is_exe()) {
        run->args_values = {img->base, static_cast<uint64_t>(DLL_PROCESS_ATTACH), 0};
        run->args = {hex_str(img->base, true), std::to_string(DLL_PROCESS_ATTACH), "0"};
        run->type = "dll_entry.DLL_PROCESS_ATTACH";
        auto* container = static_cast<Process*>(init_container_process());
        if (container) {
            for (auto& p : processes) {
                if (p.get() == container) {
                    run->process_context = p;
                    curr_process = p;
                    break;
                }
            }
        }
        if (!img->is_driver()) {
            user_modules.insert(user_modules.begin(), module);
        }
    } else {
        run->type = "module_entry";
        std::vector<uint64_t> args_vals;
        std::vector<std::string> args_strs;
        for (int i = 0; i < 4; ++i) {
            uint64_t arg_val = mem_map(8, 0, PERM_MEM_RW, "emu.module_arg_" + std::to_string(i));
            args_vals.push_back(arg_val);
            args_strs.push_back(hex_str(arg_val, true));
        }
        run->args_values = args_vals;
        run->args = args_strs;
    }

    add_run(run);

    if (all_entrypoints) {
        static const size_t MAX_EXPORTS_TO_EMULATE = 10;
        auto exports = img->get_exports();
        if (exports.size() > MAX_EXPORTS_TO_EMULATE) {
            exports.resize(MAX_EXPORTS_TO_EMULATE);
        }

        if (!exports.empty()) {
            std::vector<uint64_t> dummy_args;
            std::vector<std::string> dummy_strs;
            for (int i = 0; i < 4; ++i) {
                uint64_t arg_val = mem_map(8, 0x41420000, PERM_MEM_RW, "emu.export_arg_" + std::to_string(i));
                dummy_args.push_back(arg_val);
                dummy_strs.push_back(hex_str(arg_val, true));
            }

            for (auto& exp : exports) {
                if (exp.name == "DllMain") continue;
                auto erun = std::make_shared<Run>();
                std::string fn = exp.name.empty() ? "no_name" : exp.name;
                erun->type = "export." + fn;
                erun->start_addr = exp.address;

                if (!exp.name.empty() && exp.name.rfind("ServiceMain", 0) == 0) {
                    int char_width = get_service_main_char_width(exp.name);
                    auto res = build_service_main_args("IPRIP", {}, char_width);
                    erun->args_values = {static_cast<uint64_t>(res.first), res.second};
                    erun->args = {std::to_string(res.first), hex_str(res.second, true)};
                } else {
                    erun->args_values = dummy_args;
                    erun->args = dummy_strs;
                }
                add_run(erun);
            }
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
void Win32Emulator::run_module(std::shared_ptr<speakeasy::RuntimeModule> module, bool all_entrypoints, bool emulate_children, const std::optional<uint64_t>& entry_point) {
    prepare_module_for_emulation(module, all_entrypoints, entry_point);
    if (processes.empty()) {
        auto p = std::make_shared<Process>(this, module);
        p->path = module->emu_path;
        p->base = module->base;
        curr_process = p;
        om->add_object(p);
        processes.push_back(p);
        auto& mm = get_address_map(module->base);
        if (mm)
            mm->set_process(current_process_);
    }
    auto t = std::make_shared<Thread>(this, stack_base_, module->stack_commit);
    
    if (curr_process) 
        curr_process->threads.push_back(t);
    curr_thread = t;
    alloc_peb(curr_process);
    init_teb(t, curr_process.get());
    start();
    while (emulate_children && !child_processes.empty()) {
        auto child = child_processes.front();
        child_processes.erase(child_processes.begin());
        prepare_module_for_emulation(child->pe, all_entrypoints);
        curr_process = child;
        curr_thread = child->threads[0];  // child process thread deferred
        start();
    }
}

// Python win32.py:353
// def _init_name(self, path, data=None, filename=None):
void Win32Emulator::_init_name(const std::string& path, const std::vector<uint8_t>& data) {
    if (data.empty()) {
        // Extract filename from path (platform independent)
        size_t lastSlash = path.find_last_of("/\\");
        file_name_ = (lastSlash == std::string::npos) ? path : path.substr(lastSlash + 1);
        
        size_t lastDot = file_name_.find_last_of('.');
        mod_name_ = (lastDot == std::string::npos) ? file_name_ : file_name_.substr(0, lastDot);
    } else {
        mod_name_ = "unknown_hash";
        file_name_ = mod_name_ + ".exe";
    }
    // Extract base name
    size_t lastSlash = file_name_.find_last_of("/\\");
    bin_base_name_ = (lastSlash == std::string::npos) ? file_name_ : file_name_.substr(lastSlash + 1);
}

// Python win32.py:368
// def emulate_module(self, path):
//     """
//     Load and emulate binary from the given path
//     """
void Win32Emulator::emulate_module(const std::string& path) {
    auto mod = load_module(path, {}, true);
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
    // TODO:
    auto stack_info = alloc_stack(stack_commit);
    stack_base_ = std::get<0>(stack_info);
    auto run = std::make_shared<Run>();
    run->type = "shellcode";
    run->start_addr = sc_addr + offset;
    add_run(run);
    if (processes.empty()) {
        auto p = std::make_shared<Process>(this);
        processes.push_back(p);
        curr_process = p;
    }
    auto t = std::make_shared<Thread>(this);
    if (curr_process) curr_process->threads.push_back(t);
    curr_thread = t;
    start();
}

// Python win32.py:475
// def alloc_peb(self, proc):
//     """
//     Allocate memory for the Process Environment Block (PEB)
//     """
void Win32Emulator::alloc_peb(std::shared_ptr<Process> proc) {
    if (!proc) return;
    if (proc->is_peb_active) return;

    size_t size = proc->get_peb_ldr()->sizeof_obj();
    uint64_t res = 0;
    uint64_t actual_size = 0;
    std::tie(res, actual_size) = get_valid_ranges(size);
    mem_reserve(actual_size, res, PERM_MEM_RW, "emu.struct.PEB_LDR_DATA");
    proc->set_peb_ldr_address(static_cast<int>(res));

    auto peb = proc->get_peb();
    proc->is_peb_active = true;

    auto* peb_struct = static_cast<speakeasy::defs::nt::PEB*>(peb->get_object());
    peb_struct->ImageBaseAddress = proc->base;
    peb_struct->OSMajorVersion = config_.os_ver.major;
    peb_struct->OSMinorVersion = config_.os_ver.minor;
    peb_struct->OSBuildNumber = config_.os_ver.build;
    peb->write_back();

    _ensure_core_dlls_loaded();
    mem_map_reserve(proc->get_peb_ldr()->get_address());
    auto mods = _ordered_peb_modules();
    init_peb(mods, proc);
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
    om = std::make_shared<ObjectManager>(this);
    int my_arch = get_arch();
    this->arch = my_arch;
    _setup_gdt(my_arch);
    setup_user_shared_data();
    mem_map(EMU_RESERVE_SIZE, EMU_RESERVED, PERM_MEM_RW, "emu.reserved");
    set_ptr_size(my_arch);
    peb_addr_ = (my_arch == 32) ? fs_addr + 0x30 : gs_addr + 0x60;

    for (auto&symlink : config_.symlinks) {
        std::string link = symlink.name;
        std::string target = symlink.target;
        if (!link.empty() && !target.empty()) {
            //this->symlinks.push_back({link, target});
            om->add_symlink(link, target);
        }
    }
    //_ensure_core_dlls_loaded();
    init_sys_modules(config_.modules.system_modules);
    _init_user_modules_from_config();
    //set_hooks();
}

// Python win32.py:556
// def init_sys_modules(self, modules_config):
//     """
//     Get the system modules (e.g. drivers) that are loaded in the emulator
//     """
std::vector<std::shared_ptr<speakeasy::RuntimeModule>> Win32Emulator::init_sys_modules(const std::vector<std::shared_ptr<speakeasy::Module>>& modules_config) {
    // Delegate to base class (WindowsEmulator) which properly parses JSON config objects
    auto sys_mods = WindowsEmulator::init_sys_modules(modules_config);

    // Driver devices from config (Python win32.py:562-568)
    for (auto& modconf : modules_config) {
        // Check if this is a SystemModule with a driver
        // SystemModule inherits from Module (non-polymorphic in config); check driver field
        auto& drv_devices = modconf->path;  // placeholder  driver info is on SystemModule only
        // C++ note: SystemModule::driver.devices requires the concrete type;
        // the config modules are stored as shared_ptr<Module>, so we check for driver via name pattern
        auto sysmod =
            std::dynamic_pointer_cast<speakeasy::SystemModule>(modconf);

        for (auto& dev_info : sysmod->driver.devices) {
            auto name_it = dev_info.find("name");
            std::string dev_name = (name_it != dev_info.end()) ? name_it->second : "";
            auto* dobj = new Device(reinterpret_cast<void*>(this));
            dobj->init_device(dev_name, 0, 0, nullptr);
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
    // Python win32.py:572-587  create a process to host shellcode or DLLs
    for (auto& p : config_.processes) {
        if (p.is_main_exe) {
            std::string name = p.name.empty() ? "" : p.name;
            std::string emu_path = p.path.empty() ? "" : p.path;
            uint64_t base = 0;
            if (!p.base.empty()) {
                base = std::stoull(p.base, nullptr, 16);
            }
            std::string cmd_line = p.command_line.empty() ? "" : p.command_line;
            
            auto proc = std::make_shared<Process>((void *)this, nullptr,
                                     std::vector<std::shared_ptr<speakeasy::RuntimeModule>>{}, name, emu_path,
                                     cmd_line, base, 0);
            curr_process = proc;
            processes.push_back(proc);
            return proc.get();
        }
    }
    return nullptr;
}

std::vector<std::shared_ptr<speakeasy::RuntimeModule>> Win32Emulator::get_user_modules() {
    // Python win32.py:578-587  return loaded user module RuntimeModules
    // modules is already vector<shared_ptr<RuntimeModule>>; filter non-driver entries
    std::vector<std::shared_ptr<speakeasy::RuntimeModule>> result;
    for (auto& mod : modules) {
        if (mod && !mod->is_driver()) {
            result.push_back(mod);
        }
    }
    return result;
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
        std::shared_ptr<Process> proc = get_current_process();
        if (proc && proc->peb_ldr_data) {
            uint64_t pld_addr = proc->peb_ldr_data->get_address();
            // PEB_LDR_DATA struct size varies by arch (~45 bytes x86, ~81 x64)
            // Use a page-based range check for safety
            if (address > pld_addr && address < pld_addr + page_size) {
                mem_map_reserve(pld_addr);
                auto mods = _ordered_peb_modules();
                init_peb(mods, nullptr);
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
    if (profiler_) {
        // Record dropped files - win32 Python uses get_dropped_files()
        profiler_->record_dropped_files_event(curr_run, get_dropped_files());
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
    heap_allocs_.push_back({addr, size, heap});
    return addr;
}

std::pair<int, uint64_t> Win32Emulator::build_service_main_args(const std::string& service_name,
                                                                 const std::vector<std::string>& service_args,
                                                                 int char_width) {
    int ptr_sz = get_ptr_size();
    std::vector<std::string> args;
    args.push_back(service_name);
    args.insert(args.end(), service_args.begin(), service_args.end());

    std::string codec;
    if (char_width == 1) codec = "utf-8";
    else if (char_width == 2) codec = "utf-16le";
    else return std::make_pair(0, 0ULL);

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
    return std::make_pair(static_cast<int>(enc_args.size()), argv_ptr);
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
    // Extract basename from file_name_
    std::string base;
    auto pos = file_name_.find_last_of("/\\");
    base = (pos != std::string::npos) ? file_name_.substr(pos + 1) : file_name_;
    return cd + base;
}

// Python win32.py:194
// def _set_input_metadata(self, path, data):
void Win32Emulator::_set_input_metadata(const std::string& path, const std::vector<uint8_t>& data) {
    if (!profiler_) return;
    
    input_.clear();
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
            ext = speakeasy::to_lower(ext);
            if (ext == ".exe") pe_type = "exe";
            else pe_type = "dll";
        }
        std::string arch_str = "unknown";
        if (pe.get_ptr_size() == 8) arch_str = "x64";
        else if (pe.get_ptr_size() == 4) arch_str = "x86";
        
        std::string hash_val = pe._hash_pe(path, data);
        
        input_["path"] = path;
        input_["sha256"] = hash_val;
        input_["size"] = std::to_string(data.size());
        input_["arch"] = arch_str;
        input_["filetype"] = pe_type;
        input_["emu_version"] = get_emu_version();
        input_["os_run"] = get_osver_string();
    } catch (...) {
        input_["path"] = path;
        input_["size"] = std::to_string(data.size());
        input_["emu_version"] = get_emu_version();
        input_["os_run"] = get_osver_string();
    }
    profiler_->add_input_metadata(input_);
}

// Python win32.py:500
// def _ordered_peb_modules(self):
std::vector<std::shared_ptr<speakeasy::RuntimeModule>> Win32Emulator::_ordered_peb_modules() {
    const std::map<std::string, int> CORE_ORDER = {
        {"ntdll", 0}, {"kernel32", 1}, {"kernelbase", 2}
    };
    auto mods = get_peb_modules();
    std::vector<std::shared_ptr<speakeasy::RuntimeModule>> exe_mods;
    std::vector<std::pair<int, std::shared_ptr<speakeasy::RuntimeModule>>> core_mods;
    std::vector<std::shared_ptr<speakeasy::RuntimeModule>> other_mods;
    
    for (auto m : mods) {
        auto img = m;
        // Check if this is an EXE: not a driver and has an .exe extension or was loaded as main module
        std::string lname = speakeasy::to_lower(img->name);
        std::string lemu = speakeasy::to_lower(img->emu_path);
        
        bool is_exe_mod = false;
        if (!img->is_driver()) {
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
    
    std::vector<std::shared_ptr<speakeasy::RuntimeModule>> result = exe_mods;
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
    // Python win32.py:589-601 — find main exe from config processes, prepend to user_modules
    using speakeasy::ProcessEntry;
    using speakeasy::Module;
    
    std::shared_ptr<ProcessEntry> proc_mod;
    for (auto& p : config_.processes) {
        if (p.is_main_exe) {
            proc_mod = std::make_shared<ProcessEntry>(p);
            break;
        }
    }

    std::vector<std::shared_ptr<Module>> all_user_mods;
    if (proc_mod) {
        // Convert ProcessEntry to a Module-compatible entry
        auto mod = std::make_shared<Module>();
        mod->name = proc_mod->name;
        mod->path = proc_mod->path;
        try {
            mod->base = std::stoull(proc_mod->base, nullptr, 0);
        } catch (...) {
            mod->base = 0;
        }
        mod->image_size = 0;
        all_user_mods.push_back(mod);
        all_user_mods.insert(all_user_mods.end(),
            config_.modules.user_modules.begin(),
            config_.modules.user_modules.end());
    } else {
        all_user_mods = config_.modules.user_modules;
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
    std::map<uint64_t, std::shared_ptr<speakeasy::RuntimeModule>> modules_by_base;
    for (auto img : modules) {
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
        std::shared_ptr<speakeasy::RuntimeModule> mod = nullptr;
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
    for (auto m : modules) {
        auto img = m;
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

