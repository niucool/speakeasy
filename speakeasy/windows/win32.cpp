// win32.cpp
#include "win32.h"
#include <algorithm>
#include <cstring>
#include <sstream>

// Constructor implementation
Win32Emulator::Win32Emulator(const nlohmann::json& config, const std::vector<std::string>& argv,
                             bool debug, void* logger, void* exit_event)
    : WindowsEmulator(config, logger, exit_event, debug),
      last_error(0), peb_addr(0), argv(argv), sessman(nullptr), 
      com(nullptr), stack_base(0) {
    
    // Initialize member variables from config
    // TODO: Parse config values properly
    if (config.contains("command_line")) {
        command_line = config["command_line"];
    }
    
    // TODO: Initialize other config values
}

std::vector<std::string> Win32Emulator::get_argv() {
    std::vector<std::string> out;
    std::string argv0 = "";
    
    if (!this->argv.empty()) {
        for (const auto& m : modules) {
            // TODO: Access PE object and check if it's an exe
            // void* pe = std::get<0>(m);
            std::string emu_path = std::get<2>(m);
            // TODO: Check if PE is exe
            // if (pe->is_exe()) {
                argv0 = emu_path;
            // }
        }
        out.push_back(argv0);
        out.insert(out.end(), this->argv.begin(), this->argv.end());
    } else if (!command_line.empty()) {
        // TODO: Implement shlex.split equivalent
        // out = shlex.split(command_line, posix=false);
        out.push_back(command_line);
    }
    return out;
}

void Win32Emulator::set_last_error(int code) {
    if (curr_thread) {
        // TODO: Cast curr_thread to appropriate type and call set_last_error
        // curr_thread->set_last_error(code);
    }
}

int Win32Emulator::get_last_error() {
    if (curr_thread) {
        // TODO: Cast curr_thread to appropriate type and call get_last_error
        // return curr_thread->get_last_error();
    }
    return 0;
}

SessionManager* Win32Emulator::get_session_manager() {
    return sessman;
}

void Win32Emulator::add_vectored_exception_handler(bool first, uint64_t handler) {
    // Check if handler already exists
    if (std::find(veh_handlers.begin(), veh_handlers.end(), 
                  reinterpret_cast<void*>(handler)) == veh_handlers.end()) {
        veh_handlers.push_back(reinterpret_cast<void*>(handler));
    }
}

void Win32Emulator::remove_vectored_exception_handler(uint64_t handler) {
    auto it = std::find(veh_handlers.begin(), veh_handlers.end(), 
                        reinterpret_cast<void*>(handler));
    if (it != veh_handlers.end()) {
        veh_handlers.erase(it);
    }
}

std::vector<void*> Win32Emulator::get_processes() {
    if (processes.size() <= 1) {
        init_processes(config_processes);
    }
    return processes;
}

void Win32Emulator::init_processes(const std::vector<nlohmann::json>& processes) {
    for (const auto& proc : processes) {
        // TODO: Create Process object
        // Process* p = new Process(this);
        // add_object(p);
        // 
        // p->name = proc.value("name", "");
        // int new_pid = proc.value("pid", 0);
        // if (new_pid) {
        //     p->pid = new_pid;
        // }
        // 
        // uint64_t base = proc.value("base_addr", 0);
        // if (base.is_string()) {
        //     base = std::stoull(base.get<std::string>(), nullptr, 16);
        // }
        // p->base = base;
        // p->path = proc.value("path", "");
        // p->session = proc.value("session", 0);
        // p->image = ntpath.basename(p->path);
        // 
        // processes.push_back(p);
    }
}

void* Win32Emulator::load_module(const std::string& path, const std::vector<uint8_t>& data,
                                 bool first_time_setup) {
    _init_name(path, data);
    
    // TODO: Load PE
    // void* pe = load_pe(path, data, w32common.IMPORT_HOOK_ADDR);
    // 
    // int disasm_mode;
    // if (pe->arch == _arch.ARCH_X86) {
    //     disasm_mode = cs.CS_MODE_32;
    // } else if (pe->arch == _arch.ARCH_AMD64) {
    //     disasm_mode = cs.CS_MODE_64;
    // } else {
    //     throw Win32EmuError("Unsupported architecture: %s", pe->arch);
    // }
    // 
    // if (!arch) {
    //     arch = pe->arch;
    //     set_ptr_size(arch);
    // }
    // 
    // // No need to initialize the engine and Capstone again
    // if (first_time_setup) {
    //     emu_eng.init_engine(_arch.ARCH_X86, pe->arch);
    //     if (!disasm_eng) {
    //         disasm_eng = cs.Cs(cs.CS_ARCH_X86, disasm_mode);
    //     }
    // }
    // 
    // api = WindowsApi(this);
    // 
    // std::string cd = get_cd();
    // if (!cd.empty() && cd.back() != '\\') {
    //     cd += '\\';
    // }
    // std::string emu_path = cd + file_name;
    // 
    // std::vector<uint8_t> module_data = data;
    // if (data.empty()) {
    //     // TODO: Read file data
    //     // std::ifstream f(path, std::ios::binary);
    //     // f.seekg(0, std::ios::end);
    //     // size_t size = f.tellg();
    //     // f.seekg(0, std::ios::beg);
    //     // module_data.resize(size);
    //     // f.read(reinterpret_cast<char*>(module_data.data()), size);
    // }
    // fileman->add_existing_file(emu_path, module_data);
    // 
    // // Strings the initial buffer so that we can detect decoded strings later on
    // if (profiler && do_strings) {
    //     profiler->strings["ansi"] = [a[1] for a in get_ansi_strings(module_data)];
    //     profiler->strings["unicode"] = [u[1] for u in get_unicode_strings(module_data)];
    // }
    // 
    // // Set the emulated path
    // std::string emu_path_final = "";
    // cd = get_cd();
    // if (!cd.empty()) {
    //     if (cd.back() != '\\') {
    //         cd += '\\';
    //     }
    //     emu_path_final = cd + os.path.basename(file_name);
    // }
    // 
    // pe->set_emu_path(emu_path_final);
    // 
    // // Handle memory allocation and module loading
    // // TODO: Implement the complex memory handling logic
    // 
    // mem_map(pe->image_size, base=base, tag='emu.module.%s' % (mod_name));
    // modules.push_back(std::make_tuple(pe, ranges, emu_path));
    // mem_write(pe->base, pe->mapped_image);
    // 
    // setup(first_time_setup=first_time_setup);
    // 
    // if (!stack_base) {
    //     auto stack_info = alloc_stack(pe->OPTIONAL_HEADER.SizeOfStackReserve or 0x12000);
    //     stack_base = std::get<0>(stack_info);
    // }
    // set_func_args(stack_base, return_hook);
    // 
    // // Init imported data
    // for (auto& [addr, imp] : pe->imports) {
    //     std::string mn = std::get<0>(imp);
    //     std::string fn = std::get<1>(imp);
    //     auto [mod, eh] = api->get_data_export_handler(mn, fn);
    //     if (eh) {
    //         uint64_t data_ptr = handle_import_data(mn, fn);
    //         std::string sym = mn + "." + fn;
    //         global_data[addr] = std::make_tuple(sym, data_ptr);
    //         mem_write(addr, common::to_bytes(data_ptr, get_ptr_size(), 'little'));
    //     }
    // }
    
    return nullptr; // TODO: Return actual PE object
}

void Win32Emulator::prepare_module_for_emulation(void* module, bool all_entrypoints) {
    if (!module) {
        // stop();
        // throw Win32EmuError('Module not found');
        return;
    }
    
    // TODO: Implement module preparation logic
    // Check if any TLS callbacks exist, these run before the module's entry point
    // std::vector<uint64_t> tls = module->get_tls_callbacks();
    // for (size_t i = 0; i < tls.size(); i++) {
    //     uint64_t cb_addr = tls[i];
    //     uint64_t base = module->get_base();
    //     if (base < cb_addr && cb_addr < base + module->get_image_size()) {
    //         std::shared_ptr<Run> run = std::make_shared<Run>();
    //         run->start_addr = cb_addr;
    //         run->type = "tls_callback_" + std::to_string(i);
    //         run->args = {base, DLL_PROCESS_ATTACH, 0};
    //         add_run(run);
    //     }
    // }
    // 
    // uint64_t ep = module->base + module->ep;
    // std::shared_ptr<Run> run = std::make_shared<Run>();
    // run->start_addr = ep;
    // 
    // void* main_exe = nullptr;
    // if (!module->is_exe()) {
    //     run->args = {module->base, DLL_PROCESS_ATTACH, 0};
    //     run->type = "dll_entry.DLL_PROCESS_ATTACH";
    //     void* container = init_container_process();
    //     if (container) {
    //         processes.push_back(container);
    //         curr_process = container;
    //     }
    // } else {
    //     run->type = "module_entry";
    //     main_exe = module;
    //     // TODO: Create args
    //     // run->args = [mem_map(8, tag='emu.module_arg_%d' % (i)) for i in range(4)];
    // }
    // 
    // if (main_exe) {
    //     user_modules.insert(user_modules.begin(), main_exe);
    // }
    // 
    // add_run(run);
    // 
    // if (all_entrypoints) {
    //     // Only emulate a subset of all the exported functions
    //     // There are some modules (such as the windows kernel) with
    //     // thousands of exports
    //     auto exports = module->get_exports();
    //     if (exports.size() > MAX_EXPORTS_TO_EMULATE) {
    //         exports.resize(MAX_EXPORTS_TO_EMULATE);
    //     }
    //     
    //     if (!exports.empty()) {
    //         // TODO: Create args
    //         // auto args = [mem_map(8, tag='emu.export_arg_%d' % (i), base=0x41420000) for i in range(4)];
    //         for (auto& exp : exports) {
    //             if (exp.name == "DllMain") {
    //                 continue;
    //             }
    //             std::shared_ptr<Run> run = std::make_shared<Run>();
    //             std::string fn = exp.name.empty() ? "no_name" : exp.name;
    //             run->type = "export." + fn;
    //             run->start_addr = exp.address;
    //             
    //             if (exp.name == "ServiceMain") {
    //                 // ServiceMain accepts a (argc, argv) pair like main().
    //                 // TODO: Implement ServiceMain handling
    //             } else {
    //                 // Here we set dummy args to pass into the export function
    //                 // run->args = args;
    //             }
    //             // Store these runs and only queue them before the unload
    //             // routine this is because some exports may not be ready to
    //             // be called yet
    //             add_run(run);
    //         }
    //     }
    // }
}

void Win32Emulator::run_module(void* module, bool all_entrypoints, bool emulate_children) {
    prepare_module_for_emulation(module, all_entrypoints);
    
    // Create an empty process object for the module if none is
    // supplied, only do this for the main module
    // TODO: Implement process creation logic
    // if (processes.empty()) {
    //     Process* p = new Process(this, path=module->get_emu_path(), base=module->base,
    //                              pe=module, cmdline=command_line);
    //     curr_process = p;
    //     om->objects.update({p->address: p});
    //     auto mm = get_address_map(module->base);
    //     if (mm) {
    //         mm->process = curr_process;
    //     }
    // }
    // 
    // Thread* t = new Thread(this, stack_base=stack_base, stack_commit=module->stack_commit);
    // om->objects.update({t->address: t});
    // curr_process->threads.push_back(t);
    // curr_thread = t;
    // 
    // void* peb = alloc_peb(curr_process);
    // 
    // // Set the TEB
    // init_teb(t, peb);
    // 
    // // Begin emulation of main module
    // start();
    // 
    // if (!emulate_children || child_processes.empty()) {
    //     return;
    // }
    // 
    // // Emulate any child processes
    // while (!child_processes.empty()) {
    //     auto child = child_processes.front();
    //     child_processes.erase(child_processes.begin());
    //     
    //     // TODO: Load child process module
    //     // child->pe = load_module(data=child->pe_data, first_time_setup=false);
    //     prepare_module_for_emulation(child->pe, all_entrypoints);
    //     
    //     command_line = child->cmdline;
    //     
    //     curr_process = child;
    //     curr_process->base = child->pe->base;
    //     curr_thread = child->threads[0];
    //     
    //     om->objects.update({curr_thread->address: curr_thread});
    //     
    //     // PEB and TEB will be initialized when the next run happens
    //     
    //     start();
    // }
}

void Win32Emulator::_init_name(const std::string& path, const std::vector<uint8_t>& data) {
    if (data.empty()) {
        // Extract filename from path (platform independent)
        size_t lastSlash = path.find_last_of("/\\");
        file_name = (lastSlash == std::string::npos) ? path : path.substr(lastSlash + 1);
        
        size_t lastDot = file_name.find_last_of('.');
        mod_name = (lastDot == std::string::npos) ? file_name : file_name.substr(0, lastDot);
    } else {
        // TODO: Calculate hash of data
        // std::string mod_hash = calculate_sha256(data);
        // mod_name = mod_hash;
        // file_name = mod_name + ".exe";
    }
    // Extract base name
    size_t lastSlash = file_name.find_last_of("/\\");
    bin_base_name = (lastSlash == std::string::npos) ? file_name : file_name.substr(lastSlash + 1);
}

void Win32Emulator::emulate_module(const std::string& path) {
    // void* mod = load_module(path);
    // run_module(mod);
}

uint64_t Win32Emulator::load_shellcode(const std::string& path, const std::string& arch,
                                       const std::vector<uint8_t>& data) {
    _init_name(path, data);
    
    int arch_type;
    if (arch == "x86") {
        arch_type = 1; // _arch.ARCH_X86
    } else if (arch == "x64" || arch == "amd64") {
        arch_type = 2; // _arch.ARCH_AMD64
    }
    
    this->arch = arch_type;
    
    std::vector<uint8_t> sc_data = data;
    std::string sc_hash;
    
    if (!data.empty()) {
        // TODO: Calculate hash
        // sc_hash = calculate_sha256(data);
    } else {
        // TODO: Read file
        // std::ifstream file(path, std::ios::binary);
        // file.seekg(0, std::ios::end);
        // size_t size = file.tellg();
        // file.seekg(0, std::ios::beg);
        // sc_data.resize(size);
        // file.read(reinterpret_cast<char*>(sc_data.data()), size);
        // sc_hash = calculate_sha256(sc_data);
    }
    
    // int disasm_mode;
    // if (this->arch == 1) { // _arch.ARCH_X86
    //     disasm_mode = cs.CS_MODE_32;
    // } else if (this->arch == 2) { // _arch.ARCH_AMD64
    //     disasm_mode = cs.CS_MODE_64;
    // } else {
    //     // throw Win32EmuError('Unsupported architecture: %s' % this->arch);
    // }
    // 
    // emu_eng.init_engine(1 /*_arch.ARCH_X86*/, this->arch);
    // 
    // if (!disasm_eng) {
    //     disasm_eng = cs.Cs(cs.CS_ARCH_X86, disasm_mode);
    // }
    // 
    // std::string sc_tag = "emu.shellcode." + sc_hash;
    // 
    // // Map the shellcode into memory
    // uint64_t sc_addr = mem_map(sc_data.size(), tag=sc_tag);
    // mem_write(sc_addr, sc_data);
    // 
    // pic_buffers.push_back(std::make_tuple(path, sc_addr, sc_data.size()));
    // 
    // std::string sc_arch = "unknown";
    // if (arch_type == 2) { // _arch.ARCH_AMD64
    //     sc_arch = "x64";
    // } else if (arch_type == 1) { // _arch.ARCH_X86
    //     sc_arch = "x86";
    // }
    // 
    // if (profiler) {
    //     // TODO: Set input metadata
    //     // input = {'path': path, 'sha256': sc_hash, 'size': sc_data.size(),
    //     //          'arch': sc_arch, 'mem_tag': sc_tag,
    //     //          'emu_version': get_emu_version(),
    //     //          'os_run': get_osver_string()};
    //     // profiler->add_input_metadata(input);
    //     // Strings the initial buffer so that we can detect decoded strings later on
    //     // if (do_strings) {
    //     //     profiler->strings["ansi"] = [a[1] for a in get_ansi_strings(sc_data)];
    //     //     profiler->strings["unicode"] = [u[1] for u in get_unicode_strings(sc_data)];
    //     // }
    // }
    // setup();
    // 
    return 0; // TODO: Return actual address
}

void Win32Emulator::run_shellcode(uint64_t sc_addr, size_t stack_commit, size_t offset) {
    // TODO: Implement shellcode execution logic
    // uint64_t target = 0;
    // for (auto& [sc_path, _sc_addr, size] : pic_buffers) {
    //     if (_sc_addr == sc_addr) {
    //         target = _sc_addr;
    //         break;
    //     }
    // }
    // 
    // if (!target) {
    //     // throw Win32EmuError('Invalid shellcode address');
    // }
    // 
    // auto stack_info = alloc_stack(stack_commit);
    // stack_base = std::get<0>(stack_info);
    // uint64_t stack_addr = std::get<1>(stack_info);
    // set_func_args(stack_base, return_hook, 0x7000);
    // 
    // std::shared_ptr<Run> run = std::make_shared<Run>();
    // run->type = "shellcode";
    // run->start_addr = sc_addr + offset;
    // run->instr_cnt = 0;
    // // TODO: Create args
    // // std::vector<uint64_t> args;
    // // for (int i = 0; i < 4; i++) {
    // //     args.push_back(mem_map(1024, tag='emu.shellcode_arg_%d' % (i), base=0x41420000 + i));
    // // }
    // // run->args = args;
    // 
    // reg_write(/*_arch.X86_REG_ECX*/ 0, 1024);
    // 
    // add_run(run);
    // 
    // // Create an empty process object for the shellcode if none is
    // // supplied
    // void* container = init_container_process();
    // if (container) {
    //     processes.push_back(container);
    //     curr_process = container;
    // } else {
    //     Process* p = new Process(this);
    //     processes.push_back(p);
    //     curr_process = p;
    // }
    // 
    // auto mm = get_address_map(sc_addr);
    // if (mm) {
    //     mm->set_process(curr_process);
    // }
    // 
    // Thread* t = new Thread(this, stack_base=stack_base, stack_commit=stack_commit);
    // om->objects.update({t->address: t});
    // curr_process->threads.push_back(t);
    // 
    // curr_thread = t;
    // 
    // void* peb = alloc_peb(curr_process);
    // 
    // // Set the TEB
    // init_teb(t, peb);
    // 
    // start();
}

void* Win32Emulator::alloc_peb(void* proc) {
    // TODO: Implement PEB allocation
    // if (proc->is_peb_active) {
    //     return nullptr;
    // }
    // size_t size = proc->get_peb_ldr()->sizeof();
    // auto [res, size_result] = get_valid_ranges(size);
    // mem_reserve(size_result, base=res, tag='emu.struct.PEB_LDR_DATA');
    // proc->set_peb_ldr_address(res);
    // 
    // void* peb = proc->get_peb();
    // proc->is_peb_active = true;
    // peb->object.ImageBaseAddress = proc->base;
    // peb->object.OSMajorVersion = osversion["major"];
    // peb->object.OSMinorVersion = osversion["minor"];
    // peb->object.OSBuildNumber = osversion["build"];
    // peb->write_back();
    // return peb;
    return nullptr;
}

void Win32Emulator::set_unhandled_exception_handler(uint64_t handler_addr) {
    unhandled_exception_filter = handler_addr;
}

void Win32Emulator::setup(size_t stack_commit, bool first_time_setup) {
    if (first_time_setup) {
        // Set the emulator to run in protected mode
        // om = objman.ObjectManager(emu=this);
    }
    
    int arch = get_arch();
    _setup_gdt(arch);
    setup_user_shared_data();
    set_ptr_size(this->arch);
    
    if (arch == 1) { // _arch.ARCH_X86
        peb_addr = fs_addr + 0x30;
    } else if (arch == 2) { // _arch.ARCH_AMD64
        peb_addr = gs_addr + 0x60;
    }
    
    // api = WindowsApi(this);
    // 
    // // Init symlinks
    // for (auto& sl : symlinks) {
    //     om->add_symlink(sl["name"], sl["target"]);
    // }
    // 
    // init_sys_modules(config_system_modules);
}

std::vector<void*> Win32Emulator::init_sys_modules(const std::vector<nlohmann::json>& modules_config) {
    std::vector<void*> sys_mods;
    
    // for (auto& modconf : modules_config) {
    //     // TODO: Create DecoyModule
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
    //         // TODO: Create Process
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

void Win32Emulator::exit_process() {
    enable_code_hook();
    run_complete = true;
}

bool Win32Emulator::_hook_mem_unmapped(void* emu, int access, uint64_t address, 
                                      size_t size, uint64_t value, void* user_data) {
    // TODO: Implement memory unmapped hook
    // std::string _access = emu_eng.mem_access.get(access);
    // 
    // if (_access == "INVALID_MEM_READ") {
    //     void* p = get_current_process();
    //     void* pld = p->get_peb_ldr();
    //     if (address > pld->address && address < (pld->address + pld->sizeof())) {
    //         mem_map_reserve(pld->address);
    //         auto user_mods = get_user_modules();
    //         init_peb(user_mods);
    //         return true;
    //     }
    // }
    // return WindowsEmulator::_hook_mem_unmapped(emu, access, address, size, value, user_data);
    return false;
}

void Win32Emulator::set_hooks() {
    WindowsEmulator::set_hooks();
    
    // if (!builtin_hooks_set) {
    //     add_mem_invalid_hook(cb=_hook_mem_unmapped);
    //     add_interrupt_hook(cb=_hook_interrupt);
    //     builtin_hooks_set = true;
    // }
    // 
    // set_mem_tracing_hooks();
}

void Win32Emulator::stop() {
    run_complete = true;
    // _unset_emu_hooks();
    // unset_hooks();
    WindowsEmulator::stop();
}

void Win32Emulator::on_emu_complete() {
    if (!emu_complete) {
        emu_complete = true;
        // if (do_strings && profiler) {
        //     auto [dec_ansi, dec_unicode] = get_mem_strings();
        //     // Filter out already known strings
        //     // TODO: Implement string filtering
        // }
    }
    stop();
}

bool Win32Emulator::on_run_complete() {
    run_complete = true;
    // curr_run->ret_val = get_return_val();
    // if (profiler) {
    //     profiler->log_dropped_files(curr_run, get_dropped_files());
    // }
    // 
    // return _exec_next_run();
    return false;
}

uint64_t Win32Emulator::heap_alloc(size_t size, const std::string& heap) {
    // uint64_t addr = mem_map(size, base=nullptr, tag='api.heap.%s' % (heap));
    // heap_allocs.push_back(std::make_tuple(addr, size, heap));
    // return addr;
    return 0;
}