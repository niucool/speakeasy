// speakeasy.cpp
#include "speakeasy.h"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cstring>

// Constructor
Speakeasy::Speakeasy(const nlohmann::json& config, void* logger, 
                     const std::vector<std::string>& argv, bool debug, void* exit_event)
    : logger(logger), emu(nullptr), argv(argv), exit_event(exit_event), 
      debug(debug) {
    _init_config(config);
}

// Destructor
Speakeasy::~Speakeasy() {
    shutdown();
}

void Speakeasy::_init_config(const nlohmann::json& config) {
    if (config.empty()) {
        // TODO: Load default config from file
        // std::string config_path = os.path.join(os.path.dirname(speakeasy.__file__), 'configs', 'default.json');
        // std::ifstream f(config_path);
        // f >> this->config;
    } else {
        this->config = config;
    }

    try {
        validate_config(this->config);
    } catch (const std::exception& err) {
        if (logger) {
            // TODO: Log exception
            // logger->exception("Invalid config: %s", err.what());
        }
        // TODO: Throw ConfigError
        // throw ConfigError("Invalid config");
    }
}

void Speakeasy::_init_emulator(const std::string& path, const std::vector<uint8_t>& data, bool is_raw_code) {
    if (!is_raw_code) {
        // TODO: Create PeFile
        // PeFile pe(path=path, data=data);
        // Get the machine type we only support x86/x64 atm
        // std::string mach = MACHINE_TYPE[pe.FILE_HEADER.Machine].split('_')[-1:][0].lower();
        // if (mach not in ('amd64', 'i386')) {
        //     throw SpeakeasyError('Unsupported architecture: %s' % mach);
        // }
        // 
        // if (pe.is_dotnet()) {
        //     throw NotSupportedError('.NET assemblies are not currently supported');
        // }
        // 
        // if (pe.is_driver()) {
        //     emu = new WinKernelEmulator(config=this->config, logger=this->logger,
        //                                 debug=this->debug, exit_event=this->exit_event);
        // } else {
        //     emu = new Win32Emulator(config=this->config, logger=this->logger, argv=this->argv,
        //                             debug=this->debug, exit_event=this->exit_event);
        // }
    } else {
        // TODO: Create Win32Emulator
        // emu = new Win32Emulator(config=this->config, logger=this->logger, argv=this->argv,
        //                         debug=this->debug, exit_event=this->exit_event);
    }
}

void Speakeasy::_init_hooks() {
    // Add any configured hooks here
    while (!api_hooks.empty()) {
        auto h = api_hooks.front();
        api_hooks.erase(api_hooks.begin());
        // TODO: Call add_api_hook with extracted values
        // auto [cb, mod, func, argc, cconv] = h;
        // add_api_hook(cb, mod, func, argc, cconv);
    }
    
    while (!code_hooks.empty()) {
        auto h = code_hooks.front();
        code_hooks.erase(code_hooks.begin());
        // TODO: Call add_code_hook with extracted values
        // auto [cb, begin, end, ctx] = h;
        // add_code_hook(cb, begin, end, ctx);
    }
    
    // TODO: Process other hook types similarly
}

std::tuple<std::string, std::string, std::string> Speakeasy::disasm(uint64_t addr, size_t size, bool fast) {
    try {
        // TODO: Call emu->get_disasm(addr, size, fast);
        // return emu->get_disasm(addr, size, fast);
        return std::make_tuple("", "", "");
    } catch (const std::exception& e) {
        // TODO: Throw SpeakeasyError
        // throw SpeakeasyError("Failed to disassemble at address: 0x%x", addr);
        return std::make_tuple("", "", "");
    }
}

bool Speakeasy::is_pe(const std::vector<uint8_t>& data) {
    // Check for the PE header
    if (data.size() >= 2 && data[0] == 'M' && data[1] == 'Z') {
        return true;
    } else {
        return false;
    }
}

PeFile* Speakeasy::load_module(const std::string& path, const std::vector<uint8_t>& data) {
    if (path.empty() && data.empty()) {
        // TODO: Throw SpeakeasyError
        // throw SpeakeasyError('No emulation target supplied');
        return nullptr;
    }

    if (!path.empty() && !std::ifstream(path).good()) {
        // TODO: Throw SpeakeasyError
        // throw SpeakeasyError('Target file not found: %s', path.c_str());
        return nullptr;
    }

    loaded_bins.push_back(path);

    std::vector<uint8_t> test;
    if (!data.empty()) {
        test = data;
    } else {
        std::ifstream f(path, std::ios::binary);
        test.resize(4);
        f.read(reinterpret_cast<char*>(test.data()), 4);
    }

    if (!is_pe(test)) {
        // TODO: Throw SpeakeasyError
        // throw SpeakeasyError('Target file is not a PE');
        return nullptr;
    }

    _init_emulator(path, data);

    // TODO: Return emu->load_module(path=path, data=data);
    // return emu->load_module(path=path, data=data);
    return nullptr;
}

void Speakeasy::run_module(PeFile* module, bool all_entrypoints, bool emulate_children) {
    _init_hooks();

    // TODO: Check emulator type and call appropriate method
    // if (isinstance(emu, Win32Emulator)) {
    //     return emu->run_module(module=module,
    //             all_entrypoints=all_entrypoints,
    //             emulate_children=emulate_children);
    // } else {
    //     return emu->run_module(module=module,
    //             all_entrypoints=all_entrypoints);
    // }
}

uint64_t Speakeasy::load_shellcode(const std::string& fpath, const std::string& arch, 
                                  const std::vector<uint8_t>& data) {
    _init_emulator("", std::vector<uint8_t>(), true);
    loaded_bins.push_back(fpath);

    // TODO: Return emu->load_shellcode(fpath, arch, data=data);
    // return emu->load_shellcode(fpath, arch, data=data);
    return 0;
}

void Speakeasy::run_shellcode(uint64_t sc_addr, size_t stack_commit, size_t offset) {
    _init_hooks();
    // TODO: Call emu->run_shellcode(sc_addr, stack_commit=stack_commit, offset=offset);
    // return emu->run_shellcode(sc_addr, stack_commit=stack_commit, offset=offset);
}

nlohmann::json Speakeasy::get_report() {
    // TODO: Return emu->get_report();
    // return emu->get_report();
    return nlohmann::json();
}

std::string Speakeasy::get_json_report() {
    // TODO: Return emu->get_json_report();
    // return emu->get_json_report();
    return "";
}

void* Speakeasy::add_api_hook(std::function<void()> cb, const std::string& module, 
                             const std::string& api_name, int argc, 
                             const std::string& call_conv) {
    if (!emu) {
        api_hooks.push_back(std::make_tuple(cb, module, api_name, argc, call_conv));
        return nullptr;
    }
    // TODO: Return emu->add_api_hook(cb, module=module, api_name=api_name, argc=argc,
    //                              call_conv=call_conv, emu=this);
    // return emu->add_api_hook(cb, module=module, api_name=api_name, argc=argc,
    //                          call_conv=call_conv, emu=this);
    return nullptr;
}

void Speakeasy::resume(uint64_t addr, int count) {
    // TODO: Implement resume logic
    // emu->run_complete = false;
    // emu->resume(addr, count=count);
}

void Speakeasy::stop() {
    // TODO: Return emu->stop();
    // return emu->stop();
}

void Speakeasy::shutdown() {
    // TODO: Implement shutdown logic
}

void Speakeasy::call(uint64_t addr, const std::vector<void*>& params) {
    // TODO: Return emu->call(addr, params=params);
    // return emu->call(addr, params=params);
}

void* Speakeasy::add_code_hook(std::function<void()> cb, uint64_t begin, uint64_t end, 
                              const std::map<std::string, std::string>& ctx) {
    if (!emu) {
        code_hooks.push_back(std::make_tuple(cb, begin, end, ctx));
        return nullptr;
    }
    // TODO: Return emu->add_code_hook(cb, begin=begin, end=end, ctx=ctx, emu=this);
    // return emu->add_code_hook(cb, begin=begin, end=end, ctx=ctx, emu=this);
    return nullptr;
}

void* Speakeasy::add_dyn_code_hook(std::function<void()> cb, 
                                  const std::map<std::string, std::string>& ctx) {
    if (!emu) {
        dyn_code_hooks.push_back(std::make_tuple(cb, ctx));
        return nullptr;
    }
    // TODO: Return emu->add_dyn_code_hook(cb, ctx=ctx, emu=this);
    // return emu->add_dyn_code_hook(cb, ctx=ctx, emu=this);
    return nullptr;
}

void* Speakeasy::add_mem_read_hook(std::function<void()> cb, uint64_t begin, uint64_t end) {
    if (!emu) {
        mem_read_hooks.push_back(std::make_tuple(cb, begin, end));
        return nullptr;
    }
    // TODO: Return emu->add_mem_read_hook(cb, begin=begin, end=end, emu=this);
    // return emu->add_mem_read_hook(cb, begin=begin, end=end, emu=this);
    return nullptr;
}

void* Speakeasy::add_mem_write_hook(std::function<void()> cb, uint64_t begin, uint64_t end) {
    if (!emu) {
        mem_write_hooks.push_back(std::make_tuple(cb, begin, end));
        return nullptr;
    }
    // TODO: Return emu->add_mem_write_hook(cb, begin=begin, end=end, emu=this);
    // return emu->add_mem_write_hook(cb, begin=begin, end=end, emu=this);
    return nullptr;
}

void* Speakeasy::add_IN_instruction_hook(std::function<void()> cb, uint64_t begin, uint64_t end) {
    if (!emu) {
        mem_write_hooks.push_back(std::make_tuple(cb, begin, end));
        return nullptr;
    }
    // TODO: Return emu->add_instruction_hook(cb, begin=begin, end=end, emu=this, insn=218);
    // return emu->add_instruction_hook(cb, begin=begin, end=end, emu=this, insn=218);
    return nullptr;
}

void* Speakeasy::add_SYSCALL_instruction_hook(std::function<void()> cb, uint64_t begin, uint64_t end) {
    if (!emu) {
        mem_write_hooks.push_back(std::make_tuple(cb, begin, end));
        return nullptr;
    }
    // TODO: Return emu->add_instruction_hook(cb, begin=begin, end=end, emu=this, insn=700);
    // return emu->add_instruction_hook(cb, begin=begin, end=end, emu=this, insn=700);
    return nullptr;
}

void* Speakeasy::add_invalid_instruction_hook(std::function<void()> cb, const std::vector<void*>& ctx) {
    if (!emu) {
        invalid_insn_hooks.push_back(std::make_tuple(cb, ctx));
        return nullptr;
    }
    // TODO: Return emu->add_invalid_instruction_hook(cb, ctx);
    // return emu->add_invalid_instruction_hook(cb, ctx);
    return nullptr;
}

void* Speakeasy::add_mem_invalid_hook(std::function<void()> cb) {
    if (!emu) {
        mem_invalid_hooks.push_back(std::make_tuple(cb));
        return nullptr;
    }
    // TODO: Return emu->add_mem_invalid_hook(cb, emu=this);
    // return emu->add_mem_invalid_hook(cb, emu=this);
    return nullptr;
}

void* Speakeasy::add_interrupt_hook(std::function<void()> cb, 
                                   const std::map<std::string, std::string>& ctx) {
    if (!emu) {
        interrupt_hooks.push_back(std::make_tuple(cb));
        return nullptr;
    }
    // TODO: Return emu->add_interrupt_hook(cb, ctx=ctx, emu=this);
    // return emu->add_interrupt_hook(cb, ctx=ctx, emu=this);
    return nullptr;
}

void* Speakeasy::get_registry_key(int handle, const std::string& path) {
    // TODO: Return emu->reg_get_key(handle=handle, path=path);
    // return emu->reg_get_key(handle=handle, path=path);
    return nullptr;
}

void* Speakeasy::get_address_map(uint64_t addr) {
    // TODO: Return emu->get_address_map(addr);
    // return emu->get_address_map(addr);
    return nullptr;
}

std::vector<void*> Speakeasy::get_user_modules() {
    // TODO: Return emu->get_user_modules();
    // return emu->get_user_modules();
    return std::vector<void*>();
}

std::vector<void*> Speakeasy::get_sys_modules() {
    // TODO: Return emu->get_sys_modules();
    // return emu->get_sys_modules();
    return std::vector<void*>();
}

uint64_t Speakeasy::mem_alloc(size_t size, uint64_t base, const std::string& tag) {
    // TODO: Return emu->mem_map(size, base=base, tag=tag);
    // return emu->mem_map(size, base=base, tag=tag);
    return 0;
}

void Speakeasy::mem_free(uint64_t base) {
    // TODO: Return emu->mem_free(base);
    // return emu->mem_free(base);
}

std::vector<uint8_t> Speakeasy::mem_read(uint64_t addr, size_t size) {
    try {
        // TODO: Return emu->mem_read(addr, size);
        // return emu->mem_read(addr, size);
        return std::vector<uint8_t>();
    } catch (const std::exception& e) {
        // TODO: Throw SpeakeasyError
        // throw SpeakeasyError("Failed to read %d bytes at address: 0x%x", size, addr);
        return std::vector<uint8_t>();
    }
}

void Speakeasy::mem_write(uint64_t addr, const std::vector<uint8_t>& data) {
    try {
        // TODO: Return emu->mem_write(addr, data);
        // return emu->mem_write(addr, data);
    } catch (const std::exception& e) {
        // TODO: Throw SpeakeasyError
        // throw SpeakeasyError("Failed to write %d bytes at address: 0x%x", data.size(), addr);
    }
}

void* Speakeasy::mem_cast(void* obj, uint64_t addr) {
    // TODO: Return emu->mem_cast(obj, addr);
    // return emu->mem_cast(obj, addr);
    return nullptr;
}

uint64_t Speakeasy::reg_read(const std::string& reg) {
    // TODO: Return emu->reg_read(reg);
    // return emu->reg_read(reg);
    return 0;
}

std::vector<std::tuple<uint64_t, std::string, std::string>> Speakeasy::get_dyn_imports() {
    // TODO: Return emu->get_dyn_imports();
    // return emu->get_dyn_imports();
    return std::vector<std::tuple<uint64_t, std::string, std::string>>();
}

void Speakeasy::reg_write(const std::string& reg, uint64_t val) {
    // TODO: Return emu->reg_write(reg, val);
    // return emu->reg_write(reg, val);
}

std::vector<void*> Speakeasy::get_dropped_files() {
    // TODO: Return emu->get_dropped_files();
    // return emu->get_dropped_files();
    return std::vector<void*>();
}

std::vector<uint8_t> Speakeasy::create_file_archive() {
    // TODO: Implement file archive creation
    // auto manifest = std::vector<nlohmann::json>();
    // // BytesIO _zip;
    // auto files = get_dropped_files();
    // 
    // if (files.empty()) {
    //     return std::vector<uint8_t>();
    // }
    // 
    // // TODO: Implement zip file creation
    // // with zipfile.ZipFile(_zip, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
    // //     for f in files:
    // //         path = f.get_path();
    // //         file_name = ntpath.basename(path);
    // //         manifest.push_back({{"path", path},
    // //                          {"file_name", file_name},
    // //                          {"size", f.get_size()},
    // //                          {"sha256", f.get_hash()}});
    // //         zf.writestr(file_name, f.get_data());
    // //     
    // //     manifest_data = json.dumps(manifest, indent=4, sort_keys=false);
    // //     zf.writestr("speakeasy_manifest.json", manifest_data);
    // // 
    // // return _zip.getvalue();
    return std::vector<uint8_t>();
}

std::vector<void*> Speakeasy::get_mem_maps() {
    // TODO: Return emu->get_mem_maps();
    // return emu->get_mem_maps();
    return std::vector<void*>();
}

std::vector<std::tuple<std::string, uint64_t, size_t, bool, void*, std::vector<uint8_t>>> 
Speakeasy::get_memory_dumps() {
    // TODO: Implement memory dumps retrieval
    // std::vector<std::tuple<std::string, uint64_t, size_t, bool, void*, std::vector<uint8_t>>> result;
    // for (auto& mm : get_mem_maps()) {
    //     uint64_t base = mm.get_base();
    //     size_t size = mm.get_size();
    //     std::string tag = mm.get_tag();
    //     void* proc = mm.get_process();
    //     bool is_free = mm.is_free();
    //     try {
    //         auto data = mem_read(base, size);
    //         result.push_back(std::make_tuple(tag, base, size, is_free, proc, data));
    //     } catch (const std::exception& e) {
    //         continue;
    //     }
    // }
    // return result;
    return std::vector<std::tuple<std::string, uint64_t, size_t, bool, void*, std::vector<uint8_t>>>();
}

std::string Speakeasy::read_mem_string(uint64_t address, int width, size_t max_chars) {
    // TODO: Return emu->read_mem_string(address, width, max_chars);
    // return emu->read_mem_string(address, width, max_chars);
    return "";
}

std::map<uint64_t, std::tuple<std::string, std::string>> Speakeasy::get_symbols() {
    // TODO: Return emu->symbols;
    // return emu->symbols;
    return std::map<uint64_t, std::tuple<std::string, std::string>>();
}

uint64_t Speakeasy::get_ret_address() {
    // TODO: Return emu->get_ret_address();
    // return emu->get_ret_address();
    return 0;
}

void Speakeasy::set_ret_address(uint64_t addr) {
    // TODO: Return emu->set_ret_address(addr);
    // return emu->set_ret_address(addr);
}

void Speakeasy::push_stack(uint64_t val) {
    // TODO: Call emu->push_stack(val);
    // emu->push_stack(val);
}

uint64_t Speakeasy::pop_stack() {
    // TODO: Return emu->pop_stack();
    // return emu->pop_stack();
    return 0;
}

uint64_t Speakeasy::get_stack_ptr() {
    // TODO: Return emu->get_stack_ptr();
    // return emu->get_stack_ptr();
    return 0;
}

void Speakeasy::set_stack_ptr(uint64_t addr) {
    // TODO: Call emu->set_stack_ptr(addr);
    // emu->set_stack_ptr(addr);
}

uint64_t Speakeasy::get_pc() {
    // TODO: Return emu->get_pc();
    // return emu->get_pc();
    return 0;
}

void Speakeasy::set_pc(uint64_t addr) {
    // TODO: Call emu->set_pc(addr);
    // emu->set_pc(addr);
}

std::tuple<uint64_t, uint64_t> Speakeasy::reset_stack(uint64_t base) {
    // TODO: Return emu->reset_stack(base);
    // return emu->reset_stack(base);
    return std::make_tuple(0, 0);
}

uint64_t Speakeasy::get_stack_base() {
    // TODO: Return emu->stack_base;
    // return emu->stack_base;
    return 0;
}

int Speakeasy::get_arch() {
    // TODO: Return emu->get_arch();
    // return emu->get_arch();
    return 0;
}

int Speakeasy::get_ptr_size() {
    // TODO: Return emu->ptr_size;
    // return emu->ptr_size;
    return 0;
}

std::map<std::string, uint64_t> Speakeasy::get_all_registers() {
    // TODO: Return emu->get_register_state();
    // return emu->get_register_state();
    return std::map<std::string, uint64_t>();
}

std::string Speakeasy::get_symbol_from_address(uint64_t address) {
    // TODO: Return emu->get_symbol_from_address(address);
    // return emu->get_symbol_from_address(address);
    return "";
}

bool Speakeasy::is_address_valid(uint64_t address) {
    // TODO: Return emu->is_address_valid(address);
    // return emu->is_address_valid(address);
    return false;
}

void* Speakeasy::add_mem_map_hook(std::function<void()> cb, uint64_t begin, uint64_t end) {
    if (!emu) {
        mem_map_hooks.push_back(std::make_tuple(cb, begin, end));
        return nullptr;
    }
    // TODO: Return emu->add_mem_map_hook(cb, begin=begin, end=end, emu=this);
    // return emu->add_mem_map_hook(cb, begin=begin, end=end, emu=this);
    return nullptr;
}

std::vector<uint8_t> Speakeasy::create_memdump_archive() {
    // TODO: Implement memory dump archive creation
    // auto manifest = std::vector<nlohmann::json>();
    // // BytesIO _zip;
    // 
    // std::vector<std::string> loaded_bins_names;
    // for (auto& b : loaded_bins) {
    //     // TODO: Extract basename and remove extension
    //     // loaded_bins_names.push_back(os.path.splitext(os.path.basename(b))[0]);
    // }
    // 
    // // TODO: Implement zip file creation
    // // with zipfile.ZipFile(_zip, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
    // //     std::vector<void*> procs;
    // //     for (auto& block : get_memory_dumps()) {
    // //         if (std::find(procs.begin(), procs.end(), std::get<4>(block)) == procs.end()) {
    // //             procs.push_back(std::get<4>(block));
    // //         }
    // //     }
    // //     
    // //     for (auto& process : procs) {
    // //         std::vector<nlohmann::json> memory_blocks;
    // //         int arch = emu->get_arch();
    // //         if (arch == /*_arch.ARCH_X86*/) {
    // //             arch_str = "x86";
    // //         } else {
    // //             arch_str = "amd64";
    // //         }
    // //         
    // //         if (process) {
    // //             int pid = process.get_pid();
    // //             std::string path = process.get_process_path();
    // //         } else {
    // //             continue;
    // //         }
    // //         
    // //         manifest.push_back({{"pid", pid}, {"process_name", path}, {"arch", arch_str},
    // //                          {"memory_blocks", memory_blocks}});
    // //         
    // //         for (auto& block : get_memory_dumps()) {
    // //             std::string tag = std::get<0>(block);
    // //             uint64_t base = std::get<1>(block);
    // //             size_t size = std::get<2>(block);
    // //             bool is_free = std::get<3>(block);
    // //             void* proc = std::get<4>(block);
    // //             auto data = std::get<5>(block);
    // //             
    // //             if (tag.empty()) {
    // //                 continue;
    // //             }
    // //             if (proc != process) {
    // //                 continue;
    // //             }
    // //             // Ignore emulator noise such as structures created by the emulator, or
    // //             // modules that were loaded
    // //             if (!tag.empty() && tag.starts_with("emu") && !tag.starts_with("emu.shellcode.")) {
    // //                 bool found = false;
    // //                 for (auto& b : loaded_bins_names) {
    // //                     if (tag.find(b) != std::string::npos) {
    // //                         found = true;
    // //                         break;
    // //                     }
    // //                 }
    // //                 if (!found) {
    // //                     continue;
    // //                 }
    // //             }
    // //             
    // //             // TODO: Calculate hash
    // //             // std::string hash = calculate_sha256(data);
    // //             
    // //             std::string file_name = tag + ".mem";
    // //             
    // //             memory_blocks.push_back({{"tag", tag}, {"base", "0x" + std::to_string(base)}, 
    // //                                    {"size", "0x" + std::to_string(size)},
    // //                                    {"is_free", is_free}, {"sha256", hash},
    // //                                    {"file_name", file_name}});
    // //             zf.writestr(file_name, data);
    // //         }
    // //         
    // //         auto manifest_data = json.dumps(manifest, indent=4, sort_keys=false);
    // //         zf.writestr("speakeasy_manifest.json", manifest_data);
    // //     }
    // // 
    // // return _zip.getvalue();
    return std::vector<uint8_t>();
}

void validate_config(const nlohmann::json& config) {
    // TODO: Implement config validation
    // std::string schema_path = os.path.join(os.path.dirname(speakeasy.__file__), 'config_schema.json');
    // std::ifstream ff(schema_path);
    // nlohmann::json schema;
    // ff >> schema;
    // 
    // // TODO: Validate config against schema
    // // jsonschema.Draft7Validator validator(schema);
    // // validator.validate(config);
}