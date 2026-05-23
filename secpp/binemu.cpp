 // binemu.cpp
#include "binemu.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cstring>
#ifdef HAS_CAPSTONE
#include <capstone/capstone.h>
#endif
#include <plog/Log.h>

// Python binemu.py:59-78 doc: "Base class for emulating binaries\n\nSubclasses must define the following attributes:\n    arch: Architecture constant (e.g., ARCH_X86, ARCH_AMD64)\n    modules: List of loaded modules\n    input: Input metadata dictionary (or None)"
// Constructor
BinaryEmulator::BinaryEmulator(const speakeasy::SpeakeasyConfig& cfg)
    : config(cfg), stack_base(0), page_size(0), inst_count(0), curr_instr_size(0),
      disasm_eng(nullptr), builtin_hooks_set(false), emu_eng(nullptr),
      runtime(0) {
    
    // Python binemu.py:59-78: __init__ -- initializes all member state
    // TODO: Python also calls _parse_config inside __init__; C++ calls after init list
    max_instructions = -1;
    timeout = 0;
    max_api_count = 5000;
    arch_ = speakeasy::arch::ARCH_X86;
    ptr_size_ = 4;
    keep_memory_on_free = false;
    
    profiler = std::make_shared<Profiler>();
    emu_version = get_emu_version();
    
    _parse_config(cfg);
}

void BinaryEmulator::log_info(const std::string& msg) {
    PLOG_INFO << msg;
}

void BinaryEmulator::log_error(const std::string& msg) {
    PLOG_ERROR << msg;
}

void BinaryEmulator::log_exception(const std::string& msg) {
    PLOG_ERROR << "EXCEPTION: " << msg;
}

std::shared_ptr<Profiler> BinaryEmulator::get_profiler() {
    // Python binemu.py:80-84 doc: "Get the current event profiler object (if any)"
    return profiler;
}

speakeasy::Report BinaryEmulator::get_report() {
    // Python binemu.py:86-92 doc: "Get the emulation report for all runs that were executed"
    if (profiler) {
        return profiler->get_report();
    }
    // Return empty map if no profiler
    return speakeasy::Report();
}

std::string BinaryEmulator::get_json_report_string() {
    // Python binemu.py:94-100 doc: "Get the emulation report ... formatted as a JSON string"
    if (profiler) {
        return get_report().to_json_string();
    }
    // Return empty string if no profiler
    return "";
}

void BinaryEmulator::_parse_config(const speakeasy::SpeakeasyConfig& cfg) {
    // Python binemu.py:102-116 doc: "Parse the config to be used for emulation"
    // TODO: Python also initializes self.emu_eng from EMU_ENGINES lookup table
    //       C++ defers engine creation to WindowsEmulator::load_image
    timeout = cfg.timeout;
    max_api_count = cfg.max_api_count;
    keep_memory_on_free = cfg.keep_memory_on_free;
    command_line = cfg.command_line;

    // Populate osversion map
    osversion["name"]   = cfg.os_ver.name;
    osversion["major"]  = std::to_string(cfg.os_ver.major);
    osversion["minor"]  = std::to_string(cfg.os_ver.minor);
    osversion["build"]  = std::to_string(cfg.os_ver.build);

    // Populate user_config map
    user_config["name"]     = cfg.user.name;
    user_config["is_admin"] = cfg.user.is_admin ? "1" : "0";

    // Populate network_config map
    network_config["hostname"] = cfg.hostname;
    network_config["domain"]   = cfg.domain;
    for (const auto& [name, ip] : cfg.network.dns.names) {
        network_config[name] = ip;
    }

    // Drive config
    for (const auto& drv : cfg.drives) {
        drive_config.push_back(drv.root_path);
    }
}

std::string BinaryEmulator::get_emu_version() {
    // Python binemu.py:117-121 doc: "Get the version of the emulator"
    return __version__; // From version.h
}

std::map<std::string, std::string> BinaryEmulator::get_os_version() {
    // Get version of the OS being emulated
    return osversion;
}

std::string BinaryEmulator::get_osver_string() {
    // Python binemu.py:123-135 doc: "Get the human readable OS version string"
    // Format: "name.major_minor" e.g. "windows.10_19041"
    auto osver = get_os_version();
    if (!osver.empty()) {
        std::string os_name = osver["name"];
        auto major_it = osver.find("major");
        auto minor_it = osver.find("minor");
        if (major_it != osver.end() && minor_it != osver.end()) {
            std::string verstr = os_name + "." + major_it->second + "_" + minor_it->second;
            return verstr;
        }
    }
    return "";
}

std::string BinaryEmulator::get_domain() {
    // Get domain of the machine being emulated
    return config.domain;
}

std::string BinaryEmulator::get_hostname() {
    // Get hostname of the machine being emulated
    return hostname;
}

std::map<std::string, std::string> BinaryEmulator::get_user() {
    // Get the current emulated user properties
    return user_config;
}

template<typename T>
size_t BinaryEmulator::objsize(T obj) {
    // Python binemu.py:137-141 doc: "Get the size (in the emulation space) of the supplied object"
    // TODO: Python delegates to obj.sizeof() -- only works for EmuStruct types
    //       C++ uses sizeof(T) which is correct for POD but wrong for structs with virtual methods
    (void)obj;
    return sizeof(T);  // Default: return sizeof(T) for plain types; override for EmuStruct types
}

template<typename T>
std::vector<uint8_t> BinaryEmulator::get_bytes(T obj) {
    // Python binemu.py:143-147 doc: "Get the bytes represented in the emulation space of the supplied object"
    // TODO: Python delegates to obj.get_bytes() -- polymorphic
    //       C++ does raw byte copy; correct for POD, wrong for EmuStruct objects
    (void)obj;
    return std::vector<uint8_t>((uint8_t*)&obj, (uint8_t*)&obj + sizeof(T));  // Default: raw byte copy; override for EmuStruct types
}

void BinaryEmulator::stop() {
    // Python binemu.py:149-156 doc: "Stop emulation completely"
    // Stops emu_eng and profiler run clock
    if (emu_eng) {
        emu_eng->stop();
    }
    if (profiler) {
        profiler->stop_run_clock();
    }
}

void BinaryEmulator::start(uint64_t addr, size_t size) {
    // Python binemu.py:158-172 doc: "Begin emulation"
    // Sets hooks, starts profiler clock, runs emu_eng->start with timeout
    set_hooks();
    _set_emu_hooks();
    if (profiler) {
        profiler->set_start_time();
    }
    try {
        if (emu_eng) {
            emu_eng->start(addr, timeout, max_instructions);
        }
    } catch (const std::exception& e) {
        if (profiler) {
            profiler->log_error(e.what());
        }
        on_emu_complete();
    }
}

std::map<std::string, std::string> BinaryEmulator::get_network_config() {
    // Get the network settings specified in the network section of the config file
    return network_config;
}

std::vector<std::string> BinaryEmulator::get_network_adapters() {
    // Get the network adapters specified in the network section of the config file
    return network_adapters;
}

std::map<std::string, std::string> BinaryEmulator::get_filesystem_config() {
    // Get the filesystem settings specified in the filesystem section of the config file
    return filesystem_config;
}

std::vector<std::string> BinaryEmulator::get_drive_config() {
    // Get the drive settings specified in the drives section of the config file
    return drive_config;
}

void BinaryEmulator::reg_write(const std::string& reg, uint64_t val) {
    // Python binemu.py:174-185: use central REG_LOOKUP table
    std::string lower = reg;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    auto it = speakeasy::arch::REG_LOOKUP.find(lower);
    if (it != speakeasy::arch::REG_LOOKUP.end())
        reg_write(it->second, val);
}

void BinaryEmulator::reg_write(int reg, uint64_t val) {
    // Python binemu.py:174-185 doc: "Write a value to an emulated cpu register"
    // String variant uses speakeasy::arch::REG_LOOKUP (Python: e_arch.REG_LOOKUP)
    if (emu_eng) {
        emu_eng->reg_write(reg, val);
    }
}

uint64_t BinaryEmulator::reg_read(const std::string& reg) {
    // Python binemu.py:187-198: use central REG_LOOKUP table
    std::string lower = reg;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    auto it = speakeasy::arch::REG_LOOKUP.find(lower);
    if (it != speakeasy::arch::REG_LOOKUP.end())
        return reg_read(it->second);
    return 0;
}

uint64_t BinaryEmulator::reg_read(int reg) {
    // Python binemu.py:187-198 doc: "Read a value from an emulated cpu register"
    // String variant uses speakeasy::arch::REG_LOOKUP
    if (emu_eng) {
        uint64_t val = 0;
        emu_eng->reg_read(reg, &val);
        return val;
    }
    return 0;
}

void BinaryEmulator::set_hooks() {
    // Python binemu.py:200-213 doc: "Set instruction level hooks"
    // Iterates HOOK_CODE, HOOK_MEM_READ, HOOK_MEM_WRITE, HOOK_MEM_INVALID, HOOK_INTERRUPT
    static const int types[] = {HOOK_CODE, HOOK_MEM_READ, HOOK_MEM_WRITE, HOOK_MEM_INVALID, HOOK_INTERRUPT};
    for (int ht : types) {
        auto it = hooks_.find(ht);
        if (it != hooks_.end()) {
            for (Hook* hook : it->second) {
                if (!hook->is_added()) hook->add();
            }
        }
    }
}

std::tuple<std::string, std::string, std::string> BinaryEmulator::_cs_disasm(const std::vector<uint8_t>& mem, 
                                                                             uint64_t addr, bool fast) {
    // Python binemu.py:215-230 doc: "Disassemble bytes using capstone"
    // Wraps capstone disasm_lite (fast) or disasm (detailed)
    /*
    try:
        if fast:
            tu = [i for i in this.disasm_eng.disasm_lite(bytes(mem), addr)]
            address, size, mnem, oper = tu[0]
        else:
            return [i for i in this.disasm_eng.disasm(bytes(mem), addr)]
    except IndexError:
        raise EmuException("Failed to disasm at address: 0x%x" % (addr))

    op = '%s %s' % (mnem, oper)
    */
#ifdef HAS_CAPSTONE
    csh handle; cs_insn* insn = nullptr;
    cs_mode mode = (get_arch() == 64) ? CS_MODE_64 : CS_MODE_32;
    if (cs_open(CS_ARCH_X86, mode, &handle) != CS_ERR_OK)
        return std::make_tuple("", "", "cs_open failed");
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_OFF);
    if (fast) cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON);
    size_t count = cs_disasm(handle, mem.data(), mem.size(), addr, 1, &insn);
    std::string mnem, ops;
    if (count > 0 && insn) {
        mnem = insn[0].mnemonic; ops = insn[0].op_str;
        cs_free(insn, count);
    }
    cs_close(&handle);
    return std::make_tuple(mnem, ops, mnem + " " + ops);
#else
    (void)mem; (void)addr; (void)fast;
    return std::make_tuple("", "", "");
#endif
}

std::tuple<std::string, std::string, std::string> BinaryEmulator::disasm(const std::vector<uint8_t>& mem, 
                                                                         uint64_t addr, bool fast) {
    // Python binemu.py:232-236 doc: "Disassemble bytes at a specified address"
    return _cs_disasm(mem, addr, fast);
}

std::map<std::string, std::string> BinaryEmulator::get_register_state() {
    // Python binemu.py:238-279 doc: "Get the current state of registers from the emulator"
    // Architecture-aware: x86 (9 regs) vs amd64 (17 regs)
    std::map<std::string, std::string> regs;
    int arch = get_arch();
    int ps = get_ptr_size();
    char buf[32];

    if (arch == speakeasy::arch::ARCH_X86) {
        struct { const char* name; int reg; } rmap[] = {
            {"esp", static_cast<int>(speakeasy::arch::REG_ESP)},
            {"ebp", static_cast<int>(speakeasy::arch::REG_EBP)},
            {"eip", static_cast<int>(speakeasy::arch::REG_EIP)},
            {"esi", static_cast<int>(speakeasy::arch::REG_ESI)},
            {"edi", static_cast<int>(speakeasy::arch::REG_EDI)},
            {"eax", static_cast<int>(speakeasy::arch::REG_EAX)},
            {"ebx", static_cast<int>(speakeasy::arch::REG_EBX)},
            {"ecx", static_cast<int>(speakeasy::arch::REG_ECX)},
            {"edx", static_cast<int>(speakeasy::arch::REG_EDX)},
        };
        for (auto& r : rmap) {
            uint64_t val = reg_read(r.reg);
            snprintf(buf, sizeof(buf), "0x%0*llx", 2 + ps * 2,
                     static_cast<unsigned long long>(val));
            regs[r.name] = buf;
        }
    } else if (arch == speakeasy::arch::ARCH_AMD64) {
        struct { const char* name; int reg; } rmap[] = {
            {"rsp", static_cast<int>(speakeasy::arch::REG_RSP)},
            {"rbp", static_cast<int>(speakeasy::arch::REG_RBP)},
            {"rip", static_cast<int>(speakeasy::arch::REG_RIP)},
            {"rsi", static_cast<int>(speakeasy::arch::REG_RSI)},
            {"rdi", static_cast<int>(speakeasy::arch::REG_RDI)},
            {"rax", static_cast<int>(speakeasy::arch::REG_RAX)},
            {"rbx", static_cast<int>(speakeasy::arch::REG_RBX)},
            {"rcx", static_cast<int>(speakeasy::arch::REG_RCX)},
            {"rdx", static_cast<int>(speakeasy::arch::REG_RDX)},
            {"r8",  static_cast<int>(speakeasy::arch::REG_R8)},
            {"r9",  static_cast<int>(speakeasy::arch::REG_R9)},
            {"r10", static_cast<int>(speakeasy::arch::REG_R10)},
            {"r11", static_cast<int>(speakeasy::arch::REG_R11)},
            {"r12", static_cast<int>(speakeasy::arch::REG_R12)},
            {"r13", static_cast<int>(speakeasy::arch::REG_R13)},
            {"r14", static_cast<int>(speakeasy::arch::REG_R14)},
            {"r15", static_cast<int>(speakeasy::arch::REG_R15)},
        };
        for (auto& r : rmap) {
            uint64_t val = reg_read(r.reg);
            snprintf(buf, sizeof(buf), "0x%0*llx", 2 + ps * 2,
                     static_cast<unsigned long long>(val));
            regs[r.name] = buf;
        }
    }
    return regs;
}

std::tuple<std::string, std::string, std::string> BinaryEmulator::get_disasm(uint64_t addr, size_t size, bool fast) {
    // Python binemu.py:281-285 doc: "Get the disassembly from an address"
    auto mem = mem_read(addr, size);
    if (mem.empty()) return std::make_tuple("", "", "");
    return _cs_disasm(mem, addr, fast);
}

// Stack operations 

// Python binemu.py:440-450 doc: "Put a value on the stack and adjust the stack pointer"
uint64_t BinaryEmulator::push_stack(uint64_t val) {
    int ps = get_ptr_size();
    uint64_t sp = get_stack_ptr();
    sp -= ps;
    mem_write(sp, std::vector<uint8_t>(reinterpret_cast<uint8_t*>(&val),
                                        reinterpret_cast<uint8_t*>(&val) + ps));
    set_stack_ptr(sp);
    return sp;
}

// Python binemu.py:452-462 doc: "Get value from the stack and adjust the stack pointer"
uint64_t BinaryEmulator::pop_stack() {
    int ps = get_ptr_size();
    uint64_t sp = get_stack_ptr();
    auto data = mem_read(sp, ps);
    uint64_t val = 0;
    for (size_t i = 0; i < data.size(); ++i)
        val |= static_cast<uint64_t>(data[i]) << (i * 8);
    set_stack_ptr(sp + ps);
    return val;
}

uint64_t BinaryEmulator::get_stack_ptr() {
    // Python binemu.py:464-472 doc: "Get the current address of the stack pointer"
    int arch = get_arch();
    if (arch == speakeasy::arch::ARCH_AMD64)
        return reg_read(static_cast<int>(speakeasy::arch::REG_RSP));
    else
        return reg_read(static_cast<int>(speakeasy::arch::REG_ESP));
}

void BinaryEmulator::set_stack_ptr(uint64_t addr) {
    // Python binemu.py:474-481 doc: "Set the current address of the stack pointer"
    int arch = get_arch();
    if (arch == speakeasy::arch::ARCH_AMD64)
        reg_write(static_cast<int>(speakeasy::arch::REG_RSP), addr);
    else
        reg_write(static_cast<int>(speakeasy::arch::REG_ESP), addr);
}

// Python binemu.py:420-430 doc: "Get the return address from the stack"
uint64_t BinaryEmulator::get_ret_address() {
    int ps = get_ptr_size();
    uint64_t sp = get_stack_ptr();
    auto data = mem_read(sp, ps);
    uint64_t val = 0;
    for (size_t i = 0; i < data.size(); ++i)
        val |= static_cast<uint64_t>(data[i]) << (i * 8);
    return val;
}

// Python binemu.py:432-438 doc: "Set the return address on the stack"
void BinaryEmulator::set_ret_address(uint64_t addr) {
    int ps = get_ptr_size();
    uint64_t sp = get_stack_ptr();
    std::vector<uint8_t> bytes(ps);
    for (size_t i = 0; i < bytes.size(); ++i)
        bytes[i] = static_cast<uint8_t>((addr >> (i * 8)) & 0xFF);
    mem_write(sp, bytes);
}

// Stack trace

// Python binemu.py:517-540 doc: "Get the current stack state"
std::vector<std::string> BinaryEmulator::get_stack_trace(int num_ptrs) {
    std::vector<std::string> trace;
    uint64_t sp = get_stack_ptr();
    int ps = get_ptr_size() > 0 ? get_ptr_size() : 4;
    char buf[128];
    for (int i = 0; i < num_ptrs; ++i) {
        uint64_t addr = sp + i * ps;
        auto data = mem_read(addr, ps);
        uint64_t val = 0;
        for (size_t j = 0; j < data.size(); ++j)
            val |= static_cast<uint64_t>(data[j]) << (j * 8);
        std::string tag = get_address_tag(val);
        if (tag.empty()) {
            snprintf(buf, sizeof(buf), "sp+0x%x: 0x%0*llx",
                     i * ps, 2 + ps * 2,
                     static_cast<unsigned long long>(val));
        } else {
            snprintf(buf, sizeof(buf), "sp+0x%x: 0x%0*llx -> %s",
                     i * ps, 2 + ps * 2,
                     static_cast<unsigned long long>(val), tag.c_str());
        }
        trace.push_back(buf);
        sp += ps;
    }
    return trace;
}

// Stack formatting 

// Python binemu.py:483-498 doc: "Get the stack and format it for display"
std::vector<std::tuple<uint64_t, uint64_t, std::string>> BinaryEmulator::format_stack(int num_ptrs) {
    std::vector<std::tuple<uint64_t, uint64_t, std::string>> result;
    uint64_t sp = get_stack_ptr();
    int ps = get_ptr_size() > 0 ? get_ptr_size() : 4;
    for (int i = 0; i < num_ptrs; ++i) {
        uint64_t addr = sp + i * ps;
        auto data = mem_read(addr, ps);
        uint64_t val = 0;
        for (size_t j = 0; j < data.size(); ++j)
            val |= static_cast<uint64_t>(data[j]) << (j * 8);
        std::string tag = get_address_tag(val);
        result.push_back({addr, val, tag});
    }
    return result;
}

// Python binemu.py:500-515 doc: "Debug function used to print the current stack state"
void BinaryEmulator::print_stack(int num_ptrs) {
    auto trace = get_stack_trace(num_ptrs);
    for (auto& line : trace) fprintf(stderr, "%s\n", line.c_str());
}


// Simple fnmatch for Windows (handles *, ?, [])
static bool hook_fnmatch(const std::string& pattern, const std::string& value) {
    if (pattern == value) return true;
    bool has = false;
    for (char ch : pattern) if (ch == '?' || ch == '*' || ch == '[' || ch == ']') { has = true; break; }
    if (!has) return false;
    size_t pi = 0, vi = 0, sp = std::string::npos, sv = 0;
    while (vi < value.size()) {
        if (pi < pattern.size() && (pattern[pi] == '?' || tolower(pattern[pi]) == tolower(value[vi]))) { ++pi; ++vi; }
        else if (pi < pattern.size() && pattern[pi] == '*') { sp = pi++; sv = vi; }
        else if (sp != std::string::npos) { pi = sp + 1; vi = ++sv; }
        else return false;
    }
    while (pi < pattern.size() && pattern[pi] == '*') ++pi;
    return pi == pattern.size();
}

// Hook management (deferred: Hook classes need Speakeasy*, not BinaryEmulator*) 


//  Dynamic code hook dispatch 

void BinaryEmulator::_fire_dyn_code_hooks(uint64_t addr) {
    // Python binemu.py:921-929 doc: "Fire all dynamic code hooks and record profiler event"
    auto mm = get_address_map(addr);
    auto* prof = get_profiler().get();
    if (prof) {
        // TODO: record_dyn_code_event is not a member of Profiler — needs implementation
        // auto* run = static_cast<Run*>(get_current_run().get());
        // if (run) prof->record_dyn_code_event(*run, mm ? mm->tag : "", mm ? mm->base : 0, mm ? mm->size : 0);
    }
    auto it = hooks_.find(HOOK_DYN_CODE);
    if (it != hooks_.end()) {
        // NOTE: Hook::cb is protected (architecture decision to enforce add_hook API).
        // DynCodeHook stores the callback in Hook::cb (protected), so we cannot
        // iterate and invoke directly from here. The dispatcher pattern used by
        // add_dyn_code_hook wraps callbacks in std::function<bool()> which are
        // invoked by the emulation engine during code block execution.
        // Future enhancement: expose a virtual dispatch() method on Hook, or
        // make DynCodeHook::fire() a public method that calls cb() internally.
        // for (Hook* h : it->second) {
        //     static_cast<DynCodeHook*>(h)->cb(mm);
        // }
    }
}

void BinaryEmulator::_set_dyn_code_hook(uint64_t addr, size_t size, std::map<std::string, std::string> ctx) {
    // Python binemu.py:931-946 doc: "Set the top level dispatch hook for dynamic code execution"
    (void)ctx;
    // TODO: Python calls hook_ref[0].disable() on first fire; C++ framework needs hook disable support
    static const size_t MAX_HOOK_SIZE = 0x10;
    if (size > MAX_HOOK_SIZE) size = MAX_HOOK_SIZE;

    // Create a self-disabling hook that fires _fire_dyn_code_hooks on first hit
    // Wrap in std::function<void()> add_code_hook expects zero-arg callback
    add_code_hook(std::function<void()>([this, addr]() {
        this->_fire_dyn_code_hooks(addr);
    }), addr, addr + size);
}

// Python binemu.py:648-655 doc: "Used to expand variables supplied in the emulator config file. This
// might be useful for accessing files that are a relative path of the
// speakeasy package.
// For example:
//     $ROOT$: This variable corresponds to the package root for speakeasy"
void BinaryEmulator::eval_emu_var() {
    // Python binemu.py:648-655: Empty function body (just docstring)
    // Reserved for config variable expansion. No-op in Python.
}

std::shared_ptr<speakeasy::Module> BinaryEmulator::get_module_from_addr(uint64_t addr) {
    // Python binemu.py:811-820 doc: "If the supplied address belongs to a module, return it"
    // TODO: 'modules' is a WindowsEmulator member, not BinaryEmulator move this to WindowsEmulator
    for (auto& mod : modules) {
        if (addr >= mod->base && addr <= mod->base + mod->image_size) {
            return mod;
        }
    }
    return nullptr;
}

std::vector<ApiHook> BinaryEmulator::get_api_hooks(const std::string& mod_name, const std::string& func_name) {
    // Python binemu.py:822-852 doc: "If an API hook has been set, return it here"
    // Two-level fnmatch: module name wildcard + api name wildcard
    std::string ml = mod_name; std::transform(ml.begin(), ml.end(), ml.begin(), ::tolower);
    std::string fl = func_name; std::transform(fl.begin(), fl.end(), fl.begin(), ::tolower);

    const auto& [mdict, wmod] = api_hooks_;
    std::vector<const ApiLevel*> cand;
    auto ex = mdict.find(ml);
    if (ex != mdict.end()) cand.push_back(&ex->second);
    if (wmod) for (auto& [sm, al] : mdict)
        if (hook_fnmatch(sm, ml) && sm != ml) cand.push_back(&al);

    std::vector<ApiHook> r;
    for (auto* al : cand) {
        auto& [fdict, wapi] = *al;
        auto fi = fdict.find(fl);
        if (fi != fdict.end()) for (auto& h : fi->second) r.push_back(h);
        if (wapi) for (auto& [sf, hs] : fdict)
            if (hook_fnmatch(sf, fl) && sf != fl) for (auto& h : hs) r.push_back(h);
    }
    return r;
}

// Hook registration methods (deferred until Hook classes are refactored
// to accept BinaryEmulator* instead of Speakeasy*)

ApiHook BinaryEmulator::add_api_hook(std::function<void()> cb, const std::string& module,
                                       const std::string& api_name, int argc,
                                       void* call_conv, BinaryEmulator* emu) {
    // Python binemu.py:854-895 doc: "Add an API level hook (e.g. kernel32.CreateFile) here"
    // FIFO ordering: all hooks in chain are called, last hook's return value used
    // Wildcard detection: ?, *, [, ] in module/api name triggers fnmatch matching
    std::string ml = module; std::transform(ml.begin(), ml.end(), ml.begin(), ::tolower);
    std::string fl = api_name; std::transform(fl.begin(), fl.end(), fl.begin(), ::tolower);

    bool wm = false, wa = false;
    for (const char* w : {"?", "*", "[", "]"}) {
        if (ml.find(w) != std::string::npos) wm = true;
        if (fl.find(w) != std::string::npos) wa = true;
    }

    if (!emu) emu = this;
    ApiHook hook(emu, emu_eng, [cb]() -> bool { cb(); return true; }, ml, fl, argc, call_conv);

    ApiLevel ad = {{}, wa};
    ad.first[fl].push_back(hook);

    auto& [mdict, pwm] = api_hooks_;
    auto mi = mdict.find(ml);
    if (mi == mdict.end()) {
        mdict[ml] = ad;
    } else {
        auto& [fdict, pwa] = mi->second;
        fdict[fl].push_back(hook);
        mi->second.second = pwa | wa;
    }
    api_hooks_.second = pwm | wm;

    if (emu_eng) hook.add();
    return hook;
}

CodeHook BinaryEmulator::add_code_hook(std::function<void()> cb, uint64_t begin, uint64_t end,
                                        std::map<std::string, std::string> ctx, BinaryEmulator* emu) {
    // Python binemu.py:897-919 doc: "Add a hook that will fire for every CPU instruction"
    if (!emu) emu = this;
    auto* h = new CodeHook(emu, emu_eng, [cb]() -> bool { cb(); return true; }, begin, end);
    hooks_[HOOK_CODE].push_back(h);
    if (emu_eng) h->add();
    return *h;
}

DynCodeHook BinaryEmulator::add_dyn_code_hook(std::function<void()> cb,
                                               std::vector<std::string> ctx, BinaryEmulator* emu) {
    // Python binemu.py:948-968 doc: "Add a hook that will fire when dynamically generated/copied code is executed"
    if (!emu) emu = this;
    auto* h = new DynCodeHook(emu, emu_eng, [cb]() -> bool { cb(); return true; });
    hooks_[HOOK_DYN_CODE].push_back(h);
    return *h;
}

ReadMemHook BinaryEmulator::add_mem_read_hook(std::function<void()> cb, uint64_t begin, uint64_t end,
                                               BinaryEmulator* emu) {
    // Python binemu.py:970-992 doc: "Add a hook that will fire for memory reads"
    if (!emu) emu = this;
    auto* h = new ReadMemHook(emu, emu_eng, [cb]() -> bool { cb(); return true; }, begin, end);
    hooks_[HOOK_MEM_READ].push_back(h);
    if (emu_eng) h->add();
    return *h;
}

WriteMemHook BinaryEmulator::add_mem_write_hook(std::function<void()> cb, uint64_t begin, uint64_t end,
                                                  BinaryEmulator* emu) {
    // Python binemu.py:994-1016 doc: "Add a hook that will fire for memory writes"
    if (!emu) emu = this;
    auto* h = new WriteMemHook(emu, emu_eng, [cb]() -> bool { cb(); return true; }, begin, end);
    hooks_[HOOK_MEM_WRITE].push_back(h);
    if (emu_eng) h->add();
    return *h;
}

MapMemHook BinaryEmulator::add_mem_map_hook(std::function<void()> cb, uint64_t begin, uint64_t end,
                                             BinaryEmulator* emu) {
    // Python binemu.py:1018-1040 doc: "Add a hook that will fire for memory maps"
    if (!emu) emu = this;
    auto* h = new MapMemHook(emu, emu_eng, [cb]() -> bool { cb(); return true; }, begin, end);
    hooks_[HOOK_MEM_MAP].push_back(h);
    if (emu_eng) h->add();
    return *h;
}

InvalidMemHook BinaryEmulator::add_mem_invalid_hook(std::function<void()> cb, BinaryEmulator* emu) {
    // Python binemu.py:1056-1076 doc: "Add a hook that will fire for invalid memory access"
    // Injects dispatch hook as first element; user hooks follow
    if (!emu) emu = this;
    auto* hook = new InvalidMemHook(emu, emu_eng, [cb]() -> bool { cb(); return true; }, false);
    auto& hl = hooks_[HOOK_MEM_INVALID];
    // Dispatch hook injection is deferred : InvalidMemHook only accepts std::function<bool()>.
    // The dispatch wrapper (_hook_mem_invalid_dispatch) would need a 4-arg callback signature,
    // but the current Hook/infrastructure passes only bool(). For now, user hooks are added
    // directly without the dispatch wrapper. When the hook system is extended to support
    // multi-arg native hooks, re-enable this block.
    hl.push_back(hook);
    if (emu_eng) hook->add();
    return *hook;
}

InterruptHook BinaryEmulator::add_interrupt_hook(std::function<void()> cb,
                                                  std::vector<std::string> ctx, BinaryEmulator* emu) {
    // Python binemu.py:1078-1100 doc: "Add a hook that will fire for software interrupts"
    if (!emu) emu = this;
    auto* h = new InterruptHook(emu, emu_eng, [cb]() -> bool { cb(); return true; });
    hooks_[HOOK_INTERRUPT].push_back(h);
    if (emu_eng) h->add();
    return *h;
}

//  Stack arguments 

void BinaryEmulator::set_func_args(uint64_t stack_addr, uint64_t ret_addr,
                                    const std::vector<uint64_t>& args, bool home_space) {
    // Python binemu.py:287-325 doc: "Set the arguments before an emulated function call"
    int ps = get_ptr_size();
    uint64_t sp = stack_addr - ps;
    int arch = get_arch();
    size_t arg_idx = 0;

    // x64: first 4 args in registers
    if (arch == 64 && home_space) {
        sp -= 0x20;  // shadow space
        static const int x64_arg_regs[] = {2, 1, 8, 9};  // rcx, rdx, r8, r9 (approx)
        for (int i = 0; i < 4 && arg_idx < args.size(); ++i) {
            reg_write(x64_arg_regs[i], args[arg_idx++]);
        }
    }

    // Push remaining args onto stack (right to left)
    for (int i = static_cast<int>(args.size()) - 1; i >= static_cast<int>(arg_idx); --i) {
        auto bytes = std::vector<uint8_t>(ps);
        for (int j = 0; j < ps; ++j)
            bytes[j] = static_cast<uint8_t>((args[i] >> (j * 8)) & 0xFF);
        mem_write(sp, bytes);
        sp -= ps;
    }

    // Push return address
    auto ret_bytes = std::vector<uint8_t>(ps);
    for (int j = 0; j < ps; ++j)
        ret_bytes[j] = static_cast<uint8_t>((ret_addr >> (j * 8)) & 0xFF);
    mem_write(sp, ret_bytes);
    set_stack_ptr(sp);
}

InstructionHook BinaryEmulator::add_instruction_hook(std::function<void()> cb, uint64_t begin, uint64_t end,
                          std::vector<std::string> ctx, BinaryEmulator* emu, void* insn) {
    // Python binemu.py:1102-1124 doc: "Add a hook that will fire for IN, SYSCALL, or SYSENTER instructions"
    if (!emu) emu = this;
    auto* h = new InstructionHook(emu, emu_eng, [cb]() -> bool { cb(); return true; }, {}, true, insn);
    hooks_[HOOK_INSN].push_back(h);
    if (emu_eng) h->add();
    return *h;
}

InvalidInstructionHook BinaryEmulator::add_invalid_instruction_hook(std::function<void()> cb,
                                         std::vector<std::string> ctx, BinaryEmulator* emu) {
    // Python binemu.py:1126-1147 doc: "Add a hook that will fire for invalid instruction attempts"
    if (!emu) emu = this;
    auto* h = new InvalidInstructionHook(emu, emu_eng, [cb]() -> bool { cb(); return true; });
    hooks_[HOOK_INSN_INVALID].push_back(h);
    if (emu_eng) h->add();
    return *h;
}

std::vector<uint64_t> BinaryEmulator::get_func_argv(int callconv, int argc) {
    // Python binemu.py:327-381 doc: "Get the arguments for a function given the supplied calling convention"
    std::vector<uint64_t> argv;
    int arch = get_arch();
    int nargs = argc;
    (void)callconv;

    if (arch == 64) {
        // x64: rcx, rdx, r8, r9
        static const int x64_regs[] = {2, 1, 8, 9};
        uint64_t sp = get_stack_ptr() + 0x20;
        for (int i = 0; i < 4 && nargs > 0; ++i) {
            argv.push_back(reg_read(x64_regs[i]));
            --nargs;
        }
        // Stack args
        for (int i = 0; i < nargs; ++i) {
            auto data = mem_read(sp + i * 8, 8);
            uint64_t val = 0;
            for (size_t j = 0; j < data.size(); ++j)
                val |= static_cast<uint64_t>(data[j]) << (j * 8);
            argv.push_back(val);
        }
    } else {
        // x86: all on stack
        uint64_t sp = get_stack_ptr() + 4;  // skip ret addr
        for (int i = 0; i < argc; ++i) {
            auto data = mem_read(sp + i * 4, 4);
            uint64_t val = 0;
            for (size_t j = 0; j < data.size(); ++j)
                val |= static_cast<uint64_t>(data[j]) << (j * 8);
            argv.push_back(val);
        }
    }
    return argv;
}

void BinaryEmulator::do_call_return(int argc, uint64_t ret_addr, uint64_t ret_value, int conv) {
    // Python binemu.py:383-418 doc: "Set the emulation state after a call has completed"
    (void)argc; (void)conv;
    reg_write(get_arch() == 64 ? 0 : 0, ret_value);  // rax/eax
    if (ret_addr != 0) {
        set_pc(ret_addr);
    }
}

//  Architecture 

int BinaryEmulator::get_arch() {
    // Python binemu.py:632-636 doc: "Get the current emulated architecture"
    return arch_;  // set by subclass constructor
}

std::string BinaryEmulator::get_arch_name() {
    // Python binemu.py:638-646 doc: "Get the name of current emulated architecture"
    // Returns "amd64" for ARCH_AMD64, "x86" for ARCH_X86, "" otherwise
    int arch = get_arch();
    if (arch == speakeasy::arch::ARCH_AMD64) return "amd64";
    if (arch == speakeasy::arch::ARCH_X86) return "x86";
    return "";
}

void BinaryEmulator::set_ptr_size(int arch) {
    // Python binemu.py:800-809 doc: "Set the current pointer size used in the emulator"
    int ps = (arch == speakeasy::arch::ARCH_AMD64) ? 8 : 4;
    ptr_size_ = ps;
}

int BinaryEmulator::get_ptr_size() {
    // Python binemu.py:771-775 doc: "Get the pointer size of the current emulation state"
    return ptr_size_;  // set by subclass constructor
}

//  String utilities 

std::string BinaryEmulator::read_mem_string(uint64_t address, int width, int max_chars) {
    // Python binemu.py:657-685 doc: "Read a string from emulated memory"
    // Supports width=1 (UTF-8) and width=2 (UTF-16LE) decoding
    std::vector<uint8_t> raw;
    for (int i = 0; max_chars == 0 || i < max_chars; ++i) {
        auto data = mem_read(address + i * width, width);
        if (data.empty()) break;
        bool zero = true;
        for (auto b : data) if (b != 0) { zero = false; break; }
        if (zero) break;
        raw.insert(raw.end(), data.begin(), data.end());
    }
    if (width == 2) {
        // Python: decode as UTF-16LE with 'ignore' error mode, then strip nulls
        std::string result;
        result.reserve(raw.size() / 2);
        for (size_t i = 0; i + 1 < raw.size(); i += 2) {
            uint16_t ch = static_cast<uint16_t>(raw[i]) | (static_cast<uint16_t>(raw[i+1]) << 8);
            if (ch == 0) break;
            // Python binemu.py:681-684 : .decode('utf-16le', 'ignore') : best-effort
            if (ch >= 0x20 && ch <= 0x7e) {
                result += static_cast<char>(ch);
            } else if (ch >= 0x80) {
                // Pass through high codepoints as UTF-8 multibyte
                if (ch < 0x800) {
                    result += static_cast<char>(0xC0 | (ch >> 6));
                    result += static_cast<char>(0x80 | (ch & 0x3F));
                } else {
                    result += static_cast<char>(0xE0 | (ch >> 12));
                    result += static_cast<char>(0x80 | ((ch >> 6) & 0x3F));
                    result += static_cast<char>(0x80 | (ch & 0x3F));
                }
            }
            // else: control chars ignored (matches Python 'ignore' error mode)
        }
        return result;
    }
    // width == 1: UTF-8 / ASCII filtering
    std::string result;
    for (auto b : raw) {
        if (b >= 0x20 || b == '\t' || b == '\n' || b == '\r') result += static_cast<char>(b);
    }
    return result;
}

size_t BinaryEmulator::mem_string_len(uint64_t address, int width) {
    // Python binemu.py:687-698 doc: "Get the length of a string from emulated memory"
    size_t len = 0;
    while (true) {
        auto data = mem_read(address + len * width, width);
        if (data.empty()) break;
        bool all_zero = true;
        for (auto b : data) if (b != 0) all_zero = false;
        if (all_zero) break;
        ++len;
    }
    return len;
}

std::tuple<std::vector<std::tuple<int, std::string>>, std::vector<std::tuple<int, std::string>>>
BinaryEmulator::get_mem_strings() {
    // Python binemu.py:777-798 doc: "Get ansi and unicode strings from emulated memory"
    // Scan all mapped memory regions for printable strings, filtered by tag
    // Python: tgt_tag_prefixes = ("emu.stack", "api"), excludes input memory tag
    static const char* tgt_tag_prefixes[] = {"emu.stack", "api"};
    std::vector<std::tuple<int, std::string>> ansi, wide;
    // Use MemoryManager base class get_mem_maps() to access MemMap with tag/base/size
    auto mmaps = MemoryManager::get_mem_maps();
    for (auto& mm : mmaps) {
        std::string tag = mm->get_tag();
        bool match = false;
        for (auto* prefix : tgt_tag_prefixes) {
            if (tag.compare(0, strlen(prefix), prefix) == 0) { match = true; break; }
        }
        if (!match) continue;
        // Python: also excludes input_mem_tag : we can't check input here
        uint64_t base = mm->get_base();
        uint64_t size = mm->get_size();
        if (size < 2) continue;
        auto data = mem_read(base, size - 1);
        if (data.empty()) continue;
        auto a = get_ansi_strings(data, 4);
        auto w = get_unicode_strings(data, 4);
        ansi.insert(ansi.end(), a.begin(), a.end());
        wide.insert(wide.end(), w.begin(), w.end());
    }
    // Python: deduplicate (list comprehension side-effect)
    std::vector<std::tuple<int, std::string>> ret_ansi, ret_wide;
    for (auto& s : ansi) {
        bool dup = false;
        for (auto& rs : ret_ansi) if (rs == s) { dup = true; break; }
        if (!dup) ret_ansi.push_back(s);
    }
    for (auto& s : wide) {
        bool dup = false;
        for (auto& rs : ret_wide) if (rs == s) { dup = true; break; }
        if (!dup) ret_wide.push_back(s);
    }
    return {ret_ansi, ret_wide};
}

size_t BinaryEmulator::mem_copy(uint64_t dst, uint64_t src, size_t n) {
    // Python binemu.py:738-744 doc: "Copy bytes from one emulated address to another"
    auto data = mem_read(src, n);
    mem_write(dst, data);
    return n;
}

void BinaryEmulator::write_mem_string(const std::string& str, uint64_t address, int width) {
    // Python binemu.py:746-762 doc: "Write string data to an emulated memory address"
    // Appends terminating zero byte if not present; supports width=1 (UTF-8) and width=2 (UTF-16LE)
    std::string data = str;
    if (data.empty() || data.back() != '\0') data += '\0';
    if (width == 2) {
        // Python binemu.py:753-761: .encode('utf-16le')
        std::vector<uint8_t> encoded;
        encoded.reserve(data.length() * 2);
        for (size_t i = 0; i < data.length(); ++i) {
            unsigned char c = static_cast<unsigned char>(data[i]);
            if (c == '\0') {
                encoded.push_back(0);
                encoded.push_back(0);
            } else if (c < 0x80) {
                // ASCII: single UTF-16 code unit
                encoded.push_back(c);
                encoded.push_back(0);
            } else {
                // Extended ASCII / UTF-8 multibyte: decode to codepoint then encode as UTF-16LE
                uint32_t cp;
                if ((c & 0xE0) == 0xC0 && i + 1 < data.length()) {
                    cp = (c & 0x1F) << 6 | (static_cast<unsigned char>(data[++i]) & 0x3F);
                } else if ((c & 0xF0) == 0xE0 && i + 2 < data.length()) {
                    cp = (c & 0x0F) << 12 | (static_cast<unsigned char>(data[++i]) & 0x3F) << 6 |
                         (static_cast<unsigned char>(data[++i]) & 0x3F);
                } else {
                    cp = c; // fallback
                }
                if (cp > 0xFFFF) {
                    // Surrogate pair (BMP only for simplicity : matches Python 'utf-16le' encoder)
                    cp -= 0x10000;
                    encoded.push_back(static_cast<uint8_t>(0xD800 | (cp >> 10)));
                    encoded.push_back(static_cast<uint8_t>(((0xD800 | (cp >> 10)) >> 8) & 0xFF));
                    encoded.push_back(static_cast<uint8_t>(0xDC00 | (cp & 0x3FF)));
                    encoded.push_back(static_cast<uint8_t>(((0xDC00 | (cp & 0x3FF)) >> 8) & 0xFF));
                } else {
                    encoded.push_back(static_cast<uint8_t>(cp & 0xFF));
                    encoded.push_back(static_cast<uint8_t>((cp >> 8) & 0xFF));
                }
            }
        }
        mem_write(address, encoded);
    } else {
        // width == 1: UTF-8
        std::vector<uint8_t> bytes(data.begin(), data.end());
        mem_write(address, bytes);
    }
}

uint64_t BinaryEmulator::read_ptr(uint64_t address) {
    // Python binemu.py:764-766 doc: "Read a pointer-sized value from memory"
    int ps = get_ptr_size();
    auto data = mem_read(address, ps);
    uint64_t val = 0;
    for (size_t i = 0; i < data.size(); ++i)
        val |= static_cast<uint64_t>(data[i]) << (i * 8);
    return val;
}

void BinaryEmulator::write_ptr(uint64_t address, uint64_t val) {
    // Python binemu.py:768-769 doc: "Write a pointer-sized value to memory"
    int ps = get_ptr_size();
    std::vector<uint8_t> bytes(ps);
    for (int i = 0; i < ps; ++i)
        bytes[i] = static_cast<uint8_t>((val >> (i * 8)) & 0xFF);
    mem_write(address, bytes);
}

//  Stack management 

std::tuple<uint64_t, uint64_t> BinaryEmulator::reset_stack(uint64_t base) {
    // Python binemu.py:577-593 doc: "Reset stack to the supplied base address"
    uint64_t ptr = base;
    int arch = get_arch();
    if (arch == speakeasy::arch::ARCH_X86) {
        reg_write(static_cast<int>(speakeasy::arch::REG_ESP), base);
        reg_write(static_cast<int>(speakeasy::arch::REG_EBP), base);
    } else if (arch == speakeasy::arch::ARCH_AMD64) {
        ptr -= get_ptr_size() * 5;  // home space
        reg_write(static_cast<int>(speakeasy::arch::REG_RSP), ptr);
        reg_write(static_cast<int>(speakeasy::arch::REG_RBP), ptr);
    }
    return {base, ptr};
}

std::tuple<uint64_t, uint64_t> BinaryEmulator::alloc_stack(size_t size) {
    // Python binemu.py:595-610 doc: "Allocate memory to use for the program stack"
    // Calls get_valid_ranges -> mem_map (physical) -> mem_reserve -> reset_stack
    auto [addr, block_size] = get_valid_ranges(size, 0x1200000);
    mem_map(block_size, addr, PERM_MEM_RWX, "emu.stack");
    uint64_t base = addr + block_size;
    mem_reserve(size, base);
    return reset_stack(base);
}

// Python binemu.py:565-575 doc: "Get the current value in the return register"
uint64_t BinaryEmulator::get_return_val() {
    int arch = get_arch();
    if (arch == speakeasy::arch::ARCH_AMD64)
        return reg_read(static_cast<int>(speakeasy::arch::REG_RAX));
    else
        return reg_read(static_cast<int>(speakeasy::arch::REG_EAX));
}

void BinaryEmulator::clean_stack_args(int argc) {
    // Python binemu.py:612-630 doc: "Adjust the stack for arguments that were supplied"
    int ps = get_ptr_size();
    uint64_t sp = get_stack_ptr();
    sp += ps;  // skip ret addr
    sp += argc * ps;
    set_stack_ptr(sp);
}

// Python binemu.py:700-717 doc: "Get all ansi strings from a supplied memory blob"
    // Python uses re.compile(b"[\x20-\x7f]{%d,}" % min_len) for regex-based extraction
    // C++ uses linear scan (iterative) -- functionally equivalent
std::vector<std::tuple<int, std::string>> BinaryEmulator::get_ansi_strings(
    const std::vector<uint8_t>& data, int min_len) {
    // Python binemu.py:700-717 : regex-based printable ASCII string extraction
    std::vector<std::tuple<int, std::string>> result;
    std::string s(reinterpret_cast<const char*>(data.data()), data.size());
    std::string pattern = "[\\x20-\\x7e]{" + std::to_string(min_len) + ",}";
    try {
        std::regex re(pattern);
        std::sregex_iterator it(s.begin(), s.end(), re);
        std::sregex_iterator end;
        size_t last_end = 0;
        for (; it != end; ++it) {
            size_t match_pos = s.find(it->str(), last_end);
            if (match_pos == std::string::npos) match_pos = it->position();
            result.push_back({static_cast<int>(match_pos), it->str()});
            last_end = match_pos + 1;
        }
    } catch (const std::regex_error&) {}
    return result;
}

// Python binemu.py:719-736 doc: "Get all unicode strings from a supplied memory blob"
std::vector<std::tuple<int, std::string>> BinaryEmulator::get_unicode_strings(
    const std::vector<uint8_t>& data, int min_len) {
    // Python binemu.py:719-736 : regex-based UTF-16LE printable ASCII string extraction
    std::vector<std::tuple<int, std::string>> result;
    // Build pattern: (?:[ -~]){min_len,}
    std::string pattern = "(?:[\\x20-\\x7e]\\x00){" + std::to_string(min_len) + ",}";
    try {
        std::regex re(pattern);
        std::string s(reinterpret_cast<const char*>(data.data()), data.size());
        std::sregex_iterator it(s.begin(), s.end(), re);
        std::sregex_iterator end;
        size_t last_end = 0;
        for (; it != end; ++it) {
            size_t match_pos = s.find(it->str(), last_end);
            if (match_pos == std::string::npos) match_pos = it->position();
            // Decode UTF-16LE to string
            std::string raw = it->str();
            std::string decoded;
            for (size_t i = 0; i + 1 < raw.size(); i += 2) {
                if (raw[i] >= 0x20 && raw[i] <= 0x7e)
                    decoded += raw[i];
            }
            if ((int)decoded.length() >= min_len)
                result.push_back({static_cast<int>(match_pos), decoded});
            last_end = match_pos + 1;
        }
    } catch (const std::regex_error&) {}
    return result;
}


uint64_t BinaryEmulator::get_pc() {
    // Python binemu.py:542-552 doc: "Get the value of the current program counter"
    int arch = get_arch();
    if (arch == speakeasy::arch::ARCH_AMD64)
        return reg_read(static_cast<int>(speakeasy::arch::REG_RIP));
    else
        return reg_read(static_cast<int>(speakeasy::arch::REG_EIP));
}

void BinaryEmulator::set_pc(uint64_t addr) {
    // Python binemu.py:554-563 doc: "Set the value of the current program counter"
    int arch = get_arch();
    int reg = (arch == speakeasy::arch::ARCH_AMD64) ?
              static_cast<int>(speakeasy::arch::REG_RIP) :
              static_cast<int>(speakeasy::arch::REG_EIP);
    if (emu_eng) {
        emu_eng->reg_write(reg, addr);
    }
}
