// binemu.cpp
#include "binemu.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#ifdef HAS_CAPSTONE
#include <capstone/capstone.h>
#endif

// Constructor
BinaryEmulator::BinaryEmulator(const std::string& config, void* logger) 
    : stack_base(0), page_size(0), inst_count(0), curr_instr_size(0),
      disasm_eng(nullptr), builtin_hooks_set(false), emu_eng(nullptr),
      logger(logger), runtime(0) {
    
    // Initialize member variables
    max_instructions = -1;
    timeout = 0;
    max_api_count = 5000;
    keep_memory_on_free = false;
    
    // Call parent constructor
    // MemoryManager();
    
    profiler = std::make_shared<Profiler>();
    emu_version = get_emu_version();
    
    _parse_config(config);
}

void BinaryEmulator::log_info(const std::string& msg) {
    if (logger) {
        // TODO: Implement logger info method
        // logger->info(msg);
    }
}

void BinaryEmulator::log_error(const std::string& msg) {
    if (logger) {
        // TODO: Implement logger error method
        // logger->error(msg);
    }
}

void BinaryEmulator::log_exception(const std::string& msg) {
    if (logger) {
        // TODO: Implement logger exception method
        // logger->exception(msg);
    }
}

std::shared_ptr<Profiler> BinaryEmulator::get_profiler() {
    // Get the current event profiler object (if any)
    return profiler;
}

std::map<std::string, std::string> BinaryEmulator::get_report() {
    // Get the emulation report for all runs that were executed
    if (profiler) {
        return profiler->get_report();
    }
    // Return empty map if no profiler
    return std::map<std::string, std::string>();
}

std::string BinaryEmulator::get_json_report_string() {
    // Get the emulation report for all runs that were executed formatted as a JSON string
    if (profiler) {
        return profiler->get_json_report_string();
    }
    // Return empty string if no profiler
    return "";
}

void BinaryEmulator::_parse_config(const std::string& config) {
    // Parse the config to be used for emulation
    // TODO: Implementation depends on JSON library
    /*
    if (isinstance(config, str)) {
        config = json.loads(config)
    }
    this.config = config
    */
    
    // TODO: Parse engine and other config options
    /*
    _eng = config.get('emu_engine', '')
    for name, eng in EMU_ENGINES:
        if name.lower() == _eng.lower():
            this.emu_eng = eng()
    if not this.emu_eng:
        raise EmuException('Unsupported emulation engine: %s' % (_eng))
    */
    
    // TODO: Parse all other config fields
}

std::string BinaryEmulator::get_emu_version() {
    // Get the version of the emulator
    return __version__; // From version.h
}

std::map<std::string, std::string> BinaryEmulator::get_os_version() {
    // Get version of the OS being emulated
    return osversion;
}

std::string BinaryEmulator::get_osver_string() {
    // Get the human readable OS version string
    auto osver = get_os_version();
    if (!osver.empty()) {
        std::string os_name = osver["name"];
        // TODO: Get major and minor versions
        /*
        major = osver.get('major')
        minor = osver.get('minor')
        if major is not None and minor is not None:
            verstr = '%s.%d_%d' % (os_name, major, minor)
            return verstr
        */
    }
    return "";
}

std::string BinaryEmulator::get_domain() {
    // Get domain of the machine being emulated
    return domain;
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
    // Get the size (in the emulation space) of the supplied object
    // TODO: Implementation depends on object type
    // return obj.sizeof();
    return 0;
}

template<typename T>
std::vector<uint8_t> BinaryEmulator::get_bytes(T obj) {
    // Get the bytes represented in the emulation space of the supplied object
    // TODO: Implementation depends on object type
    // return obj.get_bytes();
    return std::vector<uint8_t>();
}

void BinaryEmulator::stop() {
    // Stop emulation completely
    if (emu_eng) {
        emu_eng->stop();
    }
    if (profiler) {
        profiler->stop_run_clock();
    }
}

void BinaryEmulator::start(uint64_t addr, size_t size) {
    // Begin emulation
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
            // TODO: Log exception
            // profiler->log_error(traceback.format_exc())
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
    // Look up register by name and write value
    static std::map<std::string, int> reg_map = {
        {"eax", 0}, {"ebx", 1}, {"ecx", 2}, {"edx", 3},
        {"esi", 4}, {"edi", 5}, {"ebp", 6}, {"esp", 7}, {"eip", 8},
        {"rax", 0}, {"rbx", 1}, {"rcx", 2}, {"rdx", 3},
        {"rsi", 4}, {"rdi", 5}, {"rbp", 6}, {"rsp", 7}, {"rip", 8},
    };
    auto it = reg_map.find(reg);
    if (it != reg_map.end()) reg_write(it->second, val);
}

void BinaryEmulator::reg_write(int reg, uint64_t val) {
    // Write a value to an emulated cpu register
    if (emu_eng) {
        emu_eng->reg_write(reg, val);
    }
}

uint64_t BinaryEmulator::reg_read(const std::string& reg) {
    static std::map<std::string, int> reg_map = {
        {"eax", 0}, {"ebx", 1}, {"ecx", 2}, {"edx", 3},
        {"esi", 4}, {"edi", 5}, {"ebp", 6}, {"esp", 7}, {"eip", 8},
        {"rax", 0}, {"rbx", 1}, {"rcx", 2}, {"rdx", 3},
        {"rsi", 4}, {"rdi", 5}, {"rbp", 6}, {"rsp", 7}, {"rip", 8},
    };
    auto it = reg_map.find(reg);
    if (it != reg_map.end()) return reg_read(it->second);
    return 0;
}

uint64_t BinaryEmulator::reg_read(int reg) {
    // Read a value from an emulated cpu register
    if (emu_eng) {
        uint64_t val = 0;
        emu_eng->reg_read(reg, &val);
        return val;
    }
    return 0;
}

void BinaryEmulator::set_hooks() {
    // Register all hooks with the emulation engine
    for (auto& [hook_type, hook_list] : hooks) {
        for (auto* h : hook_list) {
            // TODO: if (!hook->is_added()) hook->add();
            (void)h;
        }
    }
}

std::tuple<std::string, std::string, std::string> BinaryEmulator::_cs_disasm(const std::vector<uint8_t>& mem, 
                                                                             uint64_t addr, bool fast) {
    // Disassemble bytes using capstone (real implementation below)
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
    // Disassemble bytes at a specified address
    return _cs_disasm(mem, addr, fast);
}

std::map<std::string, std::string> BinaryEmulator::get_register_state() {
    std::map<std::string, std::string> regs;
    static const char* names_x86[] = {"esp","ebp","eip","esi","edi","eax","ebx","ecx","edx"};
    static const char* names_x64[] = {"rsp","rbp","rip","rsi","rdi","rax","rbx","rcx","rdx","r8","r9","r10","r11","r12","r13","r14","r15"};
    auto names = (get_arch() == 64) ? std::vector<const char*>(names_x64, names_x64 + 17)
                                     : std::vector<const char*>(names_x86, names_x86 + 9);
    for (size_t i = 0; i < names.size(); ++i) {
        uint64_t val = reg_read(static_cast<int>(i));
        char buf[32];
        snprintf(buf, sizeof(buf), "0x%llx", static_cast<unsigned long long>(val));
        regs[names[i]] = buf;
    }
    return regs;
}

std::tuple<std::string, std::string, std::string> BinaryEmulator::get_disasm(uint64_t addr, size_t size, bool fast) {
    // Get the disassembly from an address
    // TODO: Implementation depends on memory read
    // return disasm(this.mem_read(addr, size), addr, fast);
    return std::make_tuple("", "", "");
}

// ── Stack operations ─────────────────────────────────────────

uint64_t BinaryEmulator::push_stack(uint64_t val) {
    int ps = get_ptr_size();
    uint64_t sp = get_stack_ptr();
    sp -= ps;
    mem_write(sp, std::vector<uint8_t>(reinterpret_cast<uint8_t*>(&val),
                                        reinterpret_cast<uint8_t*>(&val) + ps));
    set_stack_ptr(sp);
    return sp;
}

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
    return reg_read(get_arch() == 64 ? 7 : 7);  // ESP/RSP = reg 7
}

void BinaryEmulator::set_stack_ptr(uint64_t addr) {
    reg_write(get_arch() == 64 ? 7 : 7, addr);
}

uint64_t BinaryEmulator::get_ret_address() {
    int ps = get_ptr_size();
    uint64_t sp = get_stack_ptr();
    auto data = mem_read(sp, ps);
    uint64_t val = 0;
    for (size_t i = 0; i < data.size(); ++i)
        val |= static_cast<uint64_t>(data[i]) << (i * 8);
    return val;
}

void BinaryEmulator::set_ret_address(uint64_t addr) {
    int ps = get_ptr_size();
    uint64_t sp = get_stack_ptr();
    std::vector<uint8_t> bytes(ps);
    for (size_t i = 0; i < bytes.size(); ++i)
        bytes[i] = static_cast<uint8_t>((addr >> (i * 8)) & 0xFF);
    mem_write(sp, bytes);
}

// ── Stack trace ─────────────────────────────────────────────

std::vector<std::string> BinaryEmulator::get_stack_trace(int num_ptrs) {
    std::vector<std::string> trace;
    uint64_t sp = get_stack_ptr();
    int ps = get_ptr_size() > 0 ? get_ptr_size() : 4;
    for (int i = 0; i < num_ptrs; ++i) {
        auto data = mem_read(sp + i * ps, ps);
        uint64_t val = 0;
        for (size_t j = 0; j < data.size(); ++j)
            val |= static_cast<uint64_t>(data[j]) << (j * 8);
        char buf[32];
        snprintf(buf, sizeof(buf), "0x%llx: 0x%llx",
                 static_cast<unsigned long long>(sp + i * ps),
                 static_cast<unsigned long long>(val));
        trace.push_back(buf);
    }
    return trace;
}

// ── Stack formatting ────────────────────────────────────────

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
        result.push_back({addr, val, ""});
    }
    return result;
}

void BinaryEmulator::print_stack(int num_ptrs) {
    auto trace = get_stack_trace(num_ptrs);
    for (auto& line : trace) fprintf(stderr, "%s\n", line.c_str());
}

// ── Hook management (deferred: Hook classes need Speakeasy*, not BinaryEmulator*) ─

void* BinaryEmulator::get_module_from_addr(uint64_t addr) {
    (void)addr;
    return nullptr;  // TODO: iterate modules
}

std::vector<ApiHook> BinaryEmulator::get_api_hooks(const std::string&, const std::string&) {
    return {};  // TODO: filter hooks by module/function
}

// Hook registration methods (deferred until Hook classes are refactored
// to accept BinaryEmulator* instead of Speakeasy*)

ApiHook BinaryEmulator::add_api_hook(std::function<void()> cb, const std::string& module,
                                      const std::string& api_name, int argc,
                                      void* call_conv, BinaryEmulator* emu) {
    (void)cb; (void)module; (void)api_name; (void)argc; (void)call_conv; (void)emu;
    return ApiHook(nullptr, nullptr, nullptr, "", "", 0, nullptr);
}

CodeHook BinaryEmulator::add_code_hook(std::function<void()> cb, uint64_t begin, uint64_t end,
                                        std::map<std::string, std::string> ctx, BinaryEmulator* emu) {
    (void)cb; (void)begin; (void)end; (void)ctx; (void)emu;
    return CodeHook(nullptr, nullptr, nullptr, 0, 0);
}

DynCodeHook BinaryEmulator::add_dyn_code_hook(std::function<void()> cb,
                                               std::vector<std::string> ctx, BinaryEmulator* emu) {
    (void)cb; (void)ctx; (void)emu;
    return DynCodeHook(nullptr, nullptr, nullptr);
}

ReadMemHook BinaryEmulator::add_mem_read_hook(std::function<void()> cb, uint64_t begin, uint64_t end,
                                               BinaryEmulator* emu) {
    (void)cb; (void)begin; (void)end; (void)emu;
    return ReadMemHook(nullptr, nullptr, nullptr, 0, 0);
}

WriteMemHook BinaryEmulator::add_mem_write_hook(std::function<void()> cb, uint64_t begin, uint64_t end,
                                                  BinaryEmulator* emu) {
    (void)cb; (void)begin; (void)end; (void)emu;
    return WriteMemHook(nullptr, nullptr, nullptr, 0, 0);
}

MapMemHook BinaryEmulator::add_mem_map_hook(std::function<void()> cb, uint64_t begin, uint64_t end,
                                             BinaryEmulator* emu) {
    (void)cb; (void)begin; (void)end; (void)emu;
    return MapMemHook(nullptr, nullptr, nullptr, 0, 0);
}

InvalidMemHook BinaryEmulator::add_mem_invalid_hook(std::function<void()> cb, BinaryEmulator* emu) {
    (void)cb; (void)emu;
    return InvalidMemHook(nullptr, nullptr, nullptr);
}

InterruptHook BinaryEmulator::add_interrupt_hook(std::function<void()> cb,
                                                  std::vector<std::string> ctx, BinaryEmulator* emu) {
    (void)cb; (void)ctx; (void)emu;
    return InterruptHook(nullptr, nullptr, nullptr);
}

// ── Stack arguments ─────────────────────────────────────────

void BinaryEmulator::set_func_args(uint64_t stack_addr, uint64_t ret_addr,
                                    const std::vector<uint64_t>& args, bool home_space) {
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

std::vector<uint64_t> BinaryEmulator::get_func_argv(int callconv, int argc) {
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
    (void)argc; (void)conv;
    if (ret_value != 0) {
        reg_write(get_arch() == 64 ? 0 : 0, ret_value);  // rax/eax
    }
    if (ret_addr != 0) {
        set_pc(ret_addr);
    }
}

// ── Architecture ────────────────────────────────────────────

int BinaryEmulator::get_arch() {
    return 32;  // default x86; set by subclass via set_ptr_size
}

std::string BinaryEmulator::get_arch_name() {
    return get_arch() == 64 ? "amd64" : "x86";
}

void BinaryEmulator::set_ptr_size(int arch) {
    if (arch == 64) {
        // ptr_size will be set by subclass
    }
}

int BinaryEmulator::get_ptr_size() {
    return 4;  // default 32-bit; overridden in subclass
}

// ── String utilities ────────────────────────────────────────

std::string BinaryEmulator::read_mem_string(uint64_t address, int width, int max_chars) {
    std::string result;
    for (int i = 0; max_chars == 0 || i < max_chars; ++i) {
        auto data = mem_read(address + i * width, width);
        if (data.empty()) break;
        uint16_t ch = 0;
        for (size_t j = 0; j < data.size(); ++j)
            ch |= static_cast<uint16_t>(data[j]) << (j * 8);
        if (ch == 0) break;
        result += static_cast<char>(ch & 0xFF);
    }
    return result;
}

int BinaryEmulator::mem_string_len(uint64_t address, int width) {
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
    return {{}, {}};  // TODO
}

size_t BinaryEmulator::mem_copy(uint64_t dst, uint64_t src, size_t n) {
    auto data = mem_read(src, n);
    mem_write(dst, data);
    return n;
}

void BinaryEmulator::write_mem_string(const std::string& str, uint64_t address, int width) {
    for (size_t i = 0; i < str.length(); ++i) {
        uint16_t ch = static_cast<uint16_t>(str[i]);
        std::vector<uint8_t> bytes(width, 0);
        for (int j = 0; j < width; ++j)
            bytes[j] = static_cast<uint8_t>((ch >> (j * 8)) & 0xFF);
        mem_write(address + i * width, bytes);
    }
}

uint64_t BinaryEmulator::read_ptr(uint64_t address) {
    int ps = get_ptr_size();
    auto data = mem_read(address, ps);
    uint64_t val = 0;
    for (size_t i = 0; i < data.size(); ++i)
        val |= static_cast<uint64_t>(data[i]) << (i * 8);
    return val;
}

void BinaryEmulator::write_ptr(uint64_t address, uint64_t val) {
    int ps = get_ptr_size();
    std::vector<uint8_t> bytes(ps);
    for (int i = 0; i < ps; ++i)
        bytes[i] = static_cast<uint8_t>((val >> (i * 8)) & 0xFF);
    mem_write(address, bytes);
}

// ── Stack management ────────────────────────────────────────

std::tuple<uint64_t, uint64_t> BinaryEmulator::reset_stack(uint64_t base) {
    uint64_t old_sp = get_stack_ptr();
    set_stack_ptr(base);
    return {base, old_sp};
}

std::tuple<uint64_t, uint64_t> BinaryEmulator::alloc_stack(size_t size) {
    uint64_t sp = get_stack_ptr();
    sp -= size;
    set_stack_ptr(sp);
    return {sp, sp + size};
}

void BinaryEmulator::clean_stack_args(int argc) {
    int ps = get_ptr_size();
    uint64_t sp = get_stack_ptr();
    sp += ps;  // skip ret addr
    sp += argc * ps;
    set_stack_ptr(sp);
}

std::vector<std::tuple<int, std::string>> BinaryEmulator::get_ansi_strings(
    const std::vector<uint8_t>& data, int min_len) {
    std::vector<std::tuple<int, std::string>> result;
    std::string current;
    int start = -1;
    for (size_t i = 0; i < data.size(); ++i) {
        if (data[i] >= 0x20 && data[i] <= 0x7e) {
            if (start == -1) start = static_cast<int>(i);
            current += static_cast<char>(data[i]);
        } else {
            if ((int)current.length() >= min_len) {
                result.push_back({start, current});
            }
            current.clear();
            start = -1;
        }
    }
    if ((int)current.length() >= min_len) result.push_back({start, current});
    return result;
}

std::vector<std::tuple<int, std::string>> BinaryEmulator::get_unicode_strings(
    const std::vector<uint8_t>& data, int min_len) {
    std::vector<std::tuple<int, std::string>> result;
    std::string current;
    int start = -1;
    for (size_t i = 0; i + 1 < data.size(); i += 2) {
        uint16_t ch = data[i] | (static_cast<uint16_t>(data[i+1]) << 8);
        if (ch >= 0x20 && ch <= 0x7e) {
            if (start == -1) start = static_cast<int>(i);
            current += static_cast<char>(ch);
        } else {
            if ((int)current.length() >= min_len) result.push_back({start, current});
            current.clear();
            start = -1;
        }
    }
    if ((int)current.length() >= min_len) result.push_back({start, current});
    return result;
}


void BinaryEmulator::set_pc(uint64_t addr) {
    if (emu_eng) {
        emu_eng->reg_write(get_arch() == 64 ? 8 : 8, addr);  // EIP/RIP
    }
}
