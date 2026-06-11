// api.cpp  ApiHandler base class implementation
//
// Maps to: speakeasy/winenv/api/api.py
//
// Provides helper methods for DLL-specific API handlers:
//   - Memory allocation / read / write
//   - String reading / writing (ANSI, Unicode, wide)
//   - File / registry delegation
//   - Object management (process / thread)
//   - Event logging (file, registry, network, DNS, HTTP, process)
//   - Format string parsing (do_str_format / va_args)
//   - Callback setup (for APCs, callbacks, etc.)

#include "api.h"

#include <cstring>
#include <sstream>
#include <algorithm>
#include <cctype>
#include <stdexcept>

#include "../../windows/winemu.h"   // WindowsEmulator
#include "../../windows/win32.h"   // WindowsEmulator
#include "../../profiler.h"         // Run, Profiler
#include "../../struct.h"           // EmuStruct
#include "../../winenv/arch.h"      // ARCH_X86, ARCH_AMD64

using namespace speakeasy;

//  Helper: emu() returns typed pointer 

static inline Win32Emulator* winemu32(void* raw) {
    return static_cast<Win32Emulator*>(raw);
}

static inline WindowsEmulator* winemu(void* raw) {
    return static_cast<WindowsEmulator*>(raw);
}

static inline BinaryEmulator* binemu(void* raw) {
    return static_cast<BinaryEmulator*>(raw);
}

//  Static member 

std::string ApiHandler::class_name = "";

//  Constructor 

ApiHandler::ApiHandler(void* emu) : emu_(emu) {
    // Detect pointer size from architecture
    int arch = binemu(emu)->get_arch();
    if (arch == speakeasy::arch::ARCH_X86) {
        ptr_size_ = 4;
    } else if (arch == speakeasy::arch::ARCH_AMD64) {
        ptr_size_ = 8;
    } else {
        throw std::runtime_error("Invalid architecture: " + std::to_string(arch));
    }

    // Note: Python auto-discovers @apihook / @impdata decorated methods
    // via dir()/getattr() at construction time.  In C++, the v2 macro
    // system (api_handler_base.h) replaces this with static registration.
    // Subclasses should call __get_hook_attrs__ in their constructor if
    // they still use the old registration path.
}

void ApiHandler::set_emu(void* e) {
    emu_ = e;
    int arch = binemu(emu_)->get_arch();
    if (arch == speakeasy::arch::ARCH_X86) {
        ptr_size_ = 4;
    } else if (arch == speakeasy::arch::ARCH_AMD64) {
        ptr_size_ = 8;
    }
}

void ApiHandler::add_hook(const std::string& name, ApiFunc func, int argc, int conv, int ordinal) {
    ApiHookInfo info;
    info.name = name;
    info.func = func;
    info.argc = argc;
    info.conv = conv;
    info.ordinal = ordinal;
    funcs_[name] = info;
}

void ApiHandler::add_data(const std::string& name, DataFunc func) {
    DataHookInfo info;
    info.name = name;
    info.func = func;
    data_[name] = info;
}

// 
// API Registration / Lookup (v1  superseded by v2 macro system)
// 

std::function<std::function<void()>(std::function<void()>)>
ApiHandler::apihook(const std::string& impname, int argc, int conv, int ordinal) {
    // Returns a decorator that tags a function with __apihook__ metadata.
    // In C++ this is replaced by the API_ENTRY / REG macro system in
    // api_handler_base.h.  Kept as a stub for v1 compatibility.
    (void)impname; (void)argc; (void)conv; (void)ordinal;
    return nullptr;
}

std::function<std::function<void()>(std::function<void()>)>
ApiHandler::impdata(const std::string& impname) {
    // Returns a decorator that tags a function with __datahook__ metadata.
    (void)impname;
    return nullptr;
}

std::string ApiHandler::get_api_name(std::function<void()> func) {
    // In Python: return func.__apihook__[0]
    (void)func;
    return "";
}

void ApiHandler::__get_hook_attrs__(ApiHandler* obj) {
    // Python: dir(obj)  getattr  __apihook__ / __datahook__
    // In C++ this is done at compile-time via API_ENTRY / REG macros.
    (void)obj;
}

DataHookInfo& ApiHandler::get_data_handler(const std::string& exp_name) {
    auto it = data_.find(exp_name);
    if (it != data_.end()) return it->second;
    return InvalidDataInfo;
}

ApiHookInfo& ApiHandler::get_func_handler(const std::string& exp_name) {
    // Support ordinal lookup: "ordinal_5"  look up by ordinal number
    if (exp_name.compare(0, 8, "ordinal_") == 0) {
        int ord_num = 0;
        try {
            ord_num = std::stoi(exp_name.substr(8));
        } catch (...) {
            return InvalidApiInfo;
        }
        // Search funcs for matching ordinal
        for (auto& [key, info] : funcs_) {
            (void)key;
            if (info.ordinal == ord_num) {
                return info;
            }
        }
    }

    auto it = funcs_.find(exp_name);
    if (it != funcs_.end()) {
        auto& info = it->second;
        return info;
    }
    return InvalidApiInfo;
}

int ApiHandler::get_pointer_size() {
    return ptr_size_;
}

// 
// EmuStruct Helpers
// 

size_t ApiHandler::sizeof_obj(EmuStruct* obj) {
    if (obj) return obj->sizeof_obj();
    throw std::runtime_error("Invalid EmuStruct object for sizeof_obj");
}

std::vector<uint8_t> ApiHandler::get_bytes(EmuStruct* obj) {
    if (obj) return obj->get_bytes();
    throw std::runtime_error("Invalid EmuStruct object for get_bytes");
}

EmuStruct* ApiHandler::cast(EmuStruct* obj, const std::vector<uint8_t>& bytez) {
    if (obj) {
        obj->from_bytes(bytez);
        return obj;
    }
    throw std::runtime_error("Invalid EmuStruct object for cast");
}

void ApiHandler::write_back(uint64_t addr, EmuStruct* obj) {
    auto bytez = get_bytes(obj);
    winemu(emu_)->mem_write(addr, bytez);
}

// 
// Memory Allocation
// 

uint64_t ApiHandler::pool_alloc(int pool_type, size_t size, const std::string& tag) {
    (void)pool_type;
    return winemu(emu_)->mem_map(size, 0, 4, tag);
}

uint64_t ApiHandler::heap_alloc(size_t size, const std::string& heap) {
    return winemu32(emu_)->heap_alloc(size, heap);
}

uint64_t ApiHandler::mem_alloc(size_t size, uint64_t base, const std::string& tag, 
                               int flags, int perms, bool shared, void* process) {
    std::shared_ptr<Process> proc_ptr = nullptr;
    if (process) {
        proc_ptr = winemu(emu_)->find_process(process);
    }
    return winemu(emu_)->mem_map(size, base, static_cast<uint32_t>(perms), tag,
                                static_cast<uint32_t>(flags), shared,
                                proc_ptr);
}

bool ApiHandler::mem_free(uint64_t addr) {
    try {
        winemu(emu_)->mem_free(addr);
        return true;
    } catch (...) {
        return false;
    }
}

uint64_t ApiHandler::mem_reserve(size_t size, uint64_t base, const std::string& tag) {
    // WindowsEmulator::mem_reserve overrides with a simplified (size, base) signature,
    // so cast to MemoryManager for the full-parameter version.
    return static_cast<MemoryManager*>(winemu(emu_))->mem_reserve(size, base, 0, tag, 0, false);
}

// 
// Memory Casting & Copying
// 

EmuStruct* ApiHandler::mem_cast(EmuStruct* obj, uint64_t addr) {
    auto struct_bytes = winemu(emu_)->mem_read(addr, obj ? obj->sizeof_obj() : 0);
    return cast(obj, struct_bytes);
}

size_t ApiHandler::mem_copy(uint64_t dst, uint64_t src, size_t n) {
    return binemu(emu_)->mem_copy(dst, src, n);
}

// 
// String Reading / Writing
// 

std::string ApiHandler::read_mem_string(uint64_t addr, int width, int max_chars) {
    return binemu(emu_)->read_mem_string(addr, width, max_chars);
}

int ApiHandler::mem_string_len(uint64_t addr, int width) {
    return binemu(emu_)->mem_string_len(addr, width);
}

std::string ApiHandler::read_ansi_string(uint64_t addr) {
    // ntos.STRING layout: { USHORT Length, USHORT MaximumLength, PCHAR Buffer }
    // ptr_size determines alignment/padding in the structure
    // We build the struct manually:
    uint16_t length = 0;
    {
        auto raw = winemu(emu_)->mem_read(addr, 2);
        if (raw.size() >= 2) length = static_cast<uint16_t>(read_le(raw, 0, 2));
    }
    uint64_t buffer_addr = 0;
    {
        auto raw = winemu(emu_)->mem_read(addr + 4, ptr_size_);
        if (!raw.empty()) buffer_addr = read_le(raw, 0, ptr_size_);
    }
    if (buffer_addr == 0) return "";
    return binemu(emu_)->read_mem_string(buffer_addr, 1, length);
}

std::string ApiHandler::read_unicode_string(uint64_t addr) {
    // UNICODE_STRING layout: { USHORT Length, USHORT MaximumLength, PWSTR Buffer }
    uint16_t length = 0;
    {
        auto raw = winemu(emu_)->mem_read(addr, 2);
        if (raw.size() >= 2) length = static_cast<uint16_t>(read_le(raw, 0, 2));
    }
    uint64_t buffer_addr = 0;
    {
        auto raw = winemu(emu_)->mem_read(addr + 4, ptr_size_);
        if (!raw.empty()) buffer_addr = read_le(raw, 0, ptr_size_);
    }
    if (buffer_addr == 0) return "";
    return binemu(emu_)->read_mem_string(buffer_addr, 2, length / 2);
}

std::string ApiHandler::read_wide_string(uint64_t addr, int max_chars) {
    return binemu(emu_)->read_mem_string(addr, 2, max_chars);
}

std::string ApiHandler::read_string(uint64_t addr, int max_chars) {
    return binemu(emu_)->read_mem_string(addr, 1, max_chars);
}

void ApiHandler::write_mem_string(const std::string& string, uint64_t addr, int width) {
    binemu(emu_)->write_mem_string(string, addr, width);
}

void ApiHandler::write_wide_string(const std::string& string, uint64_t addr) {
    write_mem_string(string, addr, 2);
}

void ApiHandler::write_string(const std::string& string, uint64_t addr) {
    write_mem_string(string, addr, 1);
}

// 
// Run Management
// 

void ApiHandler::queue_run(const std::string& run_type, uint64_t ep,
                           const std::vector<std::string>& run_args) {
    auto run = std::make_shared<Run>();
    run->type = run_type;
    run->start_addr = ep;
    run->args = run_args;
    winemu(emu_)->add_run(run);
}

// 
// Event Logging
// 

void ApiHandler::log_file_access(const std::string& path, const std::string& event_type,
                                 const std::vector<uint8_t>* in_data, int handle,
                                 const std::vector<std::string>& disposition,
                                 const std::vector<std::string>& access, uint64_t buffer,
                                 int size) {
    auto prof = binemu(emu_)->get_profiler();
    if (prof) {
        auto run = std::static_pointer_cast<Run>(winemu(emu_)->get_current_run());
        const std::vector<uint8_t>& data_ref = in_data ? *in_data : std::vector<uint8_t>();
        prof->log_file_access(run, path, event_type, data_ref, handle,
                              disposition, access, buffer, size);
    }
}

void ApiHandler::log_process_event(void* proc, const std::string& event_type,
                                   const std::map<std::string, std::string>& kwargs) {
    auto prof = binemu(emu_)->get_profiler();
    if (prof) {
        auto run = std::static_pointer_cast<Run>(winemu(emu_)->get_current_run());
        prof->log_process_event(run, proc, event_type, kwargs);
    }
}

void ApiHandler::log_registry_access(const std::string& path, const std::string& event_type,
                                     const std::string& value_name,
                                     const std::vector<uint8_t>* in_data, int handle,
                                     const std::vector<std::string>& disposition,
                                     const std::vector<std::string>& access, uint64_t buffer,
                                     int size) {
    auto prof = binemu(emu_)->get_profiler();
    if (prof) {
        auto run = std::static_pointer_cast<Run>(winemu(emu_)->get_current_run());
        const std::vector<uint8_t>& data_ref = in_data ? *in_data : std::vector<uint8_t>();
        prof->log_registry_access(run, path, event_type, value_name, data_ref, handle,
                                  disposition, access, buffer, size);
    }
}

void ApiHandler::log_dns(const std::string& domain, const std::string& ip) {
    auto prof = binemu(emu_)->get_profiler();
    if (prof) {
        auto run = std::static_pointer_cast<Run>(winemu(emu_)->get_current_run());
        prof->log_dns(run, domain, ip);
    }
}

void ApiHandler::log_network(const std::string& server, int port, const std::string& typ,
                             const std::string& proto, const std::vector<uint8_t>& in_data,
                             const std::string& method) {
    auto prof = binemu(emu_)->get_profiler();
    if (prof) {
        auto run = std::static_pointer_cast<Run>(winemu(emu_)->get_current_run());
        prof->log_network(run, server, port, typ, proto, in_data, method);
    }
}

void ApiHandler::log_http(const std::string& server, int port, const std::string& headers,
                          const std::vector<uint8_t>& body, bool secure) {
    auto prof = binemu(emu_)->get_profiler();
    if (prof) {
        auto run = std::static_pointer_cast<Run>(winemu(emu_)->get_current_run());
        prof->log_http(run, server, port, "http", headers, body, secure);
    }
}

// 
// Utility Methods
// 

uint64_t ApiHandler::get_max_int() {
    // e.g. for 4-byte ptr: 0xFFFFFFFF, for 8-byte: 0xFFFFFFFFFFFFFFFF
    if (ptr_size_ == 8)
        return UINT64_MAX;
    return 0xFFFFFFFFULL;
}

std::vector<uint8_t> ApiHandler::mem_read(uint64_t addr, size_t size) {
    return winemu(emu_)->mem_read(addr, size);
}

// 
// File Management (delegates to WindowsEmulator)
// 

void* ApiHandler::file_open(const std::string& path, bool create) {
    return winemu(emu_)->file_open(path, create);
}

uint32_t ApiHandler::file_create_mapping(void* hfile, const std::string& in_name, size_t size, int prot) {
    return winemu(emu_)->file_create_mapping(hfile, in_name, size, prot);
}

void* ApiHandler::file_get(int handle) {
    return winemu(emu_)->file_get(handle);
}

bool ApiHandler::does_file_exist(const std::string& path) {
    return winemu(emu_)->does_file_exist(path);
}

// 
// Registry Management (delegates to WindowsEmulator)
// 

uint32_t ApiHandler::reg_open_key(const std::string& path, bool create) {
    return winemu(emu_)->reg_open_key(path, create);
}

std::shared_ptr<RegKey> ApiHandler::reg_get_key(int handle) {
    return winemu(emu_)->reg_get_key(handle);
}

std::vector<std::string> ApiHandler::reg_get_subkeys(std::shared_ptr<RegKey> hkey) {
    return winemu(emu_)->reg_get_subkeys(hkey);
}

// 
// Encoding / Character Width
// 

std::string ApiHandler::get_encoding(int char_width) {
    if (char_width == 2) return "utf-16le";
    if (char_width == 1) return "utf-8";
    throw std::runtime_error("No encoding found for char width: " + std::to_string(char_width));
}

// 
// Memory Write
// 

size_t ApiHandler::mem_write(uint64_t addr, const std::vector<uint8_t>& data) {
    winemu(emu_)->mem_write(addr, data);
    return data.size();
}

// 
// Thread Management
// 

void* ApiHandler::create_thread(uint64_t addr, void* ctx, void* hproc,
                                const std::string& thread_type, bool is_suspended) {
    auto proc = winemu(emu_)->find_process(hproc);
    if (!proc) {
        proc = winemu(emu_)->get_current_process();
    }
    auto thread = winemu(emu_)->create_thread(addr, ctx, proc, thread_type, is_suspended);
    return thread.get();
}

std::shared_ptr<KernelObject> ApiHandler::get_object_from_id(int id) {
    return winemu(emu_)->get_object_from_id(id);
}

std::shared_ptr<KernelObject> ApiHandler::get_object_from_addr(uint64_t addr) {
    return winemu(emu_)->get_object_from_addr(addr);
}

int ApiHandler::get_object_handle(std::shared_ptr<KernelObject> obj) {
    return winemu(emu_)->get_object_handle(obj);
}

std::shared_ptr<KernelObject> ApiHandler::get_object_from_handle(int hnd) {
    return winemu(emu_)->get_object_from_handle(hnd);
}

std::shared_ptr<KernelObject> ApiHandler::get_object_from_name(const std::string& in_name) {
    return winemu(emu_)->get_object_from_name(in_name);
}

// 
// OS Information
// 

std::map<std::string, std::string> ApiHandler::get_os_version() {
    return binemu(emu_)->get_os_version();
}

void ApiHandler::exit_process() {
    winemu32(emu_)->exit_process();
}

// 
// Character / Format Methods
// 

int ApiHandler::get_char_width(const std::map<std::string, std::string>& ctx) {
    auto it = ctx.find("func_name");
    if (it == ctx.end()) {
        throw std::runtime_error("Failed to get character width: no func_name in context");
    }
    const std::string& func_name_str = it->second;
    if (func_name_str.size() >= 1 && func_name_str.back() == 'A') return 1;
    if (func_name_str.size() >= 1 && func_name_str.back() == 'W') return 2;
    throw std::runtime_error("Failed to get character width from function: " + func_name_str);
}

int ApiHandler::get_va_arg_count(const std::string& fmt) {
    // Count format specifiers (%d, %s, %x, etc.), ignoring escaped %%
    int count = 0;
    // TODO: escape flag not yet used  Python port incomplete, needs format string state tracking
    bool escape = false; (void)escape;
    for (size_t i = 0; i < fmt.size(); ++i) {
        if (fmt[i] == '%') {
            if (i + 1 < fmt.size() && fmt[i + 1] == '%') {
                // %%  escaped percent, skip both
                ++i;
                continue;
            }
            ++count;
        }
    }
    return count;
}

std::vector<uint64_t> ApiHandler::va_args(uint64_t va_list, int num_args) {
    std::vector<uint64_t> args;
    uint64_t ptr = va_list;
    for (int n = 0; n < num_args; ++n) {
        auto raw = winemu(emu_)->mem_read(ptr, ptr_size_);
        uint64_t arg = 0;
        if (!raw.empty()) arg = read_le(raw, 0, ptr_size_);
        args.push_back(arg);
        ptr += ptr_size_;
    }
    return args;
}

void ApiHandler::setup_callback(uint64_t func, const std::vector<uint64_t>& args,
                                const std::vector<uint64_t>& caller_argv) {
    // For APIs that call functions, set up the stack so the callback
    // flows naturally.
    auto emu_obj = winemu(emu_);
    auto run = std::static_pointer_cast<Run>(emu_obj->get_current_run());

    if (run->api_callbacks.empty()) {
        // First callback in this chain: save return address, redirect to func
        uint64_t ret = binemu(emu_)->get_ret_address();
        uint64_t sp = binemu(emu_)->get_stack_ptr();

        // Set up the call frame
        binemu(emu_)->set_func_args(sp, 0xEBDA /* API_CALLBACK_HANDLER_ADDR */, args);
        binemu(emu_)->set_pc(func);
        run->api_callbacks.push_back({ret, [ret, func, caller_argv](){ (void)ret; (void)func; (void)caller_argv; }, caller_argv});
    } else {
        // Nested callback: just push onto the stack
        run->api_callbacks.push_back({0, [func, args](){ (void)func; (void)args; }, args});
    }
}

std::string ApiHandler::do_str_format(const std::string& string, const std::vector<uint64_t>& argv) {
    // Format a string similar to msvcrt.printf
    // This is a best-effort implementation; the Python original is very brittle too.

    std::string result;
    std::vector<uint64_t> args = argv;
    size_t i = 0;

    while (i < string.size()) {
        if (string[i] == '%' && i + 1 < string.size()) {
            if (string[i + 1] == '%') {
                result += '%';
                i += 2;
                continue;
            }

            size_t start = i;
            ++i; // skip '%'

            // Collect flags / width / precision
            std::string fmt_mods;
            while (i < string.size() && (string[i] == 'l' || string[i] == 'h' ||
                                          string[i] == 'w' || string[i] == 'z' ||
                                          string[i] == 't' || string[i] == 'j')) {
                fmt_mods += string[i];
                ++i;
            }

            // Skip digits (width)
            while (i < string.size() && std::isdigit(static_cast<unsigned char>(string[i]))) {
                fmt_mods += string[i];
                ++i;
            }

            if (i >= string.size()) break;

            char conv = string[i];
            bool has_ll = (fmt_mods.find("ll") != std::string::npos);

            if (args.empty()) break;

            switch (conv) {
            case 's': {
                // String pointer
                uint64_t addr = args[0];
                args.erase(args.begin());
                std::string str_val;
                if (fmt_mods.find('w') != std::string::npos || fmt_mods.find('S') != std::string::npos) {
                    str_val = binemu(emu_)->read_mem_string(addr, 2);
                } else {
                    str_val = binemu(emu_)->read_mem_string(addr, 1);
                }
                result += str_val;
                break;
            }
            case 'S': {
                // Wide string (%S)
                uint64_t addr = args[0];
                args.erase(args.begin());
                result += binemu(emu_)->read_mem_string(addr, 2);
                break;
            }
            case 'd':
            case 'i':
            case 'u':
            case 'x':
            case 'X': {
                uint64_t val;
                if (has_ll && ptr_size_ == 4) {
                    // 64-bit value passed as two 32-bit args
                    uint64_t low = args[0];
                    uint64_t high = args.size() > 1 ? args[1] : 0;
                    val = (high << 32) | low;
                    args.erase(args.begin());
                    if (args.size() > 0) args.erase(args.begin());
                } else {
                    val = args[0];
                    args.erase(args.begin());
                }
                if (conv == 'x' || conv == 'X') {
                    char buf[32];
                    if (conv == 'X')
                        snprintf(buf, sizeof(buf), "%llX", (unsigned long long)val);
                    else
                        snprintf(buf, sizeof(buf), "%llx", (unsigned long long)val);
                    result += buf;
                } else {
                    char buf[32];
                    snprintf(buf, sizeof(buf), "%lld", (long long)val);
                    result += buf;
                }
                break;
            }
            case 'c': {
                uint64_t val = args[0] & 0xFF;
                args.erase(args.begin());
                result += static_cast<char>(val);
                break;
            }
            case 'p':
            case 'P': {
                uint64_t val = args[0];
                args.erase(args.begin());
                char buf[32];
                snprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)val);
                result += buf;
                break;
            }
            default:
                // Unknown format, emit as-is
                result += string.substr(start, i - start + 1);
                break;
            }
            ++i;
        } else {
            result += string[i];
            ++i;
        }
    }

    return result;
}
