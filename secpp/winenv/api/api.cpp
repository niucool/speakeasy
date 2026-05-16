// api.cpp
#include "api.h"
#include "../../binemu.h"
#include <stdexcept>
#include <algorithm>

// ── Static member definitions ───────────────────────────
static const std::string EMU_API_CTX_API = "api";

// ── Constructor ─────────────────────────────────────────
ApiHandler::ApiHandler(void* emu) : emu(emu), ptr_size(4) {
    if (emu) {
        auto* be = reinterpret_cast<BinaryEmulator*>(emu);
        ptr_size = (be->get_arch() == 64) ? 8 : 4;
    }
}

// ── Decorator stubs (C++ uses macro registration, not runtime decorators) ──

std::function<std::function<void()>(std::function<void()>)> 
ApiHandler::apihook(const std::string& impname, int argc, int conv, int ordinal) {
    (void)impname; (void)argc; (void)conv; (void)ordinal;
    return nullptr;
}

std::function<std::function<void()>(std::function<void()>)> 
ApiHandler::impdata(const std::string& impname) {
    (void)impname;
    return nullptr;
}

std::string ApiHandler::get_api_name(std::function<void()> func) {
    (void)func;
    return "";
}

void ApiHandler::__get_hook_attrs__(ApiHandler* obj) {
    (void)obj;
}

std::function<void()> ApiHandler::get_data_handler(const std::string& exp_name) {
    auto it = data.find(exp_name);
    if (it != data.end()) return it->second.func;
    return nullptr;
}

std::tuple<std::string, std::function<void()>, int, int, int> 
ApiHandler::get_func_handler(const std::string& exp_name) {
    if (exp_name.size() > 8 && exp_name.substr(0, 8) == "ordinal_") {
        try {
            int ord = std::stoi(exp_name.substr(8));
            for (auto& [k, v] : funcs)
                if (v.ordinal == ord)
                    return std::make_tuple(v.name, v.func, v.argc, v.conv, v.ordinal);
        } catch (...) {}
    }
    auto it = funcs.find(exp_name);
    if (it != funcs.end())
        return std::make_tuple(it->second.name, it->second.func, it->second.argc, it->second.conv, it->second.ordinal);
    return std::make_tuple("", nullptr, 0, 0, 0);
}

int ApiHandler::get_ptr_size() { return ptr_size; }

// ── EmuStruct helpers (require struct.h) ─────────────────

size_t ApiHandler::sizeof_obj(EmuStruct* obj) {
    if (!obj) return 0;
    try { return obj->sizeof_obj(); } catch (...) { return 0; }
}

std::vector<uint8_t> ApiHandler::get_bytes(EmuStruct* obj) {
    if (!obj) return {};
    try { return obj->get_bytes(); } catch (...) { return {}; }
}

EmuStruct* ApiHandler::cast(EmuStruct* obj, const std::vector<uint8_t>& bytez) {
    if (!obj) return nullptr;
    (void)bytez;
    return nullptr; // cast() not on C++ EmuStruct
}

void ApiHandler::write_back(uint64_t addr, EmuStruct* obj) {
    if (!obj || !emu) return;
    auto bytes = get_bytes(obj);
    if (!bytes.empty())
        reinterpret_cast<BinaryEmulator*>(emu)->mem_write(addr, bytes);
}

// ── Memory allocation ───────────────────────────────────

uint64_t ApiHandler::pool_alloc(int pool_type, size_t size, const std::string& tag) {
    if (!emu) return 0;
    (void)pool_type; (void)size; (void)tag;
    return 0;
}

uint64_t ApiHandler::heap_alloc(size_t size, uint64_t heap) {
    if (!emu) return 0;
    (void)size; (void)heap;
    return 0;
}

uint64_t ApiHandler::mem_alloc(size_t size, uint64_t base, const std::string& tag,
                               int flags, int perms, bool shared, void* process) {
    if (!emu) return 0;
    (void)flags; (void)shared; (void)process;
    return reinterpret_cast<BinaryEmulator*>(emu)->mem_map(size, base, perms, tag);
}

bool ApiHandler::mem_free(uint64_t addr) {
    if (!emu) return false;
    reinterpret_cast<BinaryEmulator*>(emu)->mem_free(addr);
    return true;
}

uint64_t ApiHandler::mem_reserve(size_t size, uint64_t base, const std::string& tag) {
    if (!emu) return 0;
    return reinterpret_cast<BinaryEmulator*>(emu)->mem_map(size, base, 0, tag);
}

EmuStruct* ApiHandler::mem_cast(EmuStruct* obj, uint64_t addr) {
    if (!obj || !emu) return nullptr;
    auto bytes = reinterpret_cast<BinaryEmulator*>(emu)->mem_read(addr, sizeof_obj(obj));
    return nullptr; // mem_cast deferred (needs EmuStruct::cast)
    (void)bytes;
}

size_t ApiHandler::mem_copy(uint64_t dst, uint64_t src, size_t n) {
    if (!emu) return 0;
    return reinterpret_cast<BinaryEmulator*>(emu)->mem_copy(dst, src, n);
}

// ── String helpers ──────────────────────────────────────

std::string ApiHandler::read_mem_string(uint64_t addr, int width, int max_chars) {
    if (!emu) return "";
    return reinterpret_cast<BinaryEmulator*>(emu)->read_mem_string(addr, width, max_chars);
}

int ApiHandler::mem_string_len(uint64_t addr, int width) {
    std::string s = read_mem_string(addr, width, 0);
    return (int)s.size();
}

std::string ApiHandler::read_ansi_string(uint64_t addr) { return read_mem_string(addr, 1, 0); }
std::string ApiHandler::read_unicode_string(uint64_t addr) { return read_mem_string(addr, 2, 0); }
std::string ApiHandler::read_wide_string(uint64_t addr, int max_chars) { return read_mem_string(addr, 2, max_chars); }
std::string ApiHandler::read_string(uint64_t addr, int max_chars) { return read_mem_string(addr, 1, max_chars); }

void ApiHandler::write_mem_string(const std::string& string, uint64_t addr, int width) {
    if (!emu) return;
    reinterpret_cast<BinaryEmulator*>(emu)->write_mem_string(string, addr, width);
}
void ApiHandler::write_wide_string(const std::string& string, uint64_t addr) { write_mem_string(string, addr, 2); }
void ApiHandler::write_string(const std::string& string, uint64_t addr) { write_mem_string(string, addr, 1); }

// ── Run queue ───────────────────────────────────────────

void ApiHandler::queue_run(const std::string& run_type, uint64_t ep,
                           const std::vector<std::string>& run_args) {
    if (!emu) return;
    (void)run_type; (void)ep; (void)run_args;
}

// ── Event logging ───────────────────────────────────────

void ApiHandler::log_file_access(const std::string& path, const std::string& event_type,
                          const std::vector<uint8_t>* data,
                          int handle, const std::vector<std::string>& disposition,
                          const std::vector<std::string>& access, uint64_t buffer,
                          int size) {
    if (!emu) return; (void)path; (void)event_type; (void)data; (void)handle; (void)disposition; (void)access; (void)buffer; (void)size;
}

void ApiHandler::log_process_event(void* proc, const std::string& event_type,
                           const std::map<std::string, std::string>& kwargs) {
    if (!emu) return; (void)proc; (void)event_type; (void)kwargs;
}

void ApiHandler::log_registry_access(const std::string& path, const std::string& event_type,
                              const std::string& value_name,
                              const std::vector<uint8_t>* data,
                              int handle, const std::vector<std::string>& disposition,
                              const std::vector<std::string>& access, uint64_t buffer,
                              int size) {
    if (!emu) return; (void)path; (void)event_type; (void)value_name; (void)data; (void)handle; (void)disposition; (void)access; (void)buffer; (void)size;
}

void ApiHandler::log_dns(const std::string& domain, const std::string& ip) {
    if (!emu) return; (void)domain; (void)ip;
}

void ApiHandler::log_network(const std::string& server, int port, const std::string& typ,
                      const std::string& proto, const std::vector<uint8_t>& data,
                      const std::string& method) {
    if (!emu) return; (void)server; (void)port; (void)typ; (void)proto; (void)data; (void)method;
}

void ApiHandler::log_http(const std::string& server, int port, const std::string& headers,
                   const std::vector<uint8_t>& body, bool secure) {
    if (!emu) return; (void)server; (void)port; (void)headers; (void)body; (void)secure;
}

// ── Memory read/write ───────────────────────────────────

std::vector<uint8_t> ApiHandler::mem_read(uint64_t addr, size_t size) {
    if (!emu) return {};
    return reinterpret_cast<BinaryEmulator*>(emu)->mem_read(addr, size);
}

size_t ApiHandler::mem_write(uint64_t addr, const std::vector<uint8_t>& data) {
    if (!emu) return 0;
    reinterpret_cast<BinaryEmulator*>(emu)->mem_write(addr, data);
    return data.size();
}

// ── File management ─────────────────────────────────────

void* ApiHandler::file_open(const std::string& path, bool create) {
    if (!emu) return nullptr;
    (void)path; (void)create;
    return nullptr;
}

void* ApiHandler::file_create_mapping(void* hfile, const std::string& name, size_t size, int prot) {
    if (!emu) return nullptr;
    (void)hfile; (void)name; (void)size; (void)prot;
    return nullptr;
}

void* ApiHandler::file_get(int handle) {
    if (!emu) return nullptr;
    (void)handle;
    return nullptr;
}

bool ApiHandler::does_file_exist(const std::string& path) {
    if (!emu) return false;
    (void)path;
    return false;
}

// ── Registry management ─────────────────────────────────

void* ApiHandler::reg_open_key(const std::string& path, bool create) {
    if (!emu) return nullptr;
    (void)path; (void)create;
    return nullptr;
}

void* ApiHandler::reg_get_key(int handle) {
    if (!emu) return nullptr;
    (void)handle;
    return nullptr;
}

std::vector<std::string> ApiHandler::reg_get_subkeys(void* hkey) {
    if (!emu) return {};
    (void)hkey;
    return {};
}

// ── Thread management ───────────────────────────────────

void* ApiHandler::create_thread(uint64_t addr, void* ctx, void* hproc,
                                const std::string& thread_type, bool is_suspended) {
    if (!emu) return nullptr;
    (void)addr; (void)ctx; (void)hproc; (void)thread_type; (void)is_suspended;
    return nullptr;
}

// ── Object management ───────────────────────────────────

void* ApiHandler::get_object_from_id(int id) {
    if (!emu) return nullptr;
    (void)id;
    return nullptr;
}

void* ApiHandler::get_object_from_addr(uint64_t addr) {
    if (!emu) return nullptr;
    (void)addr;
    return nullptr;
}

int ApiHandler::get_object_handle(void* obj) {
    if (!emu) return 0;
    (void)obj;
    return 0;
}

void* ApiHandler::get_object_from_handle(int hnd) {
    if (!emu) return nullptr;
    (void)hnd;
    return nullptr;
}

void* ApiHandler::get_object_from_name(const std::string& name) {
    if (!emu) return nullptr;
    (void)name;
    return nullptr;
}

// ── OS info ─────────────────────────────────────────────

std::map<std::string, std::string> ApiHandler::get_os_version() {
    return {{"major","10"}, {"minor","0"}, {"build","19041"}};
}

void ApiHandler::exit_process() {
    if (emu) reinterpret_cast<BinaryEmulator*>(emu)->stop();
}

// ── Format/encoding helpers ─────────────────────────────

int ApiHandler::get_char_width(const std::map<std::string, std::string>& ctx) {
    auto it = ctx.find("api");
    if (it != ctx.end() && it->second.find('W') != std::string::npos)
        return 2;
    return 1;
}

int ApiHandler::get_va_arg_count(const std::string& fmt) {
    int c = 0;
    for (char ch : fmt) if (ch == '%') c++;
    return c;
}

std::vector<uint64_t> ApiHandler::va_args(uint64_t va_list, int num_args) {
    std::vector<uint64_t> argv;
    if (!emu) return argv;
    auto* be = reinterpret_cast<BinaryEmulator*>(emu);
    for (int i = 0; i < num_args; i++) {
        auto bytes = be->mem_read(va_list + i * ptr_size, ptr_size);
        uint64_t val = 0;
        for (size_t j = 0; j < bytes.size(); j++)
            val |= (uint64_t)bytes[j] << (j * 8);
        argv.push_back(val);
    }
    return argv;
}

void ApiHandler::setup_callback(uint64_t func, const std::vector<uint64_t>& args,
                        const std::vector<uint64_t>& caller_argv) {
    (void)func; (void)args; (void)caller_argv;
}

std::string ApiHandler::do_str_format(const std::string& string, const std::vector<uint64_t>& argv) {
    (void)argv;
    return string;
}

std::string ApiHandler::get_encoding(int char_width) {
    return (char_width == 2) ? "utf-16-le" : "utf-8";
}

uint64_t ApiHandler::get_max_int() {
    return (ptr_size == 8) ? 0xFFFFFFFFFFFFFFFFULL : 0xFFFFFFFF;
}
