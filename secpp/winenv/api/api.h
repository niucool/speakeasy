// api.h
#ifndef API_H
#define API_H

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <functional>
#include <tuple>
#include <variant>
#include <cstdint>
#include "../../struct.h"
#include "../../profiler.h"
#include "../../winenv/arch.h"

// Forward declarations
class WindowsEmulator;
class BinaryEmulator;
class RegKey;

// ---------------------------------------------------------------------------
// ApiArg  variant type for API handler arguments.
//
// Input:  all args are uint64_t (raw stack values).
// Output: handlers may replace raw values with resolved strings/blobs/pointers
//         for log_api display.  Implicit conversion to uint64_t keeps existing
//         handler body code compiling without changes.
// ---------------------------------------------------------------------------
struct ApiArg {
    std::variant<uint64_t, void*, std::string, std::vector<uint8_t>> data;

    ApiArg() : data(uint64_t(0)) {}
    // NOLINTBEGIN  implicit conversions are intentional
    ApiArg(uint64_t v)                : data(v) {}
    ApiArg(void* v)                   : data(v) {}
    ApiArg(const std::string& s)      : data(s) {}
    ApiArg(std::string&& s)           : data(std::move(s)) {}
    ApiArg(const std::vector<uint8_t>& b) : data(b) {}
    ApiArg(std::vector<uint8_t>&& b)  : data(std::move(b)) {}

    // Implicit read: keep existing a[0] / static_cast<uint32_t>(a[2]) working.
    operator uint64_t() const { return std::get<uint64_t>(data); }

    ApiArg& operator=(uint64_t v)              { data = v; return *this; }
    ApiArg& operator=(void* v)                 { data = v; return *this; }
    ApiArg& operator=(const std::string& s)    { data = s; return *this; }
    ApiArg& operator=(std::string&& s)         { data = std::move(s); return *this; }
    ApiArg& operator=(const std::vector<uint8_t>& b) { data = b; return *this; }
    ApiArg& operator=(std::vector<uint8_t>&& b)      { data = std::move(b); return *this; }

    bool is_uint64() const { return std::holds_alternative<uint64_t>(data); }
    bool is_ptr()    const { return std::holds_alternative<void*>(data); }
    bool is_string() const { return std::holds_alternative<std::string>(data); }
    bool is_blob()   const { return std::holds_alternative<std::vector<uint8_t>>(data); }

    const std::string&             as_string() const { return std::get<std::string>(data); }
    const std::vector<uint8_t>&    as_blob()   const { return std::get<std::vector<uint8_t>>(data); }
    void*                          as_ptr()    const { return std::get<void*>(data); }
    // NOLINTEND
};

using ArgList = std::vector<ApiArg>;

// Helper: read raw uint64_t from an ArgList (same as std::get<uint64_t>(a[i])).
// Kept for cases where the implicit conversion is ambiguous.
inline uint64_t arg_val(const ArgList& a, size_t i) { return std::get<uint64_t>(a[i].data); }

using ApiFunc = std::function<uint64_t(void* emu, ArgList& argv, void* ctx)>;

using DataFunc = std::function<uint64_t(uint64_t ptr)>;

// Structure to hold function hook information
struct ApiHookInfo {
    std::string name;
    ApiFunc func = nullptr;
    int argc = 0;
    int conv = 0;
    int ordinal = 0;
};

// Structure to hold data hook information
struct DataHookInfo {
    std::string name;
    DataFunc func = nullptr;
};

struct ApiEntry {
    std::string name;
    int argc = 0;
    int conv = 0;
    ApiFunc handler;
};

static ApiHookInfo InvalidApiInfo;
static DataHookInfo InvalidDataInfo;


// Base class for handling exported functions
class ApiHandler {
protected:
    std::map<std::string, ApiHookInfo> funcs_;
    std::map<std::string, DataHookInfo> data_;
    std::string mod_name_;
    void* emu_; // Kept as void* to avoid circular dependency with WindowsEmulator/BinaryEmulator includes
    int ptr_size_;

public:
    const std::map<std::string, ApiHookInfo>& get_hook_funcs() const { return funcs_; }
    const std::map<std::string, DataHookInfo>& get_hook_data() const { return data_; }

    void set_emu(void* e);
    void add_hook(const std::string& name, ApiFunc func, int argc, int conv, int ordinal = 0);
    void add_data(const std::string& name, DataFunc func);

    // Static member for class name
    static std::string class_name;

    // Destructor
    virtual ~ApiHandler() = default;

    // Constructor
    ApiHandler(void* emu);

    // Pure virtual methods to be implemented by subclass handlers
    virtual std::string get_name() const = 0;
    virtual const std::vector<ApiEntry>& get_apis() const = 0;

    const ApiEntry* find_api(const std::string& name) const {
        for (auto& e : get_apis())
            if (e.name == name) return &e;
        return nullptr;
    }
    
    // Static methods for decorators
    static std::function<std::function<void()>(std::function<void()>)> 
    apihook(const std::string& impname = "", int argc = 0, int conv = 0, int ordinal = 0);
    
    static std::function<std::function<void()>(std::function<void()>)> 
    impdata(const std::string& impname);
    
    static std::string get_api_name(std::function<void()> func);

    // Helper methods
    void __get_hook_attrs__(ApiHandler* obj);
    DataHookInfo& get_data_handler(const std::string& exp_name);
    ApiHookInfo& get_func_handler(const std::string& exp_name);
    int get_pointer_size();
    
    // Memory management methods
    size_t sizeof_obj(speakeasy::EmuStruct* obj);
    std::vector<uint8_t> get_bytes(speakeasy::EmuStruct* obj);
    speakeasy::EmuStruct* cast(speakeasy::EmuStruct* obj, const std::vector<uint8_t>& bytez);
    void write_back(uint64_t addr, speakeasy::EmuStruct* obj);
    
    // Memory allocation methods
    uint64_t pool_alloc(int pool_type, size_t size, const std::string& tag);
    uint64_t heap_alloc(size_t size, const std::string& heap);
    uint64_t mem_alloc(size_t size, uint64_t base = 0, const std::string& tag = "", 
                       int flags = 0, int perms = 0, bool shared = false, void* process = nullptr);
    bool mem_free(uint64_t addr);
    uint64_t mem_reserve(size_t size, uint64_t base = 0, const std::string& tag = "");
    
    // Memory casting and copying methods
    speakeasy::EmuStruct* mem_cast(speakeasy::EmuStruct* obj, uint64_t addr);
    size_t mem_copy(uint64_t dst, uint64_t src, size_t n);
    
    // String handling methods
    std::string read_mem_string(uint64_t addr, int width, int max_chars = 0);
    int mem_string_len(uint64_t addr, int width);
    std::string read_ansi_string(uint64_t addr);
    std::string read_unicode_string(uint64_t addr);
    std::string read_wide_string(uint64_t addr, int max_chars = 0);
    std::string read_string(uint64_t addr, int max_chars = 0);
    void write_mem_string(const std::string& string, uint64_t addr, int width);
    void write_wide_string(const std::string& string, uint64_t addr);
    void write_string(const std::string& string, uint64_t addr);
    
    // Run management methods
    void queue_run(const std::string& run_type, uint64_t ep, const std::vector<std::string>& run_args = {});
    
    // Logging methods
    void log_file_access(const std::string& path, const std::string& event_type, 
                         const std::vector<uint8_t>* data = nullptr,
                         int handle = 0, const std::vector<std::string>& disposition = {},
                         const std::vector<std::string>& access = {}, uint64_t buffer = 0,
                         int size = -1);
                         
    void log_process_event(void* proc, const std::string& event_type, 
                           const std::map<std::string, std::string>& kwargs);
                           
    void log_registry_access(const std::string& path, const std::string& event_type, 
                             const std::string& value_name = "", 
                             const std::vector<uint8_t>* data = nullptr,
                             int handle = 0, const std::vector<std::string>& disposition = {},
                             const std::vector<std::string>& access = {}, uint64_t buffer = 0,
                             int size = -1);
                             
    void log_dns(const std::string& domain, const std::string& ip = "");
    
    void log_network(const std::string& server, int port, const std::string& typ = "unknown", 
                     const std::string& proto = "unknown", const std::vector<uint8_t>& data = {},
                     const std::string& method = "");
                     
    void log_http(const std::string& server, int port, const std::string& headers = "", 
                  const std::vector<uint8_t>& body = {}, bool secure = false);
    
    // Utility methods
    uint64_t get_max_int();
    std::vector<uint8_t> mem_read(uint64_t addr, size_t size);
    
    // File management methods
    void* file_open(const std::string& path, bool create = false);
    uint32_t file_create_mapping(void* hfile, const std::string& name, size_t size, int prot);
    void* file_get(int handle);
    bool does_file_exist(const std::string& path);
    
    // Registry management methods
    uint32_t reg_open_key(const std::string& path, bool create = false);
    std::shared_ptr<RegKey> reg_get_key(int handle);
    std::vector<std::string> reg_get_subkeys(std::shared_ptr<RegKey> hkey);
    
    // Encoding methods
    std::string get_encoding(int char_width);
    
    // Memory write method
    size_t mem_write(uint64_t addr, const std::vector<uint8_t>& data);
    
    // Thread management methods
    void* create_thread(uint64_t addr, void* ctx, void* hproc, 
                        const std::string& thread_type = "thread", bool is_suspended = false);
    
    // Object management methods
    std::shared_ptr<KernelObject> get_object_from_id(int id);
    std::shared_ptr<KernelObject> get_object_from_addr(uint64_t addr);
    int get_object_handle(std::shared_ptr<KernelObject> obj);
    std::shared_ptr<KernelObject> get_object_from_handle(int hnd);
    std::shared_ptr<KernelObject> get_object_from_name(const std::string& name);
    
    // OS methods
    std::map<std::string, std::string> get_os_version();
    void exit_process();
    
    // Character and format methods
    int get_char_width(const std::map<std::string, std::string>& ctx);
    int get_va_arg_count(const std::string& fmt);
    std::vector<uint64_t> va_args(uint64_t va_list, int num_args);
    void setup_callback(uint64_t func, const std::vector<uint64_t>& args, 
                        const std::vector<uint64_t>& caller_argv = {});
    std::string do_str_format(const std::string& string, const std::vector<uint64_t>& argv);
};

//  Registration macros 
//
// Usage in handler class:
//   class Foo : public ApiHandler {
//       API_LIST_BEGIN
//       API_ENTRY(CreateFileA, 7)
//       API_ENTRY(ReadFile, 5)
//       API_ENTRY(CloseHandle, 1)
//       API_LIST_END
//   public:
//       Foo(void* emu);
//   };

#define API_LIST_BEGIN \
private: \
    std::vector<ApiEntry> apis_; \
    static uint64_t _stub(void* e, ArgList& a, void* c) { (void)e; (void)a; (void)c; return 1; }

/// Declare an API handler method + register it in the table.
/// Each API_ENTRY declares `static uint64_t name(...)` and adds it to the list.
#define API_ENTRY(name, argc) \
    static uint64_t name(void* emu, ArgList& argv, void* ctx);

#define API_LIST_END

/// Initialize the API table in the constructor.
/// Usage: INIT_API_TABLE(Kernel32)
#define INIT_API_TABLE(klass) \
    apis_ = {

/// Register one API entry. Usage: REG(klass, CreateFileA, 7)
// REG for stdcall. Note: Windows APIs are typically stdcall, but some may be cdecl.
#define REG(klass, name, argc) \
    {#name, argc, speakeasy::arch::CALL_CONV_STDCALL, klass::name},

// REG2 for cdecl. Usage: REG2(klass, printf, 2)
#define REG2(klass, name, argc) \
    {#name, argc, speakeasy::arch::CALL_CONV_CDECL, klass::name},

/// End the API table initialization.
#define END_API_TABLE \
    };

/// Generate a stub implementation for an API (returns 1, for usermode).
#define STUB(klass, name) \
    uint64_t klass::name(void* e, ArgList& a, void* c) { \
        (void)e; (void)a; (void)c; return 1; \
    }

/// Generate a stub implementation for a kernel-mode API (returns 0 = STATUS_SUCCESS).
#define KERNEL_STUB(klass, name) \
    uint64_t klass::name(void* e, ArgList& a, void* c) { \
        (void)e; (void)a; (void)c; return 0; \
    }

#endif // API_H