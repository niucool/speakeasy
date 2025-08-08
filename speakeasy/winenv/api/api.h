// api.h
#ifndef API_H
#define API_H

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <functional>
#include <tuple>
#include <cstdint>

// TODO: Need C++ equivalents for these Python imports
// #include "arch.h"
// #include "profiler.h"
// #include "struct.h"
// #include "errors.h"
// #include "windows/common.h"
// #include "winenv/defs/nt/ntoskrnl.h"

// Forward declarations
class EmuStruct;
class Run;
class ApiEmuError;

// Structure to hold function hook information
struct ApiHookInfo {
    std::string name;
    std::function<void()> func;
    int argc;
    int conv;
    int ordinal;
};

// Structure to hold data hook information
struct DataHookInfo {
    std::string name;
    std::function<void()> func;
};

// Base class for handling exported functions
class ApiHandler {
protected:
    std::map<std::string, ApiHookInfo> funcs;
    std::map<std::string, DataHookInfo> data;
    std::string mod_name;
    void* emu; // TODO: Should be BinaryEmulator* or appropriate emulator type
    int ptr_size;

public:
    // Static member for class name
    static std::string name;

    // Constructor
    ApiHandler(void* emu);
    
    // Static methods for decorators
    static std::function<std::function<void()>(std::function<void()>)> 
    apihook(const std::string& impname = "", int argc = 0, int conv = 0, int ordinal = 0);
    
    static std::function<std::function<void()>(std::function<void()>)> 
    impdata(const std::string& impname);
    
    static std::string get_api_name(std::function<void()> func);

    // Helper methods
    void __get_hook_attrs__(ApiHandler* obj);
    std::function<void()> get_data_handler(const std::string& exp_name);
    std::tuple<std::string, std::function<void()>, int, int, int> get_func_handler(const std::string& exp_name);
    int get_ptr_size();
    
    // Memory management methods
    size_t sizeof_obj(EmuStruct* obj);
    std::vector<uint8_t> get_bytes(EmuStruct* obj);
    EmuStruct* cast(EmuStruct* obj, const std::vector<uint8_t>& bytez);
    void write_back(uint64_t addr, EmuStruct* obj);
    
    // Memory allocation methods
    uint64_t pool_alloc(int pool_type, size_t size, const std::string& tag);
    uint64_t heap_alloc(size_t size, uint64_t heap);
    uint64_t mem_alloc(size_t size, uint64_t base = 0, const std::string& tag = "", 
                       int flags = 0, int perms = 0, bool shared = false, void* process = nullptr);
    bool mem_free(uint64_t addr);
    uint64_t mem_reserve(size_t size, uint64_t base = 0, const std::string& tag = "");
    
    // Memory casting and copying methods
    EmuStruct* mem_cast(EmuStruct* obj, uint64_t addr);
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
    void* file_create_mapping(void* hfile, const std::string& name, size_t size, int prot);
    void* file_get(int handle);
    bool does_file_exist(const std::string& path);
    
    // Registry management methods
    void* reg_open_key(const std::string& path, bool create = false);
    void* reg_get_key(int handle);
    std::vector<std::string> reg_get_subkeys(void* hkey);
    
    // Encoding methods
    std::string get_encoding(int char_width);
    
    // Memory write method
    size_t mem_write(uint64_t addr, const std::vector<uint8_t>& data);
    
    // Thread management methods
    void* create_thread(uint64_t addr, void* ctx, void* hproc, 
                        const std::string& thread_type = "thread", bool is_suspended = false);
    
    // Object management methods
    void* get_object_from_id(int id);
    void* get_object_from_addr(uint64_t addr);
    int get_object_handle(void* obj);
    void* get_object_from_handle(int hnd);
    void* get_object_from_name(const std::string& name);
    
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

#endif // API_H