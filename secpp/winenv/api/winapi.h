// winapi.h
#ifndef WINAPI_H
#define WINAPI_H

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <cstdint>

// TODO: Replace Python imports with C++ equivalents
// #include "arch.h"
// #include "errors.h"
// #include "api.h"
// #include "kernelmode.h"
// #include "usermode.h"

// Forward declarations
class ApiHandler;
class Emulator;

/**
 * Windows API handler class
 */
class WindowsApi {
private:
    std::map<std::string, ApiHandler*> mods;
    std::vector<void*> instances;
    std::map<std::string, void*> data;
    Emulator* emu;
    int ptr_size;

public:
    /**
     * Constructor
     */
    WindowsApi(Emulator* emu);
    
    /**
     * Load API handler module
     */
    ApiHandler* load_api_handler(const std::string& mod_name);
    
    /**
     * Get data export handler
     */
    std::tuple<ApiHandler*, void*> get_data_export_handler(const std::string& mod_name, 
                                                           const std::string& exp_name);
    
    /**
     * Get export function handler
     */
    std::tuple<ApiHandler*, void*> get_export_func_handler(const std::string& mod_name, 
                                                           const std::string& exp_name);
    
    /**
     * Call the handler to implement the imported API
     */
    void* call_api_func(ApiHandler* mod, void* func, const std::vector<void*>& argv, void* ctx);
    
    /**
     * Call the handler to initialize and return imported data variables
     */
    void* call_data_func(ApiHandler* mod, void* func, uint64_t ptr);
    
    /**
     * Get pointer size
     */
    int get_ptr_size() const { return ptr_size; }
};

/**
 * Autoload API handlers
 */
std::vector<std::tuple<std::string, ApiHandler*>> autoload_api_handlers();

#endif // WINAPI_H