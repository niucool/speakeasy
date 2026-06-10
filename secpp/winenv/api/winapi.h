// winapi.h
#ifndef WINAPI_H
#define WINAPI_H

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <cstdint>
#include <functional>

#include "api.h"

// Forward declarations
class ApiHandler;
class BinaryEmulator;

/**
 * Windows API handler class
 */
class WindowsApi {
private:
    std::map<std::string, std::shared_ptr<ApiHandler>> mods_;
    std::vector<void*> instances_;
    std::map<std::string, void*> data_;
    BinaryEmulator* emu_;
    int ptr_size;

    // Cache for handler functions returned by get_data_export_handler/get_export_func_handler
    std::map<std::string, ApiFunc> func_cache_;

public:
    /**
     * Constructor
     */
    WindowsApi(BinaryEmulator* emu);
    
    /**
     * Load API handler module
     */
    std::shared_ptr<ApiHandler> load_api_handler(const std::string& mod_name);
    
    /**
     * Get data export handler
     */
    std::tuple<std::shared_ptr<ApiHandler>, DataHookInfo&> get_data_export_handler(const std::string& mod_name,
                                                           const std::string& exp_name);
    
    /**
     * Get export function handler
     */
    std::tuple<std::shared_ptr<ApiHandler>, ApiHookInfo&> get_export_func_handler(const std::string& mod_name,
                                                           const std::string& exp_name);
    
    /**
     * Call the handler to implement the imported API
     */
    void* call_api_func(std::shared_ptr<ApiHandler> mod, ApiFunc func, ArgList& argv, void* ctx);
    
    /**
     * Call the handler to initialize and return imported data variables
     */
    void* call_data_func(std::shared_ptr<ApiHandler> mod, DataFunc func, uint64_t ptr);
    
    /**
     * Get pointer size
     */
    int get_ptr_size() const { return ptr_size; }
};

namespace speakeasy {
namespace api {
void register_all_api_handlers();
}
}

/**
 * Autoload API handlers
 */
std::vector<std::tuple<std::string, ApiHandler*>> autoload_api_handlers();

#endif // WINAPI_H