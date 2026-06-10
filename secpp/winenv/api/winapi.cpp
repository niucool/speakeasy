// winapi.cpp
#include "winapi.h"
#include "../../helper.h"
#include "api.h"
#include "api_handler_registry.h"
#include "../../winenv/arch.h"
#include "../../errors.h"
#include "../../windows/winemu.h"  // BinaryEmulator::get_arch
#include <algorithm>
#include <cctype>
#include <tuple>

// Constructor
WindowsApi::WindowsApi(BinaryEmulator* emu) : emu_(emu) {
    // Register all API handlers
    speakeasy::api::register_all_api_handlers();

    // Detect pointer size from architecture
    auto* bemu = reinterpret_cast<BinaryEmulator*>(emu);
    if (bemu) {
        int arch = bemu->get_arch();
        if (arch == speakeasy::arch::ARCH_X86)
            ptr_size = 4;
        else if (arch == speakeasy::arch::ARCH_AMD64)
            ptr_size = 8;
        else
            throw ApiEmuError("Invalid architecture");
    } else {
        ptr_size = 4;  // fallback
    }
}

std::shared_ptr<ApiHandler> WindowsApi::load_api_handler(const std::string& mod_name) {
    // Use the ApiHandlerRegistry to find and create API handlers
    std::string lower_name = speakeasy::to_lower(mod_name);

    // Check if already loaded
    auto it = mods_.find(lower_name);
    if (it != mods_.end()) {
        return it->second;
    }

    // Try to create handler via registry (looks up exact name match)
    std::shared_ptr<ApiHandler> handler = ApiHandlerRegistry::create_handler(lower_name, emu_);
    if (handler) {
        for (const auto& entry : handler->get_apis()) {
            handler->add_hook(entry.name, entry.handler, entry.argc, entry.conv);
        }
        mods_[lower_name] = handler;
        return handler;
    }

    // Fallback: iterate all registered handlers and match by name
    auto all_handlers = ApiHandlerRegistry::get_all_handlers();
    for (const auto& [name, factory] : all_handlers) {
        std::string reg_name = speakeasy::to_lower(name);
        if (reg_name == lower_name) {
            auto handler = factory(emu_);
            if (handler) {
                for (const auto& entry : handler->get_apis()) {
                    handler->add_hook(entry.name, entry.handler, entry.argc, entry.conv);
                }
                mods_[lower_name] = handler;
            }
            return handler;
        }
    }

    return nullptr;
}

std::tuple<std::shared_ptr<ApiHandler>, DataHookInfo&> WindowsApi::get_data_export_handler(const std::string& mod_name,
                                                                   const std::string& exp_name) {
    // Find the module handler
    std::string key = speakeasy::to_lower(mod_name);

    auto mod_it = mods_.find(key);
    auto mod = (mod_it != mods_.end()) ? mod_it->second : nullptr;

    if (!mod) {
        mod = load_api_handler(mod_name);
    }

    if (!mod) {
        return std::tuple<std::shared_ptr<ApiHandler>, DataHookInfo&>(nullptr, InvalidDataInfo);
    }

    // Delegate to the handler's get_data_handler method
    auto& handler = mod->get_data_handler(exp_name);

    // Cache the function and return a void* pointer to it
    //std::string cache_key = key + ":" + exp_name + ":data";
    //func_cache_[cache_key] = handler.func;

    //return std::make_tuple(mod, handler);
    return std::tuple<std::shared_ptr<ApiHandler>, DataHookInfo&>(mod, handler);
}

std::tuple<std::shared_ptr<ApiHandler>, ApiHookInfo&> WindowsApi::get_export_func_handler(const std::string& mod_name,
                                                                   const std::string& exp_name) {
    // Find the module handler
    std::string key = speakeasy::to_lower(mod_name);

    auto mod_it = mods_.find(key);
    auto mod = (mod_it != mods_.end()) ? mod_it->second : nullptr;

    if (!mod) {
        mod = load_api_handler(mod_name);
    }

    if (!mod) {
        return std::tuple<std::shared_ptr<ApiHandler>, ApiHookInfo&>(nullptr, InvalidApiInfo);
    }

    // Delegate to the handler's get_func_handler method
    auto& info = mod->get_func_handler(exp_name);

    if (!info.func) {
        return std::tuple<std::shared_ptr<ApiHandler>, ApiHookInfo&>(mod, InvalidApiInfo);
    }

    // Cache the function and return a void* pointer to it
    std::string cache_key = key + ":" + exp_name + ":func";
    func_cache_[cache_key] = info.func;
    return std::tuple<std::shared_ptr<ApiHandler>, ApiHookInfo&>(mod, info);
}

void* WindowsApi::call_api_func(std::shared_ptr<ApiHandler> mod, ApiFunc func, ArgList& argv, void* ctx) {
    if (func == nullptr) {
        return nullptr;
    }

    (void)mod;
    return (void *)func((void *)emu_, argv, ctx);
    //// Check if mod is a valid handler
    //if (mod) {
    //    std::string exp_name;
    //    for (const auto& [k, v] : func_cache_) {
    //        if (v == func) {
    //            // Key format: "mod_name:exp_name:func"
    //            size_t first = k.find(':');
    //            size_t second = k.find(':', first + 1);
    //            if (first != std::string::npos && second != std::string::npos) {
    //                exp_name = k.substr(first + 1, second - first - 1);
    //            }
    //            break;
    //        }
    //    }
    //    if (!exp_name.empty()) {
    //        const auto* entry = mod->find_api(exp_name);
    //        if (entry) {
    //            std::vector<uint64_t> u64_argv;
    //            for (void* arg : argv) {
    //                u64_argv.push_back(reinterpret_cast<uintptr_t>(arg));
    //            }
    //            uint64_t rv = entry->handler(emu, entry->name, entry->argc, u64_argv);
    //            return reinterpret_cast<void*>(static_cast<uintptr_t>(rv));
    //        }
    //    }
    //}

    //// Fallback: Cast void* back to std::function<void()>* and invoke
    //auto* handler_func = reinterpret_cast<std::function<void()>*>(func);
    //if (handler_func && *handler_func) {
    //    (*handler_func)();
    //}

    return nullptr;
}

void* WindowsApi::call_data_func(std::shared_ptr<ApiHandler> mod, DataFunc func, uint64_t ptr) {
    /**
     * Call the handler to initialize and return imported data variables
     *
     * In C++, data handler functions are stored as std::function<void()> which
     * capture all context at registration time.
     */
    (void)mod;
    (void)ptr;

    if (func == nullptr) {
        return nullptr;
    }

    // Cast void* back to std::function<void()>* and invoke
    return (void *)func(ptr);
}

std::vector<std::tuple<std::string, ApiHandler*>> autoload_api_handlers() {
    std::vector<std::tuple<std::string, ApiHandler*>> api_handlers;

    // Use the static ApiHandlerRegistry to enumerate all registered handlers
    auto all_handlers = ApiHandlerRegistry::get_all_handlers();

    for (const auto& [name, factory] : all_handlers) {
        // Create a placeholder tuple with name and null handler
        // (handlers are instantiated on demand by load_api_handler)
        api_handlers.push_back(std::make_tuple(name, static_cast<ApiHandler*>(nullptr)));
    }

    return api_handlers;
}
