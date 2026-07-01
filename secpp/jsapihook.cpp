// jsapihook.cpp - Bridge between JS ApiHook.install() and C++ add_api_hook() (quickjspp modernized)
#include "jsapihook.h"
#include "jsengine.h"
#include "speakeasy.h"

#include <algorithm>
#include <sstream>
#include <plog/Log.h>

namespace speakeasy {

    // ============================================================================
    // JsHookEntry
    // ============================================================================

    void JsHookEntry::fire_on_call_back(const std::string& api, const std::vector<uint64_t>& argv) {
        if (!js_ctx || JS_IsUndefined(on_call_back.v) || !JS_IsFunction(js_ctx->ctx, on_call_back.v)) {
            return;
        }

        try {
            // Convert the incoming C++ vector variables natively into an array wrapper
            qjs::Value args_arr{js_ctx->ctx, JS_NewArray(js_ctx->ctx)};
            for (size_t i = 0; i < argv.size(); i++) {
                args_arr[static_cast<uint32_t>(i)] = static_cast<int64_t>(argv[i]);
            }

            // Invoke the JS callback via std::function conversion
            on_call_back.as<std::function<void(std::string, qjs::Value)>>()(api, std::move(args_arr));
        }
        catch (const qjs::exception&) {
            JsPluginEngine::dump_error(*js_ctx);
        }
    }

    void JsHookEntry::fire_on_exit(const std::string& api, const std::vector<uint64_t>& argv, uint64_t retval) {
        if (!js_ctx || JS_IsUndefined(on_exit.v) || !JS_IsFunction(js_ctx->ctx, on_exit.v)) {
            return;
        }

        try {
            // Build the JS array parameters
            qjs::Value args_arr{js_ctx->ctx, JS_NewArray(js_ctx->ctx)};
            for (size_t i = 0; i < argv.size(); i++) {
                args_arr[static_cast<uint32_t>(i)] = static_cast<int64_t>(argv[i]);
            }

            // Call target JS function: callback(api, args_arr, retval)
            on_exit.as<std::function<void(std::string, qjs::Value, int64_t)>>()(api, std::move(args_arr), static_cast<int64_t>(retval));
        }
        catch (const qjs::exception&) {
            JsPluginEngine::dump_error(*js_ctx);
        }
    }

    // ============================================================================
    // JsApiHookRegistry
    // ============================================================================

    JsApiHookRegistry::JsApiHookRegistry(qjs::Context& ctx, Speakeasy& speakeasy)
        : ctx_(ctx), speakeasy_(speakeasy)
    {}

    JsApiHookRegistry::~JsApiHookRegistry() {
        remove_all();
    }

    bool JsApiHookRegistry::install(qjs::Value this_val,
        const std::string& lib, const std::string& name,
        uint32_t ordinal, bool is_ordinal,
        uint64_t address, bool is_address,
        qjs::Value on_call_back, qjs::Value on_exit) {
        // Create a unique key
        std::string key;
        if (is_address) {
            std::ostringstream oss;
            oss << "addr:0x" << std::hex << address;
            key = oss.str();
        }
        else if (is_ordinal) {
            std::ostringstream oss;
            oss << lib << ".#" << ordinal;
            key = oss.str();
        }
        else {
            key = lib + "." + name;
        }

        // Check for duplicate hook records
        if (hooks_.find(key) != hooks_.end()) {
            PLOG_WARNING << "[JsApiHook] duplicate hook: " << key;
            return false;
        }

        // Instantiating wrapper automatically manages assignment/duplication inside internal storage objects
        auto entry = std::make_unique<JsHookEntry>(ctx_);
        entry->on_call_back = on_call_back;
        entry->on_exit = on_exit;
        entry->module = lib;
        entry->api_name = name;
        entry->ordinal = ordinal;
        entry->is_ordinal = is_ordinal;
        entry->is_address = is_address;
        entry->address = address;
        entry->key = key;

        // Track a persistent reference for lambda capturing lifetimes safely
        JsHookEntry* entry_ptr = entry.get();
        hooks_[key] = std::move(entry);

        if (is_address) {
            PLOG_WARNING << "[JsApiHook] address-based hooks not yet implemented: " << key
                << " (use install by name: Emu.install('lib', 'Func'))";
            return true;
        }

        // The bridge lambda execution structure remains clean. entry_ptr outlives callbacks.
        auto bridge = [entry_ptr](void* emu, const std::string& api_called,
            void* orig, std::vector<uint64_t> argv) -> uint64_t {
                // Fire JS OnCallBack BEFORE executing the handler
                entry_ptr->fire_on_call_back(api_called, argv);

                // Call original back-end system handlers safely
                ApiCallback* orig_cb = reinterpret_cast<ApiCallback*>(orig);
                uint64_t retval = 0;
                if (orig_cb) {
                    retval = (*orig_cb)(emu, api_called, nullptr, argv);
                }

                // Fire JS OnExit AFTER executing the handler
                entry_ptr->fire_on_exit(api_called, argv, retval);
                return retval;
            };

        std::string api_name_for_hook = entry_ptr->api_name;
        if (is_ordinal && api_name_for_hook.empty()) {
            PLOG_INFO << "[JsApiHook] ordinal-based hook for " << lib << " #" << ordinal;
        }

        // Register into system facade definitions
        speakeasy_.add_api_hook(bridge, entry_ptr->module, api_name_for_hook, 0, "stdcall");

        PLOG_INFO << "[JsApiHook] installed hook: " << key;
        return true;
    }

    void JsApiHookRegistry::remove_all() {
        // Explicit value cleanup drops completely because destructors for qjs::Value handle ref-count decreases via RAII
        hooks_.clear();
    }

} // namespace speakeasy