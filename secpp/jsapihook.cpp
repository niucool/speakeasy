// jsapihook.cpp - Bridge between JS ApiHook.install() and C++ add_api_hook()
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

JsHookEntry::~JsHookEntry() {
    // JS values must be freed BEFORE the entry is destroyed.
    // The registry calls FreeValue explicitly in remove_all().
}

void JsHookEntry::fire_on_call_back(const std::string& api,
                                     const std::vector<uint64_t>& argv) {
    if (!js_ctx || JS_IsUndefined(on_call_back) || !JS_IsFunction(js_ctx, on_call_back)) {
        return;
    }

    // Build a JS array of arguments
    JSValue args = JS_NewArray(js_ctx);
    for (size_t i = 0; i < argv.size(); i++) {
        JS_SetPropertyUint32(js_ctx, args, static_cast<uint32_t>(i),
                             JS_NewInt64(js_ctx, static_cast<int64_t>(argv[i])));
    }

    // Build the call args: [api_name_string, args_array]
    JSValue call_args[2];
    call_args[0] = JS_NewString(js_ctx, api.c_str());
    call_args[1] = args;

    JSValue ret = JS_Call(js_ctx, on_call_back, JS_UNDEFINED, 2, call_args);

    if (JS_IsException(ret)) {
        JsPluginEngine::dump_error(js_ctx);
    }

    JS_FreeValue(js_ctx, ret);
    JS_FreeValue(js_ctx, call_args[0]);
    JS_FreeValue(js_ctx, args);
}

void JsHookEntry::fire_on_exit(const std::string& api,
                                const std::vector<uint64_t>& argv, uint64_t retval) {
    if (!js_ctx || JS_IsUndefined(on_exit) || !JS_IsFunction(js_ctx, on_exit)) {
        return;
    }

    // Build a JS array of arguments
    JSValue args = JS_NewArray(js_ctx);
    for (size_t i = 0; i < argv.size(); i++) {
        JS_SetPropertyUint32(js_ctx, args, static_cast<uint32_t>(i),
                             JS_NewInt64(js_ctx, static_cast<int64_t>(argv[i])));
    }

    // Build call args: [api_name, args_array, return_value]
    JSValue call_args[3];
    call_args[0] = JS_NewString(js_ctx, api.c_str());
    call_args[1] = args;
    call_args[2] = JS_NewInt64(js_ctx, static_cast<int64_t>(retval));

    JSValue ret = JS_Call(js_ctx, on_exit, JS_UNDEFINED, 3, call_args);

    if (JS_IsException(ret)) {
        JsPluginEngine::dump_error(js_ctx);
    }

    JS_FreeValue(js_ctx, ret);
    JS_FreeValue(js_ctx, call_args[0]);
    JS_FreeValue(js_ctx, args);
}

// ============================================================================
// JsApiHookRegistry
// ============================================================================

JsApiHookRegistry::JsApiHookRegistry(JSContext* ctx, Speakeasy& speakeasy)
    : ctx_(ctx), speakeasy_(speakeasy)
{
}

JsApiHookRegistry::~JsApiHookRegistry() {
    remove_all();
}

bool JsApiHookRegistry::install(JSValueConst this_val,
                                 const std::string& lib, const std::string& name,
                                 uint32_t ordinal, bool is_ordinal,
                                 uint64_t address, bool is_address,
                                 JSValueConst on_call_back, JSValueConst on_exit) {
    // Create a unique key
    std::string key;
    if (is_address) {
        std::ostringstream oss;
        oss << "addr:0x" << std::hex << address;
        key = oss.str();
    } else if (is_ordinal) {
        std::ostringstream oss;
        oss << lib << ".#" << ordinal;
        key = oss.str();
    } else {
        key = lib + "." + name;
    }

    // Check for duplicate
    if (hooks_.find(key) != hooks_.end()) {
        PLOG_WARNING << "[JsApiHook] duplicate hook: " << key;
        return false;
    }

    // Create entry with Dup'd JS values
    auto entry = std::make_unique<JsHookEntry>();
    entry->js_ctx = ctx_;
    entry->on_call_back = JS_DupValue(ctx_, on_call_back);
    entry->on_exit = JS_DupValue(ctx_, on_exit);
    entry->module = lib;
    entry->api_name = name;
    entry->ordinal = ordinal;
    entry->is_ordinal = is_ordinal;
    entry->is_address = is_address;
    entry->address = address;
    entry->key = key;

    // Store raw pointer for the lambda capture
    JsHookEntry* entry_ptr = entry.get();
    hooks_[key] = std::move(entry);

    if (is_address) {
        // Address-based hooks: use a code hook (fires on every instruction at that address)
        // For now, log a warning — proper implementation needs add_code_hook
        PLOG_WARNING << "[JsApiHook] address-based hooks not yet implemented: " << key
                     << " (use install by name: Emu.install('lib', 'Func'))";
        return true;
    }

    // Build the bridge lambda. entry_ptr is captured by value (raw pointer).
    // The registry (this) outlives the hook, so the pointer stays valid.
    auto bridge = [entry_ptr](void* emu, const std::string& api_called,
                               void* orig, std::vector<uint64_t> argv) -> uint64_t {
        // Fire JS OnCallBack BEFORE the handler
        entry_ptr->fire_on_call_back(api_called, argv);

#if 1
        // Call the original handler (must call this or the API won't execute!)
        ApiCallback* orig_cb = reinterpret_cast<ApiCallback*>(orig);
        uint64_t retval = 0;
        if (orig_cb) {
            retval = (*orig_cb)(emu, api_called, nullptr, argv);
        }

        // Fire JS OnExit AFTER the handler
        entry_ptr->fire_on_exit(api_called, argv, retval);
#endif
        return retval;
    };

    // Determine API name for the hook registration
    std::string api_name_for_hook = entry_ptr->api_name;
    if (is_ordinal && api_name_for_hook.empty()) {
        // For ordinal hooks, we need to look up the name. If we can't find it,
        // we'll match all APIs in the module (empty string = wildcard behavior
        // depends on the fnmatch logic).
        PLOG_INFO << "[JsApiHook] ordinal-based hook for " << lib << " #" << ordinal;
    }

    // Register with Speakeasy's hook system
    speakeasy_.add_api_hook(bridge, entry_ptr->module, api_name_for_hook, 0, "stdcall");

    PLOG_INFO << "[JsApiHook] installed hook: " << key;
    return true;
}

void JsApiHookRegistry::remove_all() {
    for (auto& [key, entry] : hooks_) {
        if (entry) {
            if (entry->js_ctx) {
                JS_FreeValue(entry->js_ctx, entry->on_call_back);
                JS_FreeValue(entry->js_ctx, entry->on_exit);
            }
        }
    }
    hooks_.clear();
}

} // namespace speakeasy
