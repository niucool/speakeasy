// jsengine.h - JavaScript plugin engine for Speakeasy
#ifndef SPEAKEASY_JSENGINE_H
#define SPEAKEASY_JSENGINE_H

#include <string>
#include <vector>
#include <memory>
#include <cstdint>
#include <quickjs.h>

// Forward declarations
class Speakeasy;

namespace speakeasy {

// Forward declarations
class JsApiHookRegistry;

/**
 * JavaScript plugin engine that wraps QuickJS for emulator scripting.
 * Owns the JSRuntime and JSContext, registers the ApiHook class and
 * Emu global object, and provides eval/script-loading methods.
 *
 * Usage:
 *   JsPluginEngine engine(speakeasy);
 *   engine.init();           // must be called AFTER emulator is running
 *   engine.eval_file("hooks.js");
 */
class JsPluginEngine {
public:
    explicit JsPluginEngine(Speakeasy& speakeasy);
    ~JsPluginEngine();

    // No copy/move
    JsPluginEngine(const JsPluginEngine&) = delete;
    JsPluginEngine& operator=(const JsPluginEngine&) = delete;

    /**
     * Initialize QuickJS runtime, context, Emu global, ApiHook class.
     * Must be called AFTER the emulator is running (PEB/TEB available).
     */
    bool init();

    /**
     * Evaluate JavaScript from a buffer.
     * @param code     JavaScript source code (null-terminated or len-specified)
     * @param filename Source filename for error messages
     * @param eval_flags JS_EVAL_TYPE_* flags
     * @return true on success, false on exception
     */
    bool eval_buf(const std::string& code, const std::string& filename,
                  int eval_flags = JS_EVAL_TYPE_GLOBAL);

    /**
     * Evaluate JavaScript from a file on the host filesystem.
     * @param filename  Path to .js file
     * @param eval_flags JS_EVAL_TYPE_* flags
     * @return true on success, false on exception
     */
    bool eval_file(const std::string& filename,
                   int eval_flags = JS_EVAL_TYPE_GLOBAL);

    /**
     * Load a main JS plugin script (matches Pascal LoadScript).
     * @param filename Path to .js file
     * @return true on success
     */
    bool load_script(const std::string& filename);

    // Accessors
    JSRuntime* runtime() const { return rt_; }
    JSContext* context() const { return ctx_; }
    Speakeasy& speakeasy() { return speakeasy_; }
    JsApiHookRegistry& hook_registry() { return *hook_registry_; }

    /**
     * Dump a JS exception to stderr (replacement for js_std_dump_error).
     * Public so the hook bridge can call it from any context.
     */
    static void dump_error(JSContext* ctx);

private:
    Speakeasy& speakeasy_;
    std::unique_ptr<JsApiHookRegistry> hook_registry_;  // MUST be before rt_ — destroyed before runtime
    JSRuntime* rt_ = nullptr;
    JSContext* ctx_ = nullptr;
    JSValue emu_obj_ = JS_UNDEFINED;
    JSValue api_class_proto_ = JS_UNDEFINED;
    JSClassID api_class_id_ = 0;

    // ========== JS native function callbacks ==========
    // These are called by QuickJS when JS code invokes global functions.

    /**
     * console.log / print / info / warn / error implementation.
     * The 'magic' parameter controls log level: 0=print, 1=log, 2=info, 3=warn, 4=error
     */
    static JSValue js_logme(JSContext* ctx, JSValueConst this_val,
                            int argc, JSValueConst* argv, int magic);

    /**
     * importScripts() - load JS files at runtime (browser-compat).
     */
    static JSValue js_native_import_scripts(JSContext* ctx, JSValueConst this_val,
                                            int argc, JSValueConst* argv);

    /**
     * ApiHook constructor - creates a new ApiHook instance with 'args' array.
     */
    static JSValue js_constructor(JSContext* ctx, JSValueConst new_target,
                                  int argc, JSValueConst* argv);

    /**
     * ApiHook.install() - register an API hook.
     */
    static JSValue js_install(JSContext* ctx, JSValueConst this_val,
                              int argc, JSValueConst* argv);

    // ========== Internal helpers ==========

    void register_native_class(JSContext* ctx);
    void init_emu_object(JSContext* ctx);
    void register_log_functions(JSContext* ctx);

    /**
     * Module loader callback registered via JS_SetModuleLoaderFunc.
     * Handles ES6 imports: import * as std from 'std'; import {x} from './file.js';
     */
    static char* module_normalize_cb(JSContext* ctx, const char* module_base_name,
                                     const char* module_name, void* opaque);
    static JSModuleDef* module_loader_cb(JSContext* ctx, const char* module_name,
                                         void* opaque);

    /**
     * Helper: read a file's contents into a malloc'd string (QuickJS-owned).
     */
    static char* load_file_content(JSContext* ctx, const char* filename, size_t* out_len);
};

} // namespace speakeasy

#endif // SPEAKEASY_JSENGINE_H
