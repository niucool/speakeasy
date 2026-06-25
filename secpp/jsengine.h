// jsengine.h - JavaScript plugin engine for Speakeasy
#ifndef SPEAKEASY_JSENGINE_H
#define SPEAKEASY_JSENGINE_H

#include <string>
#include <vector>
#include <memory>
#include <cstdint>
#include <quickjspp.hpp>

// Forward declarations
class Speakeasy;

namespace speakeasy {

// Forward declarations
class JsApiHookRegistry;

/**
 * JavaScript plugin engine that wraps QuickJS (via quickjspp) for emulator scripting.
 * Owns the qjs::Runtime and qjs::Context, registers the ApiHook class and
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
     * @param code     JavaScript source code (null-terminated)
     * @param filename Source filename for error messages
     * @param flags    JS_EVAL_TYPE_* flags
     * @return true on success, false on exception
     */
    bool eval_buf(const std::string& code, const std::string& filename,
                  int flags = JS_EVAL_TYPE_GLOBAL);

    /**
     * Evaluate JavaScript from a file on the host filesystem.
     */
    bool eval_file(const std::string& filename,
                   int flags = JS_EVAL_TYPE_GLOBAL);

    /**
     * Load a main JS plugin script (matches Pascal LoadScript).
     */
    bool load_script(const std::string& filename);

    // Accessors
    JSRuntime* runtime() const { return rt_ ? rt_->rt : nullptr; }
    JSContext* context() const { return ctx_ ? ctx_->ctx : nullptr; }
    qjs::Runtime* rt() { return rt_.get(); }
    qjs::Context* ctx() { return ctx_.get(); }
    Speakeasy& speakeasy() { return speakeasy_; }
    JsApiHookRegistry& hook_registry() { return *hook_registry_; }

    /**
     * Dump a JS exception to stderr (replacement for js_std_dump_error).
     * Public so the hook bridge can call it from any context.
     */
    static void dump_error(JSContext* ctx);

private:
    Speakeasy& speakeasy_;
    std::unique_ptr<qjs::Runtime> rt_;
    std::unique_ptr<qjs::Context> ctx_;
    std::unique_ptr<JsApiHookRegistry> hook_registry_;  // destroyed before ctx_

    // These are RAII qjs::Value — auto-freed when destroyed
    qjs::Value emu_obj_ = qjs::Value{JS_UNDEFINED};
    qjs::Value api_class_proto_ = qjs::Value{JS_UNDEFINED};
    JSClassID api_class_id_ = 0;

    // ========== Internal helpers ==========

    void register_native_class();
    void init_emu_object();
    void register_log_functions();

    /**
     * Module loader callback registered via JS_SetModuleLoaderFunc.
     * Handles ES6 imports: import * as std from 'std'; import {x} from './file.js';
     */
    static char* module_normalize_cb(JSContext* ctx, const char* module_base_name,
                                     const char* module_name, void* opaque);
    static JSModuleDef* module_loader_cb(JSContext* ctx, const char* module_name,
                                         void* opaque);

    /**
     * Helper: read a file's contents into a string.
     */
    static std::string load_file_content(const std::string& filename);
};

} // namespace speakeasy

#endif // SPEAKEASY_JSENGINE_H
