// jsengine.h - JavaScript plugin engine for Speakeasy (quickjspp modernized)
#ifndef SPEAKEASY_JSENGINE_H
#define SPEAKEASY_JSENGINE_H

#include <string>
#include <memory>
#include <cstdint>
#include <quickjspp.hpp>

// Forward declarations
class Speakeasy;

namespace speakeasy {

    class JsApiHookRegistry;

    /**
     * JavaScript plugin engine that wraps QuickJS for emulator scripting using quickjspp.
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
         */
        bool init();

        /**
         * Evaluate JavaScript from a buffer.
         */
        bool eval_buf(const std::string& code, const std::string& filename,
            int eval_flags = JS_EVAL_TYPE_GLOBAL);

        /**
         * Evaluate JavaScript from a file on the host filesystem.
         */
        bool eval_file(const std::string& filename,
            int eval_flags = JS_EVAL_TYPE_GLOBAL);

        /**
         * Load a main JS plugin script.
         */
        bool load_script(const std::string& filename);

        // Accessors
        JSRuntime* runtime() const;
        JSContext* context() const;
        qjs::Context& qjs_context() { return *context_; }
        Speakeasy& speakeasy() { return speakeasy_; }
        JsApiHookRegistry& hook_registry() { return *hook_registry_; }

        /**
         * Dump a JS exception using quickjspp extraction.
         */
        static void dump_error(qjs::Context& ctx);

    private:
        Speakeasy& speakeasy_;
        std::unique_ptr<qjs::Runtime> runtime_;
        std::unique_ptr<qjs::Context> context_;
        std::unique_ptr<JsApiHookRegistry> hook_registry_;

        // ========== Modern C++ / quickjspp Function Bindings ==========

        void js_logme(const std::string& message, int magic);
        void js_native_import_scripts(qjs::Value this_val, const std::vector<std::string>& files);
        qjs::Value js_install(qjs::Value this_val, const std::vector<qjs::Value>& args);

        // ========== Internal helpers ==========
        void register_native_class();
        void init_emu_object();
        void register_log_functions();
    };

} // namespace speakeasy

#endif // SPEAKEASY_JSENGINE_H