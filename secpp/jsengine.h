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

    class JsHook
    {
    public:

        uint64_t id = 0;
        bool enabled = true;

        std::string api;

        qjs::Value onCallback;
        qjs::Value onExit;

        explicit JsHook(qjs::Context& ctx)
            : onCallback(ctx.newValue(JS_UNDEFINED))
            , onExit(ctx.newValue(JS_UNDEFINED))
        {}

        bool disable()
        {
            enabled = false;

            // call your hook registry
            // hook_registry_->disable(id);

            return true;
        }


        bool enable()
        {
            enabled = true;

            // hook_registry_->enable(id);

            return true;
        }


        bool remove()
        {
            // hook_registry_->remove(id);

            return true;
        }
    };

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
         * @returns The result as a qjs::Value.
         * @throws qjs::exception on JS error, std::runtime_error if not initialized.
         */
        qjs::Value eval_buf(const std::string& code, const std::string& filename,
            int eval_flags = JS_EVAL_TYPE_GLOBAL);

        /**
         * Evaluate JavaScript from a file on the host filesystem.
         * @returns The result as a qjs::Value.
         * @throws qjs::exception on JS error, std::runtime_error if not initialized.
         */
        qjs::Value eval_file(const std::string& filename,
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

        // ========== Internal helpers ==========
        void register_native_class();
        void init_emu_object();
        void register_log_functions();

        qjs::Value create_hook_object(
            std::shared_ptr<JsHook> hook);
        qjs::Value api_hook_install(qjs::Value config);
    };

} // namespace speakeasy

#endif // SPEAKEASY_JSENGINE_H