// jsapihook.h - Bridge between JS ApiHook.install() and C++ add_api_hook() (quickjspp modernized)
#ifndef SPEAKEASY_JSAPIHOOK_H
#define SPEAKEASY_JSAPIHOOK_H

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <cstdint>
#include <quickjspp.hpp>

class Speakeasy;
namespace speakeasy { class JsPluginEngine; }

namespace speakeasy {

    /**
     * Stores a single hooked API entry with JS callback references.
     * JS values are held as qjs::Value objects, managing lifecycle automatically.
     */
    struct JsHookEntry {
        qjs::Context* js_ctx = nullptr;   // Modern wrapper context pointer for evaluation
        qjs::Value on_call_back;          // JS function wrapper, called when API is invoked
        qjs::Value on_exit;               // JS function wrapper, called after API returns
        std::string module;
        std::string api_name;
        uint32_t ordinal = 0;
        bool is_ordinal = false;
        bool is_address = false;
        uint64_t address = 0;
        std::string key;  // unique key for lookup

        // Explicit constructor required to safely pass context along for default uninitialized qjs::Value instances
        JsHookEntry(qjs::Context& ctx)
            : js_ctx(&ctx), on_call_back(ctx.newValue(JS_UNDEFINED)), on_exit(ctx.newValue(JS_UNDEFINED)) {}

        /**
         * Call the JS OnCallBack with the API arguments.
         * @param api    Full API name string (e.g. "kernel32.CreateFileA")
         * @param argv   Raw uint64_t arguments
         */
        void fire_on_call_back(const std::string& api, const std::vector<uint64_t>& argv);

        /**
         * Call the JS OnExit with the API arguments and return value.
         */
        void fire_on_exit(const std::string& api, const std::vector<uint64_t>& argv, uint64_t retval);

        ~JsHookEntry() = default;  // Automatically frees managed JS values via RAII
    };

    /**
     * Registry that bridges JavaScript ApiHook.install() calls to
     * the C++ Speakeasy::add_api_hook() system.
     */
    class JsApiHookRegistry {
    public:
        /**
         * @param ctx       qjs::Context wrapper reference (not owned)
         * @param speakeasy Speakeasy facade (not owned)
         */
        JsApiHookRegistry(qjs::Context& ctx, Speakeasy& speakeasy);
        ~JsApiHookRegistry();

        JsApiHookRegistry(const JsApiHookRegistry&) = delete;
        JsApiHookRegistry& operator=(const JsApiHookRegistry&) = delete;

        /**
         * Install a hook. Called from api_hook_install() after argument validation.
         * @returns A unique hook ID on success, or 0 on failure.
         */
        uint64_t install(
            const std::string& lib, const std::string& name,
            uint32_t ordinal, bool is_ordinal,
            uint64_t address, bool is_address,
            qjs::Value on_call_back, qjs::Value on_exit);

        /**
         * Remove all hooks and clear internal storage map.
         */
        void remove_all();

    private:
        qjs::Context& ctx_;    // Reference to the active C++ context wrapper
        Speakeasy& speakeasy_; // Facade reference
        std::map<std::string, std::unique_ptr<JsHookEntry>> hooks_;
        uint64_t next_id_ = 1; // Monotonically increasing hook ID counter
    };

} // namespace speakeasy

#endif // SPEAKEASY_JSAPIHOOK_H