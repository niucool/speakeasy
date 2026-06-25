// jsapihook.h - Bridge between JS ApiHook.install() and C++ add_api_hook()
#ifndef SPEAKEASY_JSAPIHOOK_H
#define SPEAKEASY_JSAPIHOOK_H

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <cstdint>
#include <quickjs.h>

class Speakeasy;
namespace speakeasy { class JsPluginEngine; }

namespace speakeasy {

/**
 * Stores a single hooked API entry with JS callback references.
 * JS values are refcounted (DupValue on store, FreeValue on remove).
 */
struct JsHookEntry {
    JSContext* js_ctx = nullptr;          // JSContext for calling JS functions
    JSValue on_call_back = JS_UNDEFINED;  // JS function, called when API is invoked
    JSValue on_exit = JS_UNDEFINED;       // JS function, called after API returns
    std::string module;
    std::string api_name;
    uint32_t ordinal = 0;
    bool is_ordinal = false;
    bool is_address = false;
    uint64_t address = 0;
    std::string key;  // unique key for lookup

    /**
     * Call the JS OnCallBack with the API arguments.
     * @param api    Full API name string (e.g. "kernel32.CreateFileA")
     * @param argv    Raw uint64_t arguments
     */
    void fire_on_call_back(const std::string& api, const std::vector<uint64_t>& argv);

    /**
     * Call the JS OnExit with the API arguments and return value.
     */
    void fire_on_exit(const std::string& api, const std::vector<uint64_t>& argv, uint64_t retval);

    ~JsHookEntry();  // frees JS values
};

/**
 * Registry that bridges JavaScript ApiHook.install() calls to
 * the C++ Speakeasy::add_api_hook() system.
 *
 * Each install() call creates a JsHookEntry with Dup'd JS callbacks,
 * then registers an ApiCallback lambda that converts C++ arguments
 * to JS values and calls the JS callbacks via JS_Call().
 */
class JsApiHookRegistry {
public:
    /**
     * @param ctx       JSContext (not owned)
     * @param speakeasy Speakeasy facade (not owned)
     */
    JsApiHookRegistry(JSContext* ctx, Speakeasy& speakeasy);
    ~JsApiHookRegistry();

    JsApiHookRegistry(const JsApiHookRegistry&) = delete;
    JsApiHookRegistry& operator=(const JsApiHookRegistry&) = delete;

    /**
     * Install a hook. Called from js_install() after argument validation.
     *
     * @param this_val     The ApiHook JS object (used as this for callbacks)
     * @param lib          Module name (e.g. "kernel32")
     * @param name         API function name (e.g. "CreateFileA")
     * @param ordinal      Ordinal number (used when is_ordinal is true)
     * @param is_ordinal   True if installing by ordinal
     * @param address      API address (used when is_address is true)
     * @param is_address   True if installing by address
     * @param on_call_back JS function to call when API is entered
     * @param on_exit      JS function to call after API returns (may be undefined)
     * @return true on success
     */
    bool install(JSValueConst this_val,
                 const std::string& lib, const std::string& name,
                 uint32_t ordinal, bool is_ordinal,
                 uint64_t address, bool is_address,
                 JSValueConst on_call_back, JSValueConst on_exit);

    /**
     * Remove all hooks and free JS values.
     */
    void remove_all();

private:
    JSContext* ctx_;      // NOT owned
    Speakeasy& speakeasy_; // NOT owned
    std::map<std::string, std::unique_ptr<JsHookEntry>> hooks_;

    /**
     * The C++ callback that bridges add_api_hook → JS execution.
     * @param user_data  Pointer to JsHookEntry
     */
    static bool api_hook_bridge(void* emu, const std::string& api,
                                 void* orig, std::vector<uint64_t> argv,
                                 void* user_data);
};

} // namespace speakeasy

#endif // SPEAKEASY_JSAPIHOOK_H
