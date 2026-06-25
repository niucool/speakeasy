// jsengine.cpp - JavaScript plugin engine for Speakeasy
#include "jsengine.h"
#include "jsemuobj.h"
#include "jsapihook.h"
#include "speakeasy.h"

#include <fstream>
#include <sstream>
#include <cstring>
#include <algorithm>
#include <plog/Log.h>

namespace speakeasy {

// ============================================================================
// Helper: retrieve the Speakeasy reference from a JSContext via runtime opaque
// ============================================================================
static Speakeasy& get_speakeasy(JSContext* ctx) {
    JSRuntime* rt = JS_GetRuntime(ctx);
    auto* engine = static_cast<JsPluginEngine*>(JS_GetRuntimeOpaque(rt));
    return engine->speakeasy();
}

// ============================================================================
// Helper: retrieve the JsPluginEngine from a JSContext
// ============================================================================
static JsPluginEngine& get_engine(JSContext* ctx) {
    JSRuntime* rt = JS_GetRuntime(ctx);
    return *static_cast<JsPluginEngine*>(JS_GetRuntimeOpaque(rt));
}

// ============================================================================
// Constructor / Destructor
// ============================================================================

JsPluginEngine::JsPluginEngine(Speakeasy& speakeasy)
    : speakeasy_(speakeasy)
{
}

JsPluginEngine::~JsPluginEngine() {
    // Clean up in reverse order of init()
    if (hook_registry_) {
        hook_registry_->remove_all();
    }
    // IMPORTANT: emu_obj_ and api_class_proto_ were passed to
    // JS_SetPropertyStr / JS_SetClassProto which use set_value()
    // internally. set_value() takes ownership WITHOUT calling
    // JS_DupValue, so the property/class now owns the only reference.
    // We must NOT call JS_FreeValue on them — that would double-free
    // when the context is destroyed.
    if (ctx_) {
        //emu_obj_ = JS_UNDEFINED;
        //api_class_proto_ = JS_UNDEFINED;
        JS_FreeContext(ctx_);
        ctx_ = nullptr;
    }
    if (rt_) {
        JS_FreeRuntime(rt_);
        rt_ = nullptr;
    }
}

// ============================================================================
// init() - Initialize QuickJS runtime, context, register globals and classes
// ============================================================================

bool JsPluginEngine::init() {
    // 1. Create JSRuntime
    rt_ = JS_NewRuntime();
    if (!rt_) {
        PLOG_ERROR << "JsPluginEngine: failed to create JSRuntime";
        return false;
    }
    JS_SetRuntimeOpaque(rt_, this);

    // 2. Create JSContext
    ctx_ = JS_NewContext(rt_);
    if (!ctx_) {
        PLOG_ERROR << "JsPluginEngine: failed to create JSContext";
        return false;
    }

    // 3. Set up ES6 module loader for file-based imports
    JS_SetModuleLoaderFunc(rt_, module_normalize_cb, module_loader_cb, this);

    // 4. Register the ApiHook native class
    register_native_class(ctx_);

    // 5. Create the Emu global object (must be after emulator is running)
    init_emu_object(ctx_);

    // 6. Register global logging functions (console.log, print, info, warn, error)
    register_log_functions(ctx_);

    // 7. Register importScripts global — JS_SetPropertyStr takes ownership
    JSValue global = JS_GetGlobalObject(ctx_);
    JS_SetPropertyStr(ctx_, global, "importScripts",
        JS_NewCFunction2(ctx_, js_native_import_scripts, "importScripts", 1,
                         JS_CFUNC_generic, 0));
    JS_FreeValue(ctx_, global);

    // 8. Initialize hook registry
    hook_registry_ = std::make_unique<JsApiHookRegistry>(ctx_, speakeasy_);

    // Note: std/os module bridge is skipped because quickjs-ng vcpkg build
    // does not include quickjs-libc. All necessary globals (console, print,
    // info, warn, error, importScripts) are registered above.

    return true;
}

// ============================================================================
// eval_buf() / eval_file() / load_script()
// ============================================================================

bool JsPluginEngine::eval_buf(const std::string& code, const std::string& filename,
                               int eval_flags) {
    if (!ctx_) {
        PLOG_ERROR << "JsPluginEngine: eval_buf called before init()";
        return false;
    }
    JSValue val = JS_Eval(ctx_, code.c_str(), code.size(), filename.c_str(), eval_flags);
    bool ok = true;
    if (JS_IsException(val)) {
        dump_error(ctx_);
        ok = false;
    }
    JS_FreeValue(ctx_, val);
    return ok;
}

bool JsPluginEngine::eval_file(const std::string& filename, int eval_flags) {
    if (!ctx_) {
        PLOG_ERROR << "JsPluginEngine: eval_file called before init()";
        return false;
    }

    size_t buf_len = 0;
    char* buf = load_file_content(ctx_, filename.c_str(), &buf_len);
    if (!buf) {
        PLOG_ERROR << "JsPluginEngine: failed to load file: " << filename;
        return false;
    }

    bool ok = true;
    JSValue val = JS_Eval(ctx_, buf, buf_len, filename.c_str(), eval_flags);
    if (JS_IsException(val)) {
        dump_error(ctx_);
        ok = false;
    }
    JS_FreeValue(ctx_, val);
    js_free(ctx_, buf);
    return ok;
}

bool JsPluginEngine::load_script(const std::string& filename) {
    // Check if file exists
    std::ifstream f(filename);
    if (!f.good()) {
        PLOG_ERROR << "JsPluginEngine: script not found: " << filename;
        return false;
    }
    f.close();

    PLOG_INFO << "Loading JS main script: " << filename;

    if (!eval_file(filename, JS_EVAL_TYPE_GLOBAL | JS_EVAL_TYPE_MODULE)) {
        PLOG_ERROR << "JsPluginEngine: failed to evaluate script: " << filename;
        return false;
    }
    return true;
}

// ============================================================================
// js_logme() - console.log / print / info / warn / error
// ============================================================================

JSValue JsPluginEngine::js_logme(JSContext* ctx, JSValueConst this_val,
                                  int argc, JSValueConst* argv, int magic) {
    (void)this_val;

    std::ostringstream oss;
    for (int i = 0; i < argc; i++) {
        if (i > 0) oss << ' ';
        const char* str = JS_ToCString(ctx, argv[i]);
        if (!str) {
            return JS_EXCEPTION;
        }
        oss << str;
        JS_FreeCString(ctx, str);
    }

    switch (magic) {
        case 0: // print
        case 1: // console.log
            PLOG_INFO << "[JS] " << oss.str();
            break;
        case 2: // info
            PLOG_INFO << "[JS:info] " << oss.str();
            break;
        case 3: // warn
            PLOG_WARNING << "[JS:warn] " << oss.str();
            break;
        case 4: // error
            PLOG_ERROR << "[JS:error] " << oss.str();
            break;
        default:
            PLOG_INFO << "[JS] " << oss.str();
            break;
    }

    return JS_UNDEFINED;
}

// ============================================================================
// js_native_import_scripts() - importScripts global function
// ============================================================================

JSValue JsPluginEngine::js_native_import_scripts(JSContext* ctx, JSValueConst this_val,
                                                   int argc, JSValueConst* argv) {
    (void)this_val;

    auto& engine = get_engine(ctx);
    for (int i = 0; i < argc; i++) {
        const char* filename = JS_ToCString(ctx, argv[i]);
        if (!filename) {
            return JS_ThrowReferenceError(ctx, "importScripts: argument %d is not a string", i);
        }

        // Check if file exists
        std::ifstream f(filename);
        if (!f.good()) {
            JS_ThrowReferenceError(ctx, "Could not load \"%s\"", filename);
            JS_FreeCString(ctx, filename);
            return JS_EXCEPTION;
        }
        f.close();

        PLOG_INFO << "JS loading module: " << filename;

        if (!engine.eval_file(filename, JS_EVAL_TYPE_GLOBAL)) {
            JS_FreeCString(ctx, filename);
            return JS_EXCEPTION;
        }
        JS_FreeCString(ctx, filename);
    }
    return JS_UNDEFINED;
}

// ============================================================================
// js_constructor() - ApiHook constructor
// ============================================================================

JSValue JsPluginEngine::js_constructor(JSContext* ctx, JSValueConst new_target,
                                         int argc, JSValueConst* argv) {
    (void)argc;
    (void)argv;

    // Get the ApiHook prototype
    auto& engine = get_engine(ctx);

    JSValue obj = JS_NewObjectProtoClass(ctx, engine.api_class_proto_, engine.api_class_id_);
    if (JS_IsException(obj)) {
        return obj;
    }

    // Create the 'args' array for each instance
    JSValue args = JS_NewArray(ctx);
    JS_DefinePropertyValueStr(ctx, obj, "args", args,
                              JS_PROP_CONFIGURABLE | JS_PROP_WRITABLE);
    JS_FreeValue(ctx, args);

    return obj;
}

// ============================================================================
// js_install() - ApiHook.install() method
// ============================================================================

JSValue JsPluginEngine::js_install(JSContext* ctx, JSValueConst this_val,
                                     int argc, JSValueConst* argv) {
    if (argc < 1) {
        JS_ThrowInternalError(ctx,
            "install expects args (libname, ApiName) or (libname, Ordinal) or (Address)");
        return JS_EXCEPTION;
    }

    bool is_address = false;
    bool is_ordinal = false;
    std::string lib, name;
    uint32_t ordinal = 0;
    uint64_t address = 0;

    if (argc == 1) {
        // install(address)
        is_address = true;
        if (JS_IsNumber(argv[0])) {
            int64_t addr = 0;
            if (JS_ToInt64(ctx, &addr, argv[0]) < 0) {
                return JS_EXCEPTION;
            }
            address = static_cast<uint64_t>(addr);
        } else {
            JS_ThrowInternalError(ctx,
                "install as Address expects arg (Address) to be a Number");
            return JS_EXCEPTION;
        }
    } else if (argc >= 2) {
        // install(lib, "name") or install(lib, ordinal)
        int tag = JS_VALUE_GET_NORM_TAG(argv[1]);
        if (tag == JS_TAG_STRING) {
            const char* lib_str = JS_ToCString(ctx, argv[0]);
            const char* name_str = JS_ToCString(ctx, argv[1]);
            if (!lib_str || !name_str) {
                if (lib_str) JS_FreeCString(ctx, lib_str);
                if (name_str) JS_FreeCString(ctx, name_str);
                return JS_EXCEPTION;
            }
            lib = lib_str;
            name = name_str;
            JS_FreeCString(ctx, lib_str);
            JS_FreeCString(ctx, name_str);
        } else if (tag == JS_TAG_INT) {
            is_ordinal = true;
            const char* lib_str = JS_ToCString(ctx, argv[0]);
            if (!lib_str) {
                return JS_EXCEPTION;
            }
            lib = lib_str;
            JS_FreeCString(ctx, lib_str);
            uint32_t ord = 0;
            if (JS_ToUint32(ctx, &ord, argv[1]) < 0) {
                return JS_EXCEPTION;
            }
            ordinal = ord;
        } else {
            JS_ThrowInternalError(ctx,
                "install expects args (libname, ApiName) or (libname, Ordinal)");
            return JS_EXCEPTION;
        }
    }

    // Validate OnCallBack and OnExit
    JSValue on_call_back = JS_GetPropertyStr(ctx, this_val, "OnCallBack");
    JSValue on_exit = JS_GetPropertyStr(ctx, this_val, "OnExit");

    if (JS_IsUndefined(on_call_back)) {
        JS_ThrowInternalError(ctx, "\"OnCallBack\" must be set to install the hook");
        return JS_EXCEPTION;
    }
    if (!JS_IsFunction(ctx, on_call_back)) {
        JS_ThrowInternalError(ctx, "\"OnCallBack\" must be a function");
        return JS_EXCEPTION;
    }

    if (!JS_IsUndefined(on_exit)) {
        if (!JS_IsFunction(ctx, on_exit)) {
            JS_ThrowInternalError(ctx, "\"OnExit\" must be a function");
            return JS_EXCEPTION;
        }
    }

    if (!JS_IsObject(this_val)) {
        return JS_NewBool(ctx, false);
    }

    // Delegate to hook registry
    auto& engine = get_engine(ctx);
    bool success = engine.hook_registry_->install(
        this_val, lib, name, ordinal, is_ordinal, address, is_address,
        on_call_back, on_exit);

    if (!success) {
        return JS_NewBool(ctx, false);
    }

    return JS_NewBool(ctx, true);
}

// ============================================================================
// register_native_class() - Register the ApiHook JS class
// ============================================================================

void JsPluginEngine::register_native_class(JSContext* ctx) {
    JSClassDef api_class_def = {};
    api_class_def.class_name = "ApiHook";
    api_class_def.finalizer = nullptr;
    api_class_def.gc_mark = nullptr;
    api_class_def.call = nullptr;
    api_class_def.exotic = nullptr;

    // Create new class ID
    JS_NewClassID(JS_GetRuntime(ctx), &api_class_id_);
    JS_NewClass(JS_GetRuntime(ctx), api_class_id_, &api_class_def);

    // Create prototype object
    api_class_proto_ = JS_NewObject(ctx);

    // Add install() method to prototype
    // JS_SetPropertyStr takes ownership, do NOT FreeValue the function
    JS_SetPropertyStr(ctx, api_class_proto_, "install",
        JS_NewCFunction2(ctx, js_install, "install", 2, JS_CFUNC_generic, 0));

    // Set the prototype on the class
    JS_SetClassProto(ctx, api_class_id_, api_class_proto_);

    // Create constructor function
    // Add to global object — JS_SetPropertyStr takes ownership of ctor
    JSValue global = JS_GetGlobalObject(ctx);
    JS_SetPropertyStr(ctx, global, "ApiHook",
        JS_NewCFunction2(ctx, js_constructor, "ApiHook", 1, JS_CFUNC_constructor, 0));
    JS_FreeValue(ctx, global);
}

// ============================================================================
// init_emu_object() - Create the Emu global object with all emulator functions
// ============================================================================

void JsPluginEngine::init_emu_object(JSContext* ctx) {
    auto& sp = get_speakeasy(ctx);

    emu_obj_ = JS_NewObject(ctx);

    // === Static properties (read at init time, matching Pascal InitJSEmu) ===

    // Helper: define a property. JS_DefinePropertyValueStr takes ownership
    // of the value, so we must NOT call JS_FreeValue on it.
    auto define_prop = [ctx](JSValue obj, const char* name, JSValue val, int flags) {
        JS_DefinePropertyValueStr(ctx, obj, name, val, flags);
    };

    // isx64
    define_prop(emu_obj_, "isx64",
        JS_NewBool(ctx, sp.get_ptr_size() == 8), JS_PROP_CONFIGURABLE);

    // PEB address
    define_prop(emu_obj_, "PEB",
        JS_NewInt64(ctx, static_cast<int64_t>(sp.get_peb_address())),
        JS_PROP_CONFIGURABLE);

    // TEB address
    define_prop(emu_obj_, "TEB",
        JS_NewInt64(ctx, static_cast<int64_t>(sp.get_teb_address())),
        JS_PROP_CONFIGURABLE);

    // PID
    define_prop(emu_obj_, "PID",
        JS_NewInt64(ctx, static_cast<int64_t>(sp.get_current_pid())),
        JS_PROP_CONFIGURABLE);

    // ImageBase and Filename
    auto modules = sp.get_user_modules();
    int64_t image_base = 0;
    std::string filename;
    if (!modules.empty() && modules[0]) {
        image_base = static_cast<int64_t>(modules[0]->base);
        filename = modules[0]->name;
    }
    define_prop(emu_obj_, "ImageBase", JS_NewInt64(ctx, image_base), JS_PROP_CONFIGURABLE);
    define_prop(emu_obj_, "Filename", JS_NewString(ctx, filename.c_str()), JS_PROP_CONFIGURABLE);

    // === Function list (matching Pascal JSEmuObj functions) ===

    JSCFunctionListEntry emu_funcs[] = {
        // Modules
        JS_CFUNC_DEF("LoadLibrary",      1, JsEmuObject::load_library),
        JS_CFUNC_DEF("GetModuleName",    1, JsEmuObject::get_module_name),
        JS_CFUNC_DEF("GetModuleHandle",  1, JsEmuObject::get_module_handle),
        JS_CFUNC_DEF("GetProcAddr",      2, JsEmuObject::get_proc_address),

        // Registers
        JS_CFUNC_DEF("ReadReg",  1, JsEmuObject::read_reg),
        JS_CFUNC_DEF("SetReg",   2, JsEmuObject::set_reg),

        // Strings
        JS_CFUNC_DEF("ReadStringA",  1, JsEmuObject::read_string_a),
        JS_CFUNC_DEF("ReadStringW",  1, JsEmuObject::read_string_w),
        JS_CFUNC_DEF("WriteStringA", 2, JsEmuObject::write_string_a),
        JS_CFUNC_DEF("WriteStringW", 2, JsEmuObject::write_string_w),

        // Memory write
        JS_CFUNC_DEF("WriteByte",  2, JsEmuObject::write_byte),
        JS_CFUNC_DEF("WriteWord",  2, JsEmuObject::write_word),
        JS_CFUNC_DEF("WriteDword", 2, JsEmuObject::write_dword),
        JS_CFUNC_DEF("WriteQword", 2, JsEmuObject::write_qword),
        JS_CFUNC_DEF("WriteMem",   2, JsEmuObject::write_mem),

        // Memory read
        JS_CFUNC_DEF("ReadByte",  1, JsEmuObject::read_byte),
        JS_CFUNC_DEF("ReadWord",  1, JsEmuObject::read_word),
        JS_CFUNC_DEF("ReadDword", 1, JsEmuObject::read_dword),
        JS_CFUNC_DEF("ReadQword", 1, JsEmuObject::read_qword),
        JS_CFUNC_DEF("ReadMem",   1, JsEmuObject::read_mem),

        // Stack
        JS_CFUNC_DEF("push", 1, JsEmuObject::push),
        JS_CFUNC_DEF("pop",  0, JsEmuObject::pop),

        // Control
        JS_CFUNC_DEF("Stop",      0, JsEmuObject::stop),
        JS_CFUNC_DEF("LastError", 0, JsEmuObject::last_error),

        // Debug
        JS_CFUNC_DEF("HexDump",   3, JsEmuObject::hex_dump),
        JS_CFUNC_DEF("StackDump", 2, JsEmuObject::stack_dump),
    };

    JS_SetPropertyFunctionList(ctx, emu_obj_, emu_funcs,
                               sizeof(emu_funcs) / sizeof(emu_funcs[0]));

    // Register as global
    JSValue global = JS_GetGlobalObject(ctx);
    JS_SetPropertyStr(ctx, global, "Emu", emu_obj_);
    JS_FreeValue(ctx, global);
}

// ============================================================================
// register_log_functions() - console, print, info, warn, error globals
// ============================================================================

void JsPluginEngine::register_log_functions(JSContext* ctx) {
    JSValue global = JS_GetGlobalObject(ctx);

    // Override console object with our own
    JSValue console = JS_NewObject(ctx);
    JS_SetPropertyStr(ctx, console, "log",
        JS_NewCFunctionMagic(ctx, js_logme, "log", 1, JS_CFUNC_generic_magic, 1));
    JS_SetPropertyStr(ctx, global, "console", console);
    JS_FreeValue(ctx, console);

    // Global logging functions with magic numbers for level control.
    // NOTE: JS_SetPropertyStr takes OWNERSHIP of the value — do NOT FreeValue it.
    JS_SetPropertyStr(ctx, global, "print",
        JS_NewCFunctionMagic(ctx, js_logme, "print", 1, JS_CFUNC_generic_magic, 0));
    JS_SetPropertyStr(ctx, global, "log",
        JS_NewCFunctionMagic(ctx, js_logme, "log", 1, JS_CFUNC_generic_magic, 1));
    JS_SetPropertyStr(ctx, global, "info",
        JS_NewCFunctionMagic(ctx, js_logme, "info", 1, JS_CFUNC_generic_magic, 2));
    JS_SetPropertyStr(ctx, global, "warn",
        JS_NewCFunctionMagic(ctx, js_logme, "warn", 1, JS_CFUNC_generic_magic, 3));
    JS_SetPropertyStr(ctx, global, "error",
        JS_NewCFunctionMagic(ctx, js_logme, "error", 1, JS_CFUNC_generic_magic, 4));

    JS_FreeValue(ctx, global);
}

// ============================================================================
// Module loader callbacks (ES6 import support)
// ============================================================================

char* JsPluginEngine::module_normalize_cb(JSContext* ctx, const char* module_base_name,
                                            const char* module_name, void* opaque) {
    // Default normalization: return the module name as-is
    // QuickJS expects us to return a malloc'd string
    size_t len = strlen(module_name);
    char* result = (char*)js_malloc(ctx, len + 1);
    if (result) {
        memcpy(result, module_name, len + 1);
    }
    return result;
}

JSModuleDef* JsPluginEngine::module_loader_cb(JSContext* ctx, const char* module_name,
                                                void* opaque) {
    (void)opaque;

    // Try to load as a file
    size_t buf_len = 0;
    char* buf = load_file_content(ctx, module_name, &buf_len);
    if (buf) {
        // Evaluate as module
        JSValue func_val = JS_Eval(ctx, buf, buf_len, module_name,
                                    JS_EVAL_TYPE_MODULE | JS_EVAL_FLAG_COMPILE_ONLY);
        js_free(ctx, buf);

        if (JS_IsException(func_val)) {
            dump_error(ctx);
            return nullptr;
        }

        // The result is a module definition
        // QuickJS-ng returns the module directly from JS_Eval with COMPILE_ONLY flag
        JSModuleDef* m = (JSModuleDef*)JS_VALUE_GET_PTR(func_val);
        // Don't free func_val as it contains the module pointer
        return m;
    }

    // For "std" and "os" module requests, return nullptr
    // (they won't be available; the bridge in init() handles the import)
    return nullptr;
}

// ============================================================================
// dump_error() - Print JS exception with stack trace
// ============================================================================

void JsPluginEngine::dump_error(JSContext* ctx) {
    JSValue exception_val = JS_GetException(ctx);
    if (JS_IsException(exception_val)) {
        PLOG_ERROR << "[JS] <no exception available>";
        return;
    }

    // Try to get the stack property
    JSValue stack_val = JS_GetPropertyStr(ctx, exception_val, "stack");
    const char* stack_str = nullptr;
    bool has_stack = false;

    if (!JS_IsUndefined(stack_val) && !JS_IsException(stack_val)) {
        stack_str = JS_ToCString(ctx, stack_val);
        if (stack_str) {
            has_stack = true;
            PLOG_ERROR << "[JS] " << stack_str;
        }
    }
    if (stack_str) {
        JS_FreeCString(ctx, stack_str);
    }
    JS_FreeValue(ctx, stack_val);

    // Fallback: print the exception as a string
    if (!has_stack) {
        const char* str = JS_ToCString(ctx, exception_val);
        if (str) {
            PLOG_ERROR << "[JS] Uncaught exception: " << str;
            JS_FreeCString(ctx, str);
        } else {
            PLOG_ERROR << "[JS] Uncaught exception: <unknown>";
        }
    }

    JS_FreeValue(ctx, exception_val);
}

// ============================================================================
// load_file_content() - Read a file into a malloc'd buffer (QuickJS-owned)
// ============================================================================

char* JsPluginEngine::load_file_content(JSContext* ctx, const char* filename,
                                          size_t* out_len) {
    std::ifstream file(filename, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        return nullptr;
    }

    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);

    // Allocate with js_malloc so QuickJS owns the memory
    char* buf = (char*)js_malloc(ctx, static_cast<size_t>(size) + 1);
    if (!buf) {
        return nullptr;
    }

    if (!file.read(buf, size)) {
        js_free(ctx, buf);
        return nullptr;
    }
    buf[size] = '\0';

    if (out_len) {
        *out_len = static_cast<size_t>(size);
    }
    return buf;
}

} // namespace speakeasy
