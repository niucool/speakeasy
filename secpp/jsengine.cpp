// jsengine.cpp - JavaScript plugin engine for Speakeasy (quickjspp wrapper)
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
static Speakeasy& get_speakeasy(JSContext* raw_ctx) {
    JSRuntime* rt = JS_GetRuntime(raw_ctx);
    auto* engine = static_cast<JsPluginEngine*>(JS_GetRuntimeOpaque(rt));
    return engine->speakeasy();
}

static JsPluginEngine& get_engine(JSContext* raw_ctx) {
    JSRuntime* rt = JS_GetRuntime(raw_ctx);
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
    // RAII: hook_registry_ destroyed first (remove_all),
    // then ctx_ (auto-frees all JS values, class protos, globals),
    // then rt_ (frees the runtime).
    // emu_obj_ and api_class_proto_ are qjs::Value with ctx=nullptr
    // (ownership was transferred via .release() during init), so no double-free.
    if (hook_registry_) {
        hook_registry_->remove_all();
    }
}

// ============================================================================
// init() - Initialize QuickJS runtime, context, register globals and classes
// ============================================================================

bool JsPluginEngine::init() {
    try {
        // 1. Create JSRuntime
        rt_ = std::make_unique<qjs::Runtime>();
        JS_SetRuntimeOpaque(rt_->rt, this);
        // Override module loader (qjs::Runtime sets a default one)
        JS_SetModuleLoaderFunc(rt_->rt, module_normalize_cb, module_loader_cb, this);

        // 2. Create JSContext
        ctx_ = std::make_unique<qjs::Context>(rt_->rt);

        // 3. Register the ApiHook native class
        register_native_class();

        // 4. Create the Emu global object
        init_emu_object();

        // 5. Register global logging functions
        register_log_functions();

        // 6. Register importScripts global
        ctx_->global()["importScripts"] = std::function<qjs::Value(qjs::rest<qjs::Value>)>(
            [this](qjs::rest<qjs::Value> args) -> qjs::Value {
                JSContext* raw_ctx = ctx_->ctx;
                for (auto& arg : args) {
                    std::string filename = (std::string)arg;
                    std::ifstream f(filename);
                    if (!f.good()) {
                        return qjs::Value{raw_ctx, JS_ThrowReferenceError(raw_ctx,
                            "Could not load \"%s\"", filename.c_str())};
                    }
                    PLOG_INFO << "JS loading module: " << filename;
                    if (!eval_file(filename, JS_EVAL_TYPE_GLOBAL)) {
                        return qjs::Value{raw_ctx, JS_EXCEPTION};
                    }
                }
                return qjs::Value{raw_ctx, JS_UNDEFINED};
            });

        // 7. Initialize hook registry
        hook_registry_ = std::make_unique<JsApiHookRegistry>(ctx_->ctx, speakeasy_);

        // 8. std/os module bridge skipped (quickjs-ng without libc)
        // All necessary globals are already registered above.

        return true;
    } catch (qjs::exception& e) {
        PLOG_ERROR << "JsPluginEngine: init failed";
        return false;
    } catch (const std::exception& e) {
        PLOG_ERROR << "JsPluginEngine: init failed: " << e.what();
        return false;
    }
}

// ============================================================================
// eval_buf() / eval_file() / load_script()
// ============================================================================

bool JsPluginEngine::eval_buf(const std::string& code, const std::string& filename,
                               int flags) {
    if (!ctx_) {
        PLOG_ERROR << "JsPluginEngine: eval_buf called before init()";
        return false;
    }
    try {
        ctx_->eval(code, filename.c_str(), flags);
        return true;
    } catch (qjs::exception& e) {
        dump_error(ctx_->ctx);
        return false;
    }
}

bool JsPluginEngine::eval_file(const std::string& filename, int flags) {
    if (!ctx_) {
        PLOG_ERROR << "JsPluginEngine: eval_file called before init()";
        return false;
    }
    try {
        ctx_->evalFile(filename.c_str(), flags);
        return true;
    } catch (qjs::exception& e) {
        dump_error(ctx_->ctx);
        return false;
    } catch (const std::runtime_error& e) {
        PLOG_ERROR << "JsPluginEngine: failed to load file: " << filename
                   << " (" << e.what() << ")";
        return false;
    }
}

bool JsPluginEngine::load_script(const std::string& filename) {
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
// register_native_class() - Register the ApiHook JS class
// ============================================================================

void JsPluginEngine::register_native_class() {
    JSContext* raw_ctx = ctx_->ctx;

    JSClassDef api_class_def = {};
    api_class_def.class_name = "ApiHook";
    JS_NewClassID(rt_->rt, &api_class_id_);
    JS_NewClass(rt_->rt, api_class_id_, &api_class_def);

    // Create prototype with install() method (raw C API — needs this_val)
    api_class_proto_ = qjs::Value{raw_ctx, JS_NewObject(raw_ctx)};

    // install() needs raw JSCFunction to access this_val
    JS_SetPropertyStr(raw_ctx, api_class_proto_.v, "install",
        JS_NewCFunction2(raw_ctx,
            [](JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) -> JSValue {
                auto& engine = get_engine(ctx);
                if (argc < 1) {
                    return JS_ThrowInternalError(ctx,
                        "install expects args (libname, ApiName) or (libname, Ordinal) or (Address)");
                }

                bool is_address = false, is_ordinal = false;
                std::string lib, name;
                uint32_t ordinal = 0;
                uint64_t address = 0;

                if (argc == 1) {
                    is_address = true;
                    int64_t addr = 0;
                    if (JS_ToInt64(ctx, &addr, argv[0]) < 0) return JS_EXCEPTION;
                    address = static_cast<uint64_t>(addr);
                } else {
                    const char* lib_str = JS_ToCString(ctx, argv[0]);
                    if (!lib_str) return JS_EXCEPTION;
                    lib = lib_str;
                    JS_FreeCString(ctx, lib_str);

                    int tag = JS_VALUE_GET_NORM_TAG(argv[1]);
                    if (tag == JS_TAG_STRING) {
                        const char* name_str = JS_ToCString(ctx, argv[1]);
                        if (!name_str) return JS_EXCEPTION;
                        name = name_str;
                        JS_FreeCString(ctx, name_str);
                    } else if (tag == JS_TAG_INT) {
                        is_ordinal = true;
                        if (JS_ToUint32(ctx, &ordinal, argv[1]) < 0) return JS_EXCEPTION;
                    } else {
                        return JS_ThrowInternalError(ctx,
                            "install expects args (libname, ApiName) or (libname, Ordinal)");
                    }
                }

                // Get OnCallBack and OnExit from this_val
                JSValue on_cb = JS_GetPropertyStr(ctx, this_val, "OnCallBack");
                JSValue on_ex = JS_GetPropertyStr(ctx, this_val, "OnExit");

                if (JS_IsUndefined(on_cb)) {
                    return JS_ThrowInternalError(ctx, "\"OnCallBack\" must be set");
                }
                if (!JS_IsFunction(ctx, on_cb)) {
                    return JS_ThrowInternalError(ctx, "\"OnCallBack\" must be a function");
                }

                if (!JS_IsUndefined(on_ex) && !JS_IsFunction(ctx, on_ex)) {
                    return JS_ThrowInternalError(ctx, "\"OnExit\" must be a function");
                }

                // Delegate to hook registry
                bool success = engine.hook_registry_->install(
                    this_val, lib, name, ordinal, is_ordinal, address, is_address,
                    on_cb, on_ex);

                JS_FreeValue(ctx, on_cb);
                JS_FreeValue(ctx, on_ex);

                return JS_NewBool(ctx, success);
            },
            "install", 2, JS_CFUNC_generic, 0));
    // Note: JS_SetPropertyStr takes ownership of the function via set_value()

    JS_SetClassProto(raw_ctx, api_class_id_, api_class_proto_.v);

    // Constructor (raw C API — needs JS_CFUNC_constructor flag)
    JSValue ctor = JS_NewCFunction2(raw_ctx,
        [](JSContext* ctx, JSValueConst new_target, int argc, JSValueConst* argv) -> JSValue {
            (void)argc; (void)argv;
            auto& engine = get_engine(ctx);
            JSValue obj = JS_NewObjectProtoClass(ctx, engine.api_class_proto_.v, engine.api_class_id_);
            if (JS_IsException(obj)) return obj;
            // Note: JS_DefinePropertyValueStr takes ownership of the value
            JS_DefinePropertyValueStr(ctx, obj, "args", JS_NewArray(ctx),
                                      JS_PROP_CONFIGURABLE | JS_PROP_WRITABLE);
            return obj;
        },
        "ApiHook", 1, JS_CFUNC_constructor, 0);

    JS_SetPropertyStr(raw_ctx, ctx_->global().v, "ApiHook", ctor);
    // Note: JS_SetPropertyStr takes ownership via set_value()
}

// ============================================================================
// init_emu_object() - Create the Emu global object with all emulator functions
// ============================================================================

void JsPluginEngine::init_emu_object() {
    JSContext* raw_ctx = ctx_->ctx;
    auto& sp = get_speakeasy(raw_ctx);

    qjs::Value emu{raw_ctx, JS_NewObject(raw_ctx)};

    // === Static properties ===
    emu["isx64"]     = (sp.get_ptr_size() == 8);
    emu["PEB"]       = static_cast<int64_t>(sp.get_peb_address());
    emu["TEB"]       = static_cast<int64_t>(sp.get_teb_address());
    emu["PID"]       = static_cast<int64_t>(sp.get_current_pid());

    auto modules = sp.get_user_modules();
    int64_t image_base = 0;
    std::string filename;
    if (!modules.empty() && modules[0]) {
        image_base = static_cast<int64_t>(modules[0]->base);
        filename = modules[0]->name;
    }
    emu["ImageBase"] = image_base;
    emu["Filename"]  = filename;

    // === Module functions ===
    emu["LoadLibrary"] = std::function<int64_t(std::string)>(
        [&sp](std::string name) -> int64_t {
            // Normalize: basename, lowercase, strip ext, add .dll
            auto slash = name.find_last_of("/\\");
            std::string fname = (slash != std::string::npos) ? name.substr(slash + 1) : name;
            auto dot = fname.rfind('.');
            std::string base = (dot != std::string::npos) ? fname.substr(0, dot) : fname;
            std::transform(base.begin(), base.end(), base.begin(), ::tolower);
            return static_cast<int64_t>(sp.load_library(base + ".dll"));
        });

    emu["GetModuleHandle"] = std::function<int64_t(std::string)>(
        [&sp](std::string name) -> int64_t {
            return static_cast<int64_t>(sp.get_module_handle_by_name(name));
        });

    emu["GetModuleName"] = std::function<qjs::Value(int64_t)>(
        [&sp](int64_t handle) -> qjs::Value {
            // Can't return string easily without JSContext — use raw API
            (void)handle; (void)sp;
            return qjs::Value{JS_UNDEFINED};
        });

    emu["GetProcAddr"] = std::function<int64_t(int64_t, std::string)>(
        [&sp](int64_t handle, std::string name) -> int64_t {
            return static_cast<int64_t>(
                sp.get_proc_address(static_cast<uint64_t>(handle), name));
        });

    // === Register functions ===
    emu["ReadReg"]  = std::function<int64_t(int32_t)>([&sp](int32_t id) { return static_cast<int64_t>(sp.reg_read(id)); });
    emu["SetReg"]   = std::function<bool(int32_t, int64_t)>([&sp](int32_t id, int64_t v) { sp.reg_write(id, static_cast<uint64_t>(v)); return true; });

    // === String functions ===
    emu["ReadStringA"]  = std::function<std::string(int64_t)>([&sp](int64_t addr) { return sp.read_mem_string(static_cast<uint64_t>(addr), 1); });
    emu["ReadStringW"]  = std::function<std::string(int64_t)>([&sp](int64_t addr) { return sp.read_mem_string(static_cast<uint64_t>(addr), 2); });
    emu["WriteStringA"] = std::function<int32_t(int64_t, std::string)>([&sp](int64_t addr, std::string s) {
        std::vector<uint8_t> d(s.size() + 1); memcpy(d.data(), s.c_str(), s.size() + 1); sp.mem_write(static_cast<uint64_t>(addr), d); return (int32_t)(s.size() + 1); });
    emu["WriteStringW"] = std::function<int32_t(int64_t, std::string)>([&sp](int64_t addr, std::string s) {
        std::vector<uint8_t> d((s.size() + 1) * 2); for (size_t i = 0; i < s.size(); i++) { d[i*2] = (uint8_t)s[i]; d[i*2+1] = 0; } d[s.size()*2] = d[s.size()*2+1] = 0; sp.mem_write(static_cast<uint64_t>(addr), d); return (int32_t)((s.size()+1)*2); });

    // === Memory read/write ===
    emu["ReadByte"]   = std::function<int32_t(int64_t)>([&sp](int64_t a) { auto d=sp.mem_read((uint64_t)a,1); return d.empty()?0:(int32_t)d[0]; });
    emu["ReadWord"]   = std::function<int32_t(int64_t)>([&sp](int64_t a) { auto d=sp.mem_read((uint64_t)a,2); return d.size()<2?0:(int32_t)(d[0]|(d[1]<<8)); });
    emu["ReadDword"]  = std::function<int64_t(int64_t)>([&sp](int64_t a) { auto d=sp.mem_read((uint64_t)a,4); return d.size()<4?0:(int64_t)(d[0]|(d[1]<<8)|(d[2]<<16)|(d[3]<<24)); });
    emu["ReadQword"]  = std::function<int64_t(int64_t)>([&sp](int64_t a) { auto d=sp.mem_read((uint64_t)a,8); return d.size()<8?0:(int64_t)(d[0]|((int64_t)d[1]<<8)|((int64_t)d[2]<<16)|((int64_t)d[3]<<24)|((int64_t)d[4]<<32)|((int64_t)d[5]<<40)|((int64_t)d[6]<<48)|((int64_t)d[7]<<56)); });

    emu["WriteByte"]  = std::function<bool(int64_t,int32_t)>([&sp](int64_t a,int32_t v) { sp.mem_write((uint64_t)a,{(uint8_t)v}); return true; });
    emu["WriteWord"]  = std::function<bool(int64_t,int32_t)>([&sp](int64_t a,int32_t v) { uint16_t v16=(uint16_t)v; sp.mem_write((uint64_t)a,{(uint8_t)(v16&0xFF),(uint8_t)(v16>>8)}); return true; });
    emu["WriteDword"] = std::function<bool(int64_t,int32_t)>([&sp](int64_t a,int32_t v) { uint32_t v32=(uint32_t)v; sp.mem_write((uint64_t)a,{(uint8_t)(v32&0xFF),(uint8_t)(v32>>8),(uint8_t)(v32>>16),(uint8_t)(v32>>24)}); return true; });
    emu["WriteQword"] = std::function<bool(int64_t,int64_t)>([&sp](int64_t a,int64_t v) { uint64_t v64=(uint64_t)v; sp.mem_write((uint64_t)a,{(uint8_t)(v64&0xFF),(uint8_t)(v64>>8),(uint8_t)(v64>>16),(uint8_t)(v64>>24),(uint8_t)(v64>>32),(uint8_t)(v64>>40),(uint8_t)(v64>>48),(uint8_t)(v64>>56)}); return true; });
    emu["WriteMem"]   = std::function<bool(int64_t,qjs::rest<qjs::Value>)>([&sp](int64_t a,qjs::rest<qjs::Value> arr) { for(size_t i=0;i<arr.size();i++){uint8_t b=(uint8_t)(int32_t)arr[i];sp.mem_write((uint64_t)a+i,{b});} return true; });
    emu["ReadMem"]    = std::function<qjs::Value(int64_t,int32_t)>([](int64_t,int32_t){ return qjs::Value{JS_UNDEFINED}; }); // TODO

    // === Stack ===
    emu["push"] = std::function<bool(int64_t)>([&sp](int64_t v) { sp.push_stack((uint64_t)v); return true; });
    emu["pop"]  = std::function<int64_t()>([&sp]() { return (int64_t)sp.pop_stack(); });

    // === Control ===
    emu["Stop"]      = std::function<bool()>([&sp]() { sp.stop(); return true; });
    emu["LastError"] = std::function<std::string()>([]() { return "no error"; });

    // === Debug ===
    emu["HexDump"]   = std::function<qjs::Value(int64_t,int32_t,int32_t)>([&sp](int64_t a,int32_t len,int32_t cols) {
        if(len<=0)return qjs::Value{JS_UNDEFINED};
        auto d=sp.mem_read((uint64_t)a,(size_t)len);std::ostringstream o;o<<std::hex;for(size_t i=0;i<d.size();i++){if(i%(uint32_t)cols==0){if(i>0)o<<'\n';o<<std::setw(8)<<((uint64_t)a+i)<<"  ";}o<<std::setw(2)<<(int)d[i]<<' ';}PLOG_INFO<<"[JS] HexDump:\n"<<o.str();return qjs::Value{JS_UNDEFINED};});
    emu["StackDump"] = std::function<qjs::Value(int64_t,int32_t)>([&sp](int64_t a,int32_t len) {
        if(len<=0)return qjs::Value{JS_UNDEFINED};
        int ps=sp.get_ptr_size();auto d=sp.mem_read((uint64_t)a,(size_t)len);std::ostringstream o;o<<std::hex<<"Stack Dump:\n";
        for(size_t i=0;i+(size_t)ps<=d.size();i+=ps){uint64_t v=0;for(int j=0;j<ps;j++)v|=(uint64_t)d[i+j]<<(j*8);o<<"  "<<std::setw(ps*2)<<((uint64_t)a+i)<<": "<<std::setw(ps*2)<<v<<'\n';}PLOG_INFO<<"[JS] "<<o.str();return qjs::Value{JS_UNDEFINED};});

    // Transfer ownership of emu_obj to the global property
    // release() gives up ownership so qjs::Value destructor won't double-free
    ctx_->global()["Emu"] = emu.release();

    // Keep a non-owning reference for cleanup order tracking
    emu_obj_ = qjs::Value{JS_UNDEFINED};
}

// ============================================================================
// register_log_functions() - console, print, info, warn, error globals
// ============================================================================

void JsPluginEngine::register_log_functions() {
    // global() returns Value by value, must store it (not auto&)
    auto g = ctx_->global();

    auto make_logger = [](int magic) {
        return std::function<qjs::Value(qjs::rest<qjs::Value>)>(
            [magic](qjs::rest<qjs::Value> args) -> qjs::Value {
                std::ostringstream oss;
                for (size_t i = 0; i < args.size(); i++) {
                    if (i > 0) oss << ' ';
                    oss << (std::string)args[i];
                }
                switch (magic) {
                    case 0: case 1: PLOG_INFO << "[JS] " << oss.str(); break;
                    case 2:          PLOG_INFO << "[JS:info] " << oss.str(); break;
                    case 3:          PLOG_WARNING << "[JS:warn] " << oss.str(); break;
                    case 4:          PLOG_ERROR << "[JS:error] " << oss.str(); break;
                    default:         PLOG_INFO << "[JS] " << oss.str(); break;
                }
                return qjs::Value{JS_UNDEFINED};
            });
    };

    // Console object
    qjs::Value console{ctx_->ctx, JS_NewObject(ctx_->ctx)};
    console["log"] = make_logger(1);
    g["console"] = console.release();

    // Global functions
    g["print"] = make_logger(0);
    g["log"]   = make_logger(1);
    g["info"]  = make_logger(2);
    g["warn"]  = make_logger(3);
    g["error"] = make_logger(4);
}

// ============================================================================
// Module loader callbacks
// ============================================================================

char* JsPluginEngine::module_normalize_cb(JSContext* ctx, const char* module_base_name,
                                            const char* module_name, void* opaque) {
    size_t len = strlen(module_name);
    char* result = (char*)js_malloc(ctx, len + 1);
    if (result) memcpy(result, module_name, len + 1);
    return result;
}

JSModuleDef* JsPluginEngine::module_loader_cb(JSContext* ctx, const char* module_name,
                                                void* opaque) {
    // Try to load as a file
    std::string content = load_file_content(module_name);
    if (!content.empty()) {
        JSValue func_val = JS_Eval(ctx, content.c_str(), content.size(), module_name,
                                    JS_EVAL_TYPE_MODULE | JS_EVAL_FLAG_COMPILE_ONLY);
        if (JS_IsException(func_val)) {
            dump_error(ctx);
            return nullptr;
        }
        return (JSModuleDef*)JS_VALUE_GET_PTR(func_val);
    }
    return nullptr;
}

// ============================================================================
// dump_error() - Print JS exception with stack trace
// ============================================================================

void JsPluginEngine::dump_error(JSContext* raw_ctx) {
    JSValue exc = JS_GetException(raw_ctx);
    if (JS_IsException(exc)) {
        PLOG_ERROR << "[JS] <no exception available>";
        return;
    }

    JSValue stack = JS_GetPropertyStr(raw_ctx, exc, "stack");
    const char* str = nullptr;
    if (!JS_IsUndefined(stack) && !JS_IsException(stack)) {
        str = JS_ToCString(raw_ctx, stack);
        if (str) { PLOG_ERROR << "[JS] " << str; JS_FreeCString(raw_ctx, str); }
    }
    JS_FreeValue(raw_ctx, stack);

    if (!str) {
        str = JS_ToCString(raw_ctx, exc);
        if (str) { PLOG_ERROR << "[JS] Uncaught exception: " << str; JS_FreeCString(raw_ctx, str); }
    }
    JS_FreeValue(raw_ctx, exc);
}

// ============================================================================
// load_file_content() - Read a file into a string
// ============================================================================

std::string JsPluginEngine::load_file_content(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary | std::ios::ate);
    if (!file.is_open()) return "";
    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);
    std::string buf(static_cast<size_t>(size), '\0');
    if (!file.read(buf.data(), size)) return "";
    return buf;
}

} // namespace speakeasy
