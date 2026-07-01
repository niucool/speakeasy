// jsengine.cpp - JavaScript plugin engine for Speakeasy (quickjspp modernized)
#include "jsengine.h"
#include "jsemuobj.h"
#include "jsapihook.h"
#include "speakeasy.h"

#include <fstream>
#include <sstream>
#include <filesystem>
#include <stdexcept>
#include <plog/Log.h>

namespace speakeasy {

    // ============================================================================
    // Constructor / Destructor
    // ============================================================================

    JsPluginEngine::JsPluginEngine(Speakeasy& speakeasy)
        : speakeasy_(speakeasy)
    {}

    JsPluginEngine::~JsPluginEngine() {
        hook_registry_.reset();
        context_.reset();
        runtime_.reset();
    }

    JSRuntime* JsPluginEngine::runtime() const {
        return runtime_ ? runtime_->rt : nullptr;
    }

    JSContext* JsPluginEngine::context() const {
        return context_ ? context_->ctx : nullptr;
    }

    // ============================================================================
    // init() - Initialize QuickJS runtime, context, register globals and classes
    // ============================================================================

    bool JsPluginEngine::init() {
        try {
            runtime_ = std::make_unique<qjs::Runtime>();

            // Pass a pointer back to this engine instance via runtime opaque if needed by raw subsystems
            JS_SetRuntimeOpaque(runtime_->rt, this);

            context_ = std::make_unique<qjs::Context>(*runtime_);

            // Modern module loader utilizing quickjspp builtin infrastructure
            context_->moduleLoader = [](std::string_view module_name) -> qjs::Context::ModuleData {
                auto source = qjs::detail::readFile(std::filesystem::path(std::string(module_name)));
                if (!source) {
                    return {};
                }
                return { qjs::detail::toUri(module_name), std::move(*source) };
                };


            register_native_class();
            init_emu_object();
            register_log_functions();

            // Modern registration of importScripts with variadic argument capabilities via custom wrapper or standard vector mapping
            context_->global()["importScripts"] = [this](qjs::Value this_val, std::vector<std::string> args) {
                this->js_native_import_scripts(std::move(this_val), args);
                };

            hook_registry_ = std::make_unique<JsApiHookRegistry>(*context_, speakeasy_);
            return true;
        }
        catch (const std::exception& e) {
            PLOG_ERROR << "JsPluginEngine: init failed: " << e.what();
            hook_registry_.reset();
            context_.reset();
            runtime_.reset();
            return false;
        }
        catch (...) {
            PLOG_ERROR << "JsPluginEngine: init failed with unknown exception";
            hook_registry_.reset();
            context_.reset();
            runtime_.reset();
            return false;
        }
    }

    // ============================================================================
    // eval_buf() / eval_file() / load_script()
    // ============================================================================

    qjs::Value JsPluginEngine::eval_buf(const std::string& code, const std::string& filename, int eval_flags) {
        if (!context_) {
            throw std::runtime_error("JsPluginEngine: eval_buf called before init()");
        }

        try {
            return context_->eval(code, filename.c_str(), eval_flags);
        }
        catch (qjs::exception&) {
            dump_error(*context_);
            throw;
        }
    }

    qjs::Value JsPluginEngine::eval_file(const std::string& filename, int eval_flags) {
        if (!context_) {
            throw std::runtime_error("JsPluginEngine: eval_file called before init()");
        }

        try {
            return context_->evalFile(filename.c_str(), eval_flags);
        }
        catch (qjs::exception&) {
            dump_error(*context_);
            throw;
        }
    }

    bool JsPluginEngine::load_script(const std::string& filename) {
        if (!std::filesystem::exists(filename)) {
            PLOG_ERROR << "JsPluginEngine: script not found: " << filename;
            return false;
        }

        PLOG_INFO << "Loading JS main script: " << filename;

        try {
            eval_file(filename, JS_EVAL_TYPE_GLOBAL | JS_EVAL_TYPE_MODULE);
            return true;
        } catch (const std::exception& e) {
            PLOG_ERROR << "JsPluginEngine: failed to evaluate script: " << filename << " - " << e.what();
            return false;
        }
    }

    // ============================================================================
    // js_logme() - Modern logging distribution logic
    // ============================================================================

    void JsPluginEngine::js_logme(const std::string& message, int magic) {
        switch (magic) {
        case 0: // print
        case 1: // console.log
            PLOG_INFO << "[JS] " << message;
            break;
        case 2: // info
            PLOG_INFO << "[JS:info] " << message;
            break;
        case 3: // warn
            PLOG_WARNING << "[JS:warn] " << message;
            break;
        case 4: // error
            PLOG_ERROR << "[JS:error] " << message;
            break;
        default:
            PLOG_INFO << "[JS] " << message;
            break;
        }
    }

    // ============================================================================
    // js_native_import_scripts() - importScripts global function
    // ============================================================================

    void JsPluginEngine::js_native_import_scripts(qjs::Value this_val, const std::vector<std::string>& files) {
        for (const auto& filename : files) {
            if (!std::filesystem::exists(filename)) {
                throw std::runtime_error("Could not load \"" + filename + "\"");
            }

            PLOG_INFO << "JS loading module: " << filename;

            eval_file(filename, JS_EVAL_TYPE_GLOBAL); // throws on error
        }
    }

    // ============================================================================
    // register_native_class() - Register ApiHook via QuickJS C API
    // ============================================================================

    qjs::Value JsPluginEngine::create_hook_object(
        std::shared_ptr<JsHook> hook)
    {
        auto* ctx = context_->ctx;


        qjs::Value obj(
            ctx,
            JS_NewObject(ctx));


        obj["id"] = (int)hook->id;


        obj["disable"] =
            [hook]()
            {
                return hook->disable();
            };


        obj["enable"] =
            [hook]()
            {
                return hook->enable();
            };


        obj["remove"] =
            [hook]()
            {
                return hook->remove();
            };


        return obj;
    }

    qjs::Value JsPluginEngine::api_hook_install(qjs::Value config)
    {
        auto* ctx = context_->ctx;

        if (!JS_IsObject(config.v))
        {
            throw std::runtime_error(
                "ApiHook.install expects an object");
        }

        // --- lib ---
        qjs::Value lib_value = config["lib"];

        if (!JS_IsString(lib_value.v))
        {
            throw std::runtime_error(
                "\"lib\" must be a string");
        }

        std::string lib = lib_value.as<std::string>();

        // --- api (name, ordinal, or address) ---
        std::string api_name;
        uint32_t ordinal = 0;
        uint64_t address = 0;
        bool is_ordinal = false;
        bool is_address = false;

        qjs::Value target = config["api"];

        if (JS_IsString(target.v))
        {
            api_name = target.as<std::string>();
        }
        else if (JS_IsNumber(target.v))
        {
            ordinal = target.as<uint32_t>();
            is_ordinal = true;
        }
        else
        {
            throw std::runtime_error(
                "\"api\" must be string or ordinal");
        }

        // --- onCallBack ---
        qjs::Value on_callback = config["onCallBack"];

        if (JS_IsUndefined(on_callback.v))
        {
            throw std::runtime_error(
                "\"onCallBack\" is required");
        }

        if (!JS_IsFunction(ctx, on_callback.v))
        {
            throw std::runtime_error(
                "\"onCallBack\" must be function");
        }

        // --- onExit (optional) ---
        qjs::Value on_exit = config["onExit"];

        if (!JS_IsUndefined(on_exit.v) &&
            !JS_IsFunction(ctx, on_exit.v))
        {
            throw std::runtime_error(
                "\"onExit\" must be function");
        }

        auto hook = std::make_shared<JsHook>(*context_);

        hook->id = (uint64_t)hook_registry_->install(
            lib,
            api_name,
            ordinal,
            is_ordinal,
            address,
            is_address,
            on_callback,
            on_exit);

        hook->api = lib + "." + api_name;
        hook->onCallback = on_callback;
        hook->onExit = on_exit;

        return create_hook_object(hook);
    }

    void JsPluginEngine::register_native_class() {
        qjs::Value api_hook = context_->newObject();

        api_hook["install"] = [this](qjs::Value config) -> qjs::Value {
            return this->api_hook_install(std::move(config));
        };

        context_->global()["ApiHook"] = api_hook;
    }

    // ============================================================================
    // init_emu_object() - Create the Emu global object with properties and list functions
    // ============================================================================

    void JsPluginEngine::init_emu_object() {
        auto& sp = speakeasy_;
        qjs::Value emu_obj = context_->newObject();

        // Set properties safely using standard conversions
        emu_obj["isx64"] = (sp.get_ptr_size() == 8);
        emu_obj["PEB"] = static_cast<int64_t>(sp.get_peb_address());
        emu_obj["TEB"] = static_cast<int64_t>(sp.get_teb_address());
        emu_obj["PID"] = static_cast<int64_t>(sp.get_current_pid());

        auto modules = sp.get_user_modules();
        int64_t image_base = 0;
        std::string filename;
        if (!modules.empty() && modules[0]) {
            image_base = static_cast<int64_t>(modules[0]->base);
            filename = modules[0]->name;
        }
        emu_obj["ImageBase"] = image_base;
        emu_obj["Filename"] = filename;

        // Bind methods using lambda wrappers capturing the emulator object
        auto emu = std::make_shared<JsEmuObject>(sp);

        emu_obj["LoadLibrary"] = [emu](const std::string& libname) { return emu->load_library(libname); };
        emu_obj["GetModuleName"] = [emu](qjs::Value handle_val) { return emu->get_module_name(std::move(handle_val)); };
        emu_obj["GetModuleHandle"] = [emu](qjs::Value name_val) { return emu->get_module_handle(std::move(name_val)); };
        emu_obj["GetProcAddr"] = [emu](int64_t handle, const std::string& fn_name) { return emu->get_proc_address(handle, fn_name); };
        emu_obj["ReadReg"] = [emu](uint32_t reg_id) { return static_cast<int64_t>(emu->read_reg(reg_id)); };
        emu_obj["SetReg"] = [emu](uint32_t reg_id, int64_t value) { return emu->set_reg(reg_id, value); };
        emu_obj["ReadStringA"] = [emu](int64_t addr, qjs::Value max_chars_val) { return emu->read_string_a(addr, std::move(max_chars_val)); };
        emu_obj["ReadStringW"] = [emu](int64_t addr, qjs::Value max_chars_val) { return emu->read_string_w(addr, std::move(max_chars_val)); };
        emu_obj["WriteStringA"] = [emu](int64_t addr, const std::string& str) { return emu->write_string_a(addr, str); };
        emu_obj["WriteStringW"] = [emu](int64_t addr, const std::string& str) { return emu->write_string_w(addr, str); };
        emu_obj["WriteByte"] = [emu](int64_t addr, uint32_t val) { return emu->write_byte(addr, val); };
        emu_obj["WriteWord"] = [emu](int64_t addr, int32_t val) { return emu->write_word(addr, val); };
        emu_obj["WriteDword"] = [emu](int64_t addr, int32_t val) { return emu->write_dword(addr, val); };
        emu_obj["WriteQword"] = [emu](int64_t addr, int64_t val) { return emu->write_qword(addr, val); };
        emu_obj["WriteMem"] = [emu](int64_t addr, const std::vector<uint8_t>& bytes) { return emu->write_mem(addr, bytes); };
        emu_obj["ReadByte"] = [emu](int64_t addr) { return emu->read_byte(addr); };
        emu_obj["ReadWord"] = [emu](int64_t addr) { return emu->read_word(addr); };
        emu_obj["ReadDword"] = [emu](int64_t addr) { return emu->read_dword(addr); };
        emu_obj["ReadQword"] = [emu](int64_t addr) { return emu->read_qword(addr); };
        emu_obj["ReadMem"] = [emu, this](int64_t addr, uint32_t length) { return emu->read_mem(*context_, addr, length); };
        emu_obj["push"] = [emu](int64_t val) { return emu->push(val); };
        emu_obj["pop"] = [emu]() { return emu->pop(); };
        emu_obj["Stop"] = [emu]() { emu->stop(); };
        emu_obj["LastError"] = [emu]() { return emu->last_error(); };
        emu_obj["HexDump"] = [emu](int64_t addr, uint32_t len, qjs::Value cols_val) { emu->hex_dump(addr, len, std::move(cols_val)); };
        emu_obj["StackDump"] = [emu](int64_t addr, uint32_t len) { emu->stack_dump(addr, len); };
        // Register into the context's global object scope
        context_->global()["Emu"] = std::move(emu_obj);
    }

    // ============================================================================
    // register_log_functions() - setup logger wrappers using lambdas
    // ============================================================================

    void JsPluginEngine::register_log_functions() {
        auto global = context_->global();
        auto console = context_->newObject();

        // Helper syntax matching standard JavaScript engine behavior
        auto make_log_wrapper = [this](int level) {
            return [this, level](std::vector<qjs::Value> args) {
                std::ostringstream oss;
                for (size_t i = 0; i < args.size(); ++i) {
                    if (i > 0) oss << ' ';
                    oss << static_cast<std::string>(args[i]);
                }
                this->js_logme(oss.str(), level);
                };
            };

        console["log"] = make_log_wrapper(1);
        global["console"] = std::move(console);

        global["print"] = make_log_wrapper(0);
        global["log"] = make_log_wrapper(1);
        global["info"] = make_log_wrapper(2);
        global["warn"] = make_log_wrapper(3);
        global["error"] = make_log_wrapper(4);
    }

    // ============================================================================
    // dump_error() - Print JS exception with stack trace using modern wrappers
    // ============================================================================

    void JsPluginEngine::dump_error(qjs::Context& ctx) {
        try {
            auto exception_val = ctx.getException();
            if (JS_IsException(exception_val.v)) {
                PLOG_ERROR << "[JS] <no exception available>";
                return;
            }

            qjs::Value stack_val = exception_val["stack"];
            if (!JS_IsUndefined(stack_val.v)) {
                std::string stack_trace = static_cast<std::string>(stack_val);
                PLOG_ERROR << "[JS] " << stack_trace;
            }
            else {
                std::string error_message = static_cast<std::string>(exception_val);
                PLOG_ERROR << "[JS] Uncaught exception: " << error_message;
            }
        }
        catch (...) {
            PLOG_ERROR << "[JS] Error handling crashed inside exception printer context";
        }
    }

} // namespace speakeasy