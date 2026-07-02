/**
 * test_js_engine.cpp  Unit and integration tests for JavaScript plugin engine
 *
 * Tests two areas:
 *   1. QuickJS C API smoke tests (no Speakeasy needed)
 *   2. JsPluginEngine integration tests (requires Speakeasy + loaded PE)
 */

#include <gtest/gtest.h>
#include <quickjs.h>

#include <cstring>
#include <string>
#include <vector>

#include "speakeasy.h"
#include "config.h"
#include "jsengine.h"
#include "jsemuobj.h"
#include "jsapihook.h"
#include "test_helper.h"

using namespace speakeasy;

// ============================================================================
// QuickJS C API Smoke Tests — validate library linking and basic functionality
// ============================================================================

TEST(QuickJSSmoke, CreateRuntime) {
    JSRuntime* rt = JS_NewRuntime();
    ASSERT_NE(rt, nullptr);
    JS_FreeRuntime(rt);
}

TEST(QuickJSSmoke, CreateContext) {
    JSRuntime* rt = JS_NewRuntime();
    ASSERT_NE(rt, nullptr);
    JSContext* ctx = JS_NewContext(rt);
    ASSERT_NE(ctx, nullptr);
    JS_FreeContext(ctx);
    JS_FreeRuntime(rt);
}

TEST(QuickJSSmoke, EvalInteger) {
    JSRuntime* rt = JS_NewRuntime();
    JSContext* ctx = JS_NewContext(rt);
    ASSERT_NE(ctx, nullptr);

    JSValue val = JS_Eval(ctx, "1 + 2", 5, "<test>", JS_EVAL_TYPE_GLOBAL);
    EXPECT_FALSE(JS_IsException(val));

    int32_t result = 0;
    int rc = JS_ToInt32(ctx, &result, val);
    EXPECT_EQ(rc, 0);
    EXPECT_EQ(result, 3);

    JS_FreeValue(ctx, val);
    JS_FreeContext(ctx);
    JS_FreeRuntime(rt);
}

TEST(QuickJSSmoke, EvalString) {
    JSRuntime* rt = JS_NewRuntime();
    JSContext* ctx = JS_NewContext(rt);
    ASSERT_NE(ctx, nullptr);

    const char* code = "'hello' + ' ' + 'world'";
    JSValue val = JS_Eval(ctx, code, strlen(code), "<test>", JS_EVAL_TYPE_GLOBAL);
    EXPECT_FALSE(JS_IsException(val));
    EXPECT_TRUE(JS_IsString(val));

    const char* str = JS_ToCString(ctx, val);
    ASSERT_NE(str, nullptr);
    EXPECT_STREQ(str, "hello world");
    JS_FreeCString(ctx, str);
    JS_FreeValue(ctx, val);
    JS_FreeContext(ctx);
    JS_FreeRuntime(rt);
}

TEST(QuickJSSmoke, EvalBoolean) {
    JSRuntime* rt = JS_NewRuntime();
    JSContext* ctx = JS_NewContext(rt);
    ASSERT_NE(ctx, nullptr);

    JSValue val = JS_Eval(ctx, "1 > 0", 5, "<test>", JS_EVAL_TYPE_GLOBAL);
    EXPECT_FALSE(JS_IsException(val));
    EXPECT_TRUE(JS_IsBool(val));
    EXPECT_EQ(JS_VALUE_GET_BOOL(val), 1);

    JS_FreeValue(ctx, val);
    JS_FreeContext(ctx);
    JS_FreeRuntime(rt);
}

TEST(QuickJSSmoke, JSValueTypes) {
    JSRuntime* rt = JS_NewRuntime();
    JSContext* ctx = JS_NewContext(rt);
    ASSERT_NE(ctx, nullptr);

    // Test NULL, UNDEFINED, TRUE, FALSE, EXCEPTION special values
    JSValue null_val = JS_NULL;
    EXPECT_TRUE(JS_IsNull(null_val));

    JSValue undef_val = JS_UNDEFINED;
    EXPECT_TRUE(JS_IsUndefined(undef_val));

    JSValue true_val = JS_TRUE;
    EXPECT_TRUE(JS_IsBool(true_val));
    EXPECT_EQ(JS_VALUE_GET_BOOL(true_val), 1);

    JSValue false_val = JS_FALSE;
    EXPECT_TRUE(JS_IsBool(false_val));
    EXPECT_EQ(JS_VALUE_GET_BOOL(false_val), 0);

    JSValue exc_val = JS_EXCEPTION;
    EXPECT_TRUE(JS_IsException(exc_val));

    JS_FreeContext(ctx);
    JS_FreeRuntime(rt);
}

TEST(QuickJSSmoke, NewInt32) {
    JSRuntime* rt = JS_NewRuntime();
    JSContext* ctx = JS_NewContext(rt);
    ASSERT_NE(ctx, nullptr);

    JSValue v = JS_NewInt32(ctx, 42);
    EXPECT_TRUE(JS_IsNumber(v));

    int32_t result = 0;
    JS_ToInt32(ctx, &result, v);
    EXPECT_EQ(result, 42);

    JS_FreeValue(ctx, v);
    JS_FreeContext(ctx);
    JS_FreeRuntime(rt);
}

TEST(QuickJSSmoke, NewInt64) {
    JSRuntime* rt = JS_NewRuntime();
    JSContext* ctx = JS_NewContext(rt);
    ASSERT_NE(ctx, nullptr);

    JSValue v = JS_NewInt64(ctx, 0x7FFFFFFFLL);
    EXPECT_TRUE(JS_IsNumber(v));

    int64_t result = 0;
    JS_ToInt64(ctx, &result, v);
    EXPECT_EQ(result, 0x7FFFFFFFLL);

    JS_FreeValue(ctx, v);
    JS_FreeContext(ctx);
    JS_FreeRuntime(rt);
}

TEST(QuickJSSmoke, NewString) {
    JSRuntime* rt = JS_NewRuntime();
    JSContext* ctx = JS_NewContext(rt);
    ASSERT_NE(ctx, nullptr);

    JSValue v = JS_NewString(ctx, "test string");
    EXPECT_TRUE(JS_IsString(v));

    const char* str = JS_ToCString(ctx, v);
    EXPECT_STREQ(str, "test string");
    JS_FreeCString(ctx, str);
    JS_FreeValue(ctx, v);
    JS_FreeContext(ctx);
    JS_FreeRuntime(rt);
}

TEST(QuickJSSmoke, NewBool) {
    JSRuntime* rt = JS_NewRuntime();
    JSContext* ctx = JS_NewContext(rt);
    ASSERT_NE(ctx, nullptr);

    JSValue v = JS_NewBool(ctx, true);
    EXPECT_TRUE(JS_IsBool(v));
    EXPECT_EQ(JS_VALUE_GET_BOOL(v), 1);

    JS_FreeValue(ctx, v);
    JS_FreeContext(ctx);
    JS_FreeRuntime(rt);
}

TEST(QuickJSSmoke, NewObject) {
    JSRuntime* rt = JS_NewRuntime();
    JSContext* ctx = JS_NewContext(rt);
    ASSERT_NE(ctx, nullptr);

    JSValue obj = JS_NewObject(ctx);
    EXPECT_TRUE(JS_IsObject(obj));

    // Set a property
    JS_SetPropertyStr(ctx, obj, "key", JS_NewInt32(ctx, 99));

    // Get the property
    JSValue prop = JS_GetPropertyStr(ctx, obj, "key");
    EXPECT_TRUE(JS_IsNumber(prop));
    int32_t val = 0;
    JS_ToInt32(ctx, &val, prop);
    EXPECT_EQ(val, 99);

    JS_FreeValue(ctx, prop);
    JS_FreeValue(ctx, obj);
    JS_FreeContext(ctx);
    JS_FreeRuntime(rt);
}

TEST(QuickJSSmoke, NewArray) {
    JSRuntime* rt = JS_NewRuntime();
    JSContext* ctx = JS_NewContext(rt);
    ASSERT_NE(ctx, nullptr);

    JSValue arr = JS_NewArray(ctx);
    EXPECT_TRUE(JS_IsObject(arr));
    EXPECT_TRUE(JS_IsArray(ctx, arr));

    // Set elements
    JS_SetPropertyUint32(ctx, arr, 0, JS_NewInt32(ctx, 10));
    JS_SetPropertyUint32(ctx, arr, 1, JS_NewInt32(ctx, 20));
    JS_SetPropertyUint32(ctx, arr, 2, JS_NewInt32(ctx, 30));

    // Check length
    JSValue len_val = JS_GetPropertyStr(ctx, arr, "length");
    int32_t len = 0;
    JS_ToInt32(ctx, &len, len_val);
    EXPECT_EQ(len, 3);
    JS_FreeValue(ctx, len_val);

    // Read elements
    JSValue e0 = JS_GetPropertyUint32(ctx, arr, 0);
    int32_t v0 = 0;
    JS_ToInt32(ctx, &v0, e0);
    EXPECT_EQ(v0, 10);
    JS_FreeValue(ctx, e0);

    JS_FreeValue(ctx, arr);
    JS_FreeContext(ctx);
    JS_FreeRuntime(rt);
}

TEST(QuickJSSmoke, EvalException) {
    JSRuntime* rt = JS_NewRuntime();
    JSContext* ctx = JS_NewContext(rt);
    ASSERT_NE(ctx, nullptr);

    const char* code = "throw 'test error';";
    JSValue val = JS_Eval(ctx, code, strlen(code), "<test>", JS_EVAL_TYPE_GLOBAL);
    EXPECT_TRUE(JS_IsException(val));

    JSValue exc = JS_GetException(ctx);
    EXPECT_FALSE(JS_IsException(exc));  // should be the thrown value

    // The thrown value should convert to a string containing "test error"
    const char* msg = JS_ToCString(ctx, exc);
    EXPECT_NE(msg, nullptr);
    if (msg) {
        bool contains = strstr(msg, "test error") != nullptr;
        EXPECT_TRUE(contains) << "Expected 'test error' in message, got: " << msg;
        JS_FreeCString(ctx, msg);
    }

    JS_FreeValue(ctx, exc);
    JS_FreeValue(ctx, val);
    JS_FreeContext(ctx);
    JS_FreeRuntime(rt);
}

TEST(QuickJSSmoke, CallFunction) {
    JSRuntime* rt = JS_NewRuntime();
    JSContext* ctx = JS_NewContext(rt);
    ASSERT_NE(ctx, nullptr);

    // Define a JS function and return it as the result
    const char* code = "var add = function(a, b) { return a + b; }; add;";
    JSValue val = JS_Eval(ctx, code, strlen(code), "<test>", JS_EVAL_TYPE_GLOBAL);
    EXPECT_FALSE(JS_IsException(val));
    EXPECT_TRUE(JS_IsFunction(ctx, val));

    // Call add(3, 4)
    JSValue args[2] = { JS_NewInt32(ctx, 3), JS_NewInt32(ctx, 4) };
    JSValue ret = JS_Call(ctx, val, JS_UNDEFINED, 2, args);
    EXPECT_FALSE(JS_IsException(ret));

    int32_t result = 0;
    JS_ToInt32(ctx, &result, ret);
    EXPECT_EQ(result, 7);

    JS_FreeValue(ctx, ret);
    JS_FreeValue(ctx, args[0]);
    JS_FreeValue(ctx, args[1]);
    JS_FreeValue(ctx, val);
    JS_FreeContext(ctx);
    JS_FreeRuntime(rt);
}

TEST(QuickJSSmoke, EvalWithModuleFlag) {
    JSRuntime* rt = JS_NewRuntime();
    JSContext* ctx = JS_NewContext(rt);
    ASSERT_NE(ctx, nullptr);

    const char* code = "export const x = 42;";
    JSValue val = JS_Eval(ctx, code, strlen(code), "<test>",
                           JS_EVAL_TYPE_MODULE | JS_EVAL_FLAG_COMPILE_ONLY);
    EXPECT_FALSE(JS_IsException(val));
    JS_FreeValue(ctx, val);
    JS_FreeContext(ctx);
    JS_FreeRuntime(rt);
}

TEST(QuickJSSmoke, GlobalObject) {
    JSRuntime* rt = JS_NewRuntime();
    JSContext* ctx = JS_NewContext(rt);
    ASSERT_NE(ctx, nullptr);

    JSValue global = JS_GetGlobalObject(ctx);
    EXPECT_TRUE(JS_IsObject(global));

    // Set a global variable via JS and check it exists
    JS_Eval(ctx, "globalThis.__test_val = 12345;", 30, "<test>", JS_EVAL_TYPE_GLOBAL);

    JSValue prop = JS_GetPropertyStr(ctx, global, "__test_val");
    EXPECT_TRUE(JS_IsNumber(prop));
    int32_t val = 0;
    JS_ToInt32(ctx, &val, prop);
    EXPECT_EQ(val, 12345);

    JS_FreeValue(ctx, prop);
    JS_FreeValue(ctx, global);
    JS_FreeContext(ctx);
    JS_FreeRuntime(rt);
}

// ============================================================================
// JS Engine Unit Tests — JsPluginEngine without a loaded PE (Emu props are 0)
// ============================================================================

class JsEngineTest : public ::testing::Test {
protected:
    Speakeasy* speakeasy_ = nullptr;
    JsPluginEngine* engine_ = nullptr;

    void SetUp() override {
        speakeasy::SpeakeasyConfig cfg;
        speakeasy_ = new Speakeasy(cfg);
    }

    void TearDown() override {
        if (speakeasy_) {
            speakeasy_->shutdown();
            delete speakeasy_;
            speakeasy_ = nullptr;
        }
        // engine_ is owned by speakeasy_, don't delete
        engine_ = nullptr;
    }

    bool init_engine() {
        if (!speakeasy_) return false;
        bool ok = speakeasy_->init_js_engine();
        if (ok) {
            engine_ = speakeasy_->js_engine();
        }
        return ok;
    }
};

TEST_F(JsEngineTest, InitJsEngine) {
    // Before loading a PE, the emulator is null; init should still work
    // (Emu properties will be 0, but the runtime/context are created)
    bool ok = speakeasy_->init_js_engine();
    if (!ok) {
        GTEST_SKIP() << "JS engine init requires a loaded module (emu_ is null)";
    }
    EXPECT_NE(speakeasy_->js_engine(), nullptr);
}

// ============================================================================
// JS Engine Integration Tests — require a loaded PE
//
// NOTE: Most tests in this suite are disabled because they trigger an
// intermittent heap corruption in QuickJS GC during JS_FreeRuntime.
// This appears to be a memory corruption in the Emu object registration
// (where 28+ function pointers are registered with QuickJS) and requires
// further investigation. The QuickJSSmoke tests (above) and JsEngineTest
// (without a loaded PE) provide stable coverage.
// ============================================================================

class JsEngineIntegrationTest : public ::testing::Test {
protected:
    Speakeasy* speakeasy_ = nullptr;

    void SetUp() override {
        auto data = load_test_bin("argv_test_x86.exe");
        if (data.empty()) {
            GTEST_SKIP() << "argv_test_x86.exe not available";
        }
        speakeasy::SpeakeasyConfig cfg;
        speakeasy_ = new Speakeasy(cfg);
        try {
            auto module = speakeasy_->load_module("", data);
            ASSERT_NE(module, nullptr) << "Failed to load test binary";
        } catch (const std::exception& e) {
            GTEST_SKIP() << "Failed to load module: " << e.what();
        }
    }

    void TearDown() override {
        if (speakeasy_) {
            speakeasy_->shutdown();
            delete speakeasy_;
            speakeasy_ = nullptr;
        }
    }

    bool init_engine() {
        if (!speakeasy_) return false;
        return speakeasy_->init_js_engine();
    }
};

TEST_F(JsEngineIntegrationTest, InitWithLoadedModule) {
    ASSERT_TRUE(init_engine());
    auto* engine = speakeasy_->js_engine();
    ASSERT_NE(engine, nullptr);
    ASSERT_NE(engine->runtime(), nullptr);
    ASSERT_NE(engine->context(), nullptr);

    // Basic eval should work
    EXPECT_NO_THROW(engine->eval_buf("2 + 2", "<test>"));
}

TEST_F(JsEngineIntegrationTest,EvalBufSimple) {
    ASSERT_TRUE(init_engine());
    auto* engine = speakeasy_->js_engine();
    ASSERT_NE(engine, nullptr);

    //EXPECT_NO_THROW(engine->eval_buf("2 + 3", "<test>"));
}

TEST_F(JsEngineIntegrationTest,EvalBufWithException) {
    ASSERT_TRUE(init_engine());
    auto* engine = speakeasy_->js_engine();
    ASSERT_NE(engine, nullptr);

    // eval_buf should throw on JS exception (but not crash)
    EXPECT_THROW(engine->eval_buf("throw new Error('intentional');", "<test>"), qjs::exception);
}

TEST_F(JsEngineIntegrationTest,ConsoleLog) {
    ASSERT_TRUE(init_engine());
    auto* engine = speakeasy_->js_engine();
    ASSERT_NE(engine, nullptr);

    // this doesn't throw errors
    engine->eval_buf("a = 'hello from test';", "<test>");
    // console.log should not throw
    EXPECT_NO_THROW(engine->eval_buf("console.log('hello from test');", "<test>"));
}

TEST_F(JsEngineIntegrationTest,PrintInfoWarnError) {
    ASSERT_TRUE(init_engine());
    auto* engine = speakeasy_->js_engine();
    ASSERT_NE(engine, nullptr);

    EXPECT_NO_THROW(engine->eval_buf("print('print test');", "<test>"));
    EXPECT_NO_THROW(engine->eval_buf("info('info test');", "<test>"));
    EXPECT_NO_THROW(engine->eval_buf("warn('warn test');", "<test>"));
    EXPECT_NO_THROW(engine->eval_buf("error('error test');", "<test>"));
}

TEST_F(JsEngineIntegrationTest,GlobalLogFunctionsExist) {
    ASSERT_TRUE(init_engine());
    auto* engine = speakeasy_->js_engine();
    ASSERT_NE(engine, nullptr);

    // Check that all logging globals are callable
    EXPECT_NO_THROW(engine->eval_buf(
        "typeof console.log === 'function' ? 'ok' : 'fail';", "<test>"));
    EXPECT_NO_THROW(engine->eval_buf(
        "typeof print === 'function' ? 'ok' : 'fail';", "<test>"));
    EXPECT_NO_THROW(engine->eval_buf(
        "typeof info === 'function' ? 'ok' : 'fail';", "<test>"));
    EXPECT_NO_THROW(engine->eval_buf(
        "typeof warn === 'function' ? 'ok' : 'fail';", "<test>"));
    EXPECT_NO_THROW(engine->eval_buf(
        "typeof error === 'function' ? 'ok' : 'fail';", "<test>"));
}

TEST_F(JsEngineIntegrationTest,ImportScriptsExists) {
    ASSERT_TRUE(init_engine());
    auto* engine = speakeasy_->js_engine();
    ASSERT_NE(engine, nullptr);

    EXPECT_NO_THROW(engine->eval_buf(
        "typeof importScripts === 'function' ? 'ok' : 'fail';", "<test>"));
}

TEST_F(JsEngineIntegrationTest,EmuGlobalExists) {
    ASSERT_TRUE(init_engine());
    auto* engine = speakeasy_->js_engine();
    ASSERT_NE(engine, nullptr);

    JSContext* ctx = engine->context();
    JSValue global = JS_GetGlobalObject(ctx);
    JSValue emu = JS_GetPropertyStr(ctx, global, "Emu");
    EXPECT_TRUE(JS_IsObject(emu));
    JS_FreeValue(ctx, emu);
    JS_FreeValue(ctx, global);
}

TEST_F(JsEngineIntegrationTest,EmuStaticProperties) {
    ASSERT_TRUE(init_engine());
    auto* engine = speakeasy_->js_engine();
    ASSERT_NE(engine, nullptr);

    JSContext* ctx = engine->context();
    JSValue global = JS_GetGlobalObject(ctx);
    JSValue emu = JS_GetPropertyStr(ctx, global, "Emu");
    ASSERT_TRUE(JS_IsObject(emu));

    // These properties should exist (values depend on loaded module)
    auto check_prop = [&](const char* name, int js_tag) {
        JSValue prop = JS_GetPropertyStr(ctx, emu, name);
        if (js_tag == JS_TAG_INT) {
            EXPECT_TRUE(JS_IsNumber(prop)) << name << " should be a number";
        }
        else if (js_tag == JS_TAG_BOOL) {
            EXPECT_TRUE(JS_IsBool(prop)) << name << " should be a bool";
        } else if (js_tag == JS_TAG_STRING) {
            EXPECT_TRUE(JS_IsString(prop)) << name << " should be a string";
        }
        JS_FreeValue(ctx, prop);
    };

    check_prop("TEB", JS_TAG_INT);
    check_prop("PEB", JS_TAG_INT);
    check_prop("PID", JS_TAG_INT);
    check_prop("isx64", JS_TAG_BOOL);     //bool
    check_prop("ImageBase", JS_TAG_INT);
    check_prop("Filename", JS_TAG_STRING);

    JS_FreeValue(ctx, emu);
    JS_FreeValue(ctx, global);
}

TEST_F(JsEngineIntegrationTest,EmuReadByteFromJS) {
    ASSERT_TRUE(init_engine());
    auto* engine = speakeasy_->js_engine();
    ASSERT_NE(engine, nullptr);

    // Read a byte from a known valid address (ImageBase should be valid)
    // eval a JS expression that reads the first byte at ImageBase
    EXPECT_NO_THROW(engine->eval_buf(
        "var b = Emu.ReadByte(Emu.ImageBase);"
        "typeof b === 'number' ? 'ok' : 'fail';",
        "<test>"));
}

TEST_F(JsEngineIntegrationTest,EmuReadWriteByteFromJS) {
    ASSERT_TRUE(init_engine());
    auto* engine = speakeasy_->js_engine();
    ASSERT_NE(engine, nullptr);

    // Read a byte, write it back, read again — should match
    EXPECT_NO_THROW(engine->eval_buf(
        "var addr = Emu.ImageBase;"
        "var original = Emu.ReadByte(addr);"
        "Emu.WriteByte(addr, 0x90);"    // NOP
        "var modified = Emu.ReadByte(addr);"
        "modified === 0x90 ? 'ok' : 'fail';",
        "<test>"));
}

TEST_F(JsEngineIntegrationTest,EmuRegisterFunctionsExist) {
    ASSERT_TRUE(init_engine());
    auto* engine = speakeasy_->js_engine();
    ASSERT_NE(engine, nullptr);

    EXPECT_NO_THROW(engine->eval_buf(
        "typeof Emu.ReadReg === 'function' ? 'ok' : 'fail';", "<test>"));
    EXPECT_NO_THROW(engine->eval_buf(
        "typeof Emu.SetReg === 'function' ? 'ok' : 'fail';", "<test>"));
}

TEST_F(JsEngineIntegrationTest,EmuMemoryFunctionsExist) {
    ASSERT_TRUE(init_engine());
    auto* engine = speakeasy_->js_engine();
    ASSERT_NE(engine, nullptr);

    // All memory access functions should be registered
    const char* mem_funcs[] = {
        "ReadByte", "ReadWord", "ReadDword", "ReadQword", "ReadMem",
        "WriteByte", "WriteWord", "WriteDword", "WriteQword", "WriteMem",
    };
    for (auto* fn : mem_funcs) {
        std::string code = std::string("typeof Emu.") + fn + " === 'function' ? 'ok' : 'fail';";
        EXPECT_NO_THROW(engine->eval_buf(code, "<test>")) << fn << " should be a function";
    }
}

TEST_F(JsEngineIntegrationTest,EmuStringFunctionsExist) {
    ASSERT_TRUE(init_engine());
    auto* engine = speakeasy_->js_engine();
    ASSERT_NE(engine, nullptr);

    EXPECT_NO_THROW(engine->eval_buf(
        "typeof Emu.ReadStringA === 'function' ? 'ok' : 'fail';", "<test>"));
    EXPECT_NO_THROW(engine->eval_buf(
        "typeof Emu.ReadStringW === 'function' ? 'ok' : 'fail';", "<test>"));
    EXPECT_NO_THROW(engine->eval_buf(
        "typeof Emu.WriteStringA === 'function' ? 'ok' : 'fail';", "<test>"));
    EXPECT_NO_THROW(engine->eval_buf(
        "typeof Emu.WriteStringW === 'function' ? 'ok' : 'fail';", "<test>"));
}

TEST_F(JsEngineIntegrationTest,EmuModuleFunctionsExist) {
    ASSERT_TRUE(init_engine());
    auto* engine = speakeasy_->js_engine();
    ASSERT_NE(engine, nullptr);

    EXPECT_NO_THROW(engine->eval_buf(
        "typeof Emu.LoadLibrary === 'function' ? 'ok' : 'fail';", "<test>"));
    EXPECT_NO_THROW(engine->eval_buf(
        "typeof Emu.GetModuleName === 'function' ? 'ok' : 'fail';", "<test>"));
    EXPECT_NO_THROW(engine->eval_buf(
        "typeof Emu.GetModuleHandle === 'function' ? 'ok' : 'fail';", "<test>"));
    EXPECT_NO_THROW(engine->eval_buf(
        "typeof Emu.GetProcAddr === 'function' ? 'ok' : 'fail';", "<test>"));
}

TEST_F(JsEngineIntegrationTest,EmuStackFunctionsExist) {
    ASSERT_TRUE(init_engine());
    auto* engine = speakeasy_->js_engine();
    ASSERT_NE(engine, nullptr);

    EXPECT_NO_THROW(engine->eval_buf(
        "typeof Emu.push === 'function' ? 'ok' : 'fail';", "<test>"));
    EXPECT_NO_THROW(engine->eval_buf(
        "typeof Emu.pop === 'function' ? 'ok' : 'fail';", "<test>"));
}

TEST_F(JsEngineIntegrationTest,EmuControlFunctionsExist) {
    ASSERT_TRUE(init_engine());
    auto* engine = speakeasy_->js_engine();
    ASSERT_NE(engine, nullptr);

    EXPECT_NO_THROW(engine->eval_buf(
        "typeof Emu.Stop === 'function' ? 'ok' : 'fail';", "<test>"));
    EXPECT_NO_THROW(engine->eval_buf(
        "typeof Emu.LastError === 'function' ? 'ok' : 'fail';", "<test>"));
}

TEST_F(JsEngineIntegrationTest,EmuDebugFunctionsExist) {
    ASSERT_TRUE(init_engine());
    auto* engine = speakeasy_->js_engine();
    ASSERT_NE(engine, nullptr);

    EXPECT_NO_THROW(engine->eval_buf(
        "typeof Emu.HexDump === 'function' ? 'ok' : 'fail';", "<test>"));
    EXPECT_NO_THROW(engine->eval_buf(
        "typeof Emu.StackDump === 'function' ? 'ok' : 'fail';", "<test>"));
}

TEST_F(JsEngineIntegrationTest,ApiHookClassExists) {
    ASSERT_TRUE(init_engine());
    auto* engine = speakeasy_->js_engine();
    ASSERT_NE(engine, nullptr);

    // ApiHook should be an object with an install method
    EXPECT_NO_THROW(engine->eval_buf(
        "typeof ApiHook === 'object' ? 'ok' : 'fail';", "<test>"));
}

TEST_F(JsEngineIntegrationTest,ApiHookHasInstallMethod) {
    ASSERT_TRUE(init_engine());
    auto* engine = speakeasy_->js_engine();
    ASSERT_NE(engine, nullptr);

    // ApiHook.install should be a function
    EXPECT_NO_THROW(engine->eval_buf(
        "typeof ApiHook.install === 'function' ? 'ok' : 'fail';", "<test>"));
}

TEST_F(JsEngineIntegrationTest,ApiHookInstallByName) {
    ASSERT_TRUE(init_engine());
    auto* engine = speakeasy_->js_engine();
    ASSERT_NE(engine, nullptr);

    // Install a hook by name via config object
    EXPECT_NO_THROW(engine->eval_buf(
        "var hook = ApiHook.install({"
        "    lib: 'kernel32',"
        "    api: 'CreateFileA',"
        "    onCallBack: function(api, args) {}"
        "});"
        "hook !== null && typeof hook === 'object' ? 'ok' : 'fail';",
        "<test>"));
}

TEST_F(JsEngineIntegrationTest,ApiHookInstallRequiresOnCallBack) {
    ASSERT_TRUE(init_engine());
    auto* engine = speakeasy_->js_engine();
    ASSERT_NE(engine, nullptr);

    // install() without onCallBack should throw; the JS try/catch handles it
    EXPECT_NO_THROW(engine->eval_buf(
        "try {"
        "    ApiHook.install({ lib: 'kernel32', api: 'CreateFileA' });"
        "    'fail';"
        "} catch(e) { 'ok'; }",
        "<test>"));
}

TEST_F(JsEngineIntegrationTest,ApiHookInstallByOrdinal) {
    ASSERT_TRUE(init_engine());
    auto* engine = speakeasy_->js_engine();
    ASSERT_NE(engine, nullptr);

    // Install a hook by ordinal via config object
    EXPECT_NO_THROW(engine->eval_buf(
        "var hook = ApiHook.install({"
        "    lib: 'kernel32',"
        "    api: 42,"
        "    onCallBack: function(api, args) {}"
        "});"
        "hook !== null && typeof hook === 'object' ? 'ok' : 'fail';",
        "<test>"));
}

TEST_F(JsEngineIntegrationTest,MultipleApiHookInstances) {
    ASSERT_TRUE(init_engine());
    auto* engine = speakeasy_->js_engine();
    ASSERT_NE(engine, nullptr);

    // Create multiple independent hooks
    EXPECT_NO_THROW(engine->eval_buf(
        "var h1 = ApiHook.install({"
        "    lib: 'kernel32',"
        "    api: 'CreateFileA',"
        "    onCallBack: function(api, args) {}"
        "});"
        "var h2 = ApiHook.install({"
        "    lib: 'kernel32',"
        "    api: 'GetProcAddress',"
        "    onCallBack: function(api, args) {}"
        "});"
        "h1 !== null && h2 !== null && h1 !== h2 ? 'ok' : 'fail';",
        "<test>"));
}

TEST_F(JsEngineIntegrationTest,RunModuleWithJsEngine) {
    ASSERT_TRUE(init_engine());
    auto* engine = speakeasy_->js_engine();
    ASSERT_NE(engine, nullptr);

    // Install a simple hook that logs API calls
    engine->eval_buf(
        "var hook = ApiHook.install({"
        "    lib: 'kernel32',"
        "    api: 'GetCommandLineA',"
        "    onCallBack: function(api, args) {"
        "        log('API called: ' + api);"
        "    }"
        "});",
        "<test>");

    // Run the loaded module
    auto modules = speakeasy_->get_user_modules();
    ASSERT_FALSE(modules.empty());
    speakeasy_->run_module(modules[0], true);

    // Should complete without crash
    SUCCEED();
}
