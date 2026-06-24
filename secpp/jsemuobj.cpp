// jsemuobj.cpp - Emulator object functions exposed to JavaScript
#include "jsemuobj.h"
#include "jsengine.h"
#include "speakeasy.h"

#include <cstring>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <plog/Log.h>

namespace speakeasy {

// Helper: retrieve Speakeasy from JSContext via runtime opaque
static Speakeasy& get_sp(JSContext* ctx) {
    JSRuntime* rt = JS_GetRuntime(ctx);
    auto* engine = static_cast<JsPluginEngine*>(JS_GetRuntimeOpaque(rt));
    return engine->speakeasy();
}

// Helper: read little-endian value from bytes
static uint16_t le16(const std::vector<uint8_t>& data, size_t off = 0) {
    if (off + 2 > data.size()) return 0;
    return static_cast<uint16_t>(data[off]) | (static_cast<uint16_t>(data[off + 1]) << 8);
}
static uint32_t le32(const std::vector<uint8_t>& data, size_t off = 0) {
    if (off + 4 > data.size()) return 0;
    return static_cast<uint32_t>(data[off]) | (static_cast<uint32_t>(data[off + 1]) << 8) |
           (static_cast<uint32_t>(data[off + 2]) << 16) | (static_cast<uint32_t>(data[off + 3]) << 24);
}
static uint64_t le64(const std::vector<uint8_t>& data, size_t off = 0) {
    if (off + 8 > data.size()) return 0;
    return static_cast<uint64_t>(data[off]) | (static_cast<uint64_t>(data[off + 1]) << 8) |
           (static_cast<uint64_t>(data[off + 2]) << 16) | (static_cast<uint64_t>(data[off + 3]) << 24) |
           (static_cast<uint64_t>(data[off + 4]) << 32) | (static_cast<uint64_t>(data[off + 5]) << 40) |
           (static_cast<uint64_t>(data[off + 6]) << 48) | (static_cast<uint64_t>(data[off + 7]) << 56);
}

// ============================================================================
// Registers
// ============================================================================

JSValue JsEmuObject::read_reg(JSContext* ctx, JSValueConst this_val,
                               int argc, JSValueConst* argv) {
    (void)this_val;
    if (argc < 1) {
        return JS_ThrowInternalError(ctx,
            "ReadReg: takes 1 arg - Ex: Emu.ReadReg(REG_EAX)");
    }
    if (!JS_IsNumber(argv[0])) {
        return JS_ThrowInternalError(ctx,
            "ReadReg: argument must be a number (Unicorn register constant)");
    }

    uint32_t reg_id = 0;
    if (JS_ToUint32(ctx, &reg_id, argv[0]) < 0) {
        return JS_EXCEPTION;
    }

    auto& sp = get_sp(ctx);
    uint64_t value = sp.reg_read(static_cast<int>(reg_id));
    return JS_NewInt64(ctx, static_cast<int64_t>(value));
}

JSValue JsEmuObject::set_reg(JSContext* ctx, JSValueConst this_val,
                              int argc, JSValueConst* argv) {
    (void)this_val;
    if (argc < 2) {
        return JS_ThrowInternalError(ctx,
            "SetReg: takes 2 args - Ex: Emu.SetReg(REG_EAX, 0x401000)");
    }
    if (!JS_IsNumber(argv[0]) || !JS_IsNumber(argv[1])) {
        return JS_ThrowInternalError(ctx,
            "SetReg: both arguments must be numbers");
    }

    uint32_t reg_id = 0;
    int64_t value = 0;
    if (JS_ToUint32(ctx, &reg_id, argv[0]) < 0) return JS_EXCEPTION;
    if (JS_ToInt64(ctx, &value, argv[1]) < 0) return JS_EXCEPTION;

    auto& sp = get_sp(ctx);
    sp.reg_write(static_cast<int>(reg_id), static_cast<uint64_t>(value));
    return JS_NewBool(ctx, true);
}

// ============================================================================
// Strings
// ============================================================================

JSValue JsEmuObject::read_string_a(JSContext* ctx, JSValueConst this_val,
                                    int argc, JSValueConst* argv) {
    (void)this_val;
    if (argc < 1) {
        return JS_ThrowInternalError(ctx,
            "ReadStringA: takes 1 or 2 args - Ex: Emu.ReadStringA(addr [, len])");
    }
    if (!JS_IsNumber(argv[0])) {
        return JS_ThrowInternalError(ctx,
            "ReadStringA: first argument must be an address (number)");
    }

    int64_t addr = 0;
    if (JS_ToInt64(ctx, &addr, argv[0]) < 0) return JS_EXCEPTION;

    size_t max_chars = 0;  // 0 = read until null
    if (argc >= 2) {
        uint32_t len = 0;
        if (JS_IsNumber(argv[1])) {
            if (JS_ToUint32(ctx, &len, argv[1]) < 0) return JS_EXCEPTION;
            max_chars = static_cast<size_t>(len);
        }
    }

    auto& sp = get_sp(ctx);
    std::string result = sp.read_mem_string(static_cast<uint64_t>(addr), 1, max_chars);
    return JS_NewString(ctx, result.c_str());
}

JSValue JsEmuObject::read_string_w(JSContext* ctx, JSValueConst this_val,
                                    int argc, JSValueConst* argv) {
    (void)this_val;
    if (argc < 1) {
        return JS_ThrowInternalError(ctx,
            "ReadStringW: takes 1 or 2 args - Ex: Emu.ReadStringW(addr [, len])");
    }
    if (!JS_IsNumber(argv[0])) {
        return JS_ThrowInternalError(ctx,
            "ReadStringW: first argument must be an address (number)");
    }

    int64_t addr = 0;
    if (JS_ToInt64(ctx, &addr, argv[0]) < 0) return JS_EXCEPTION;

    size_t max_chars = 0;
    if (argc >= 2) {
        uint32_t len = 0;
        if (JS_IsNumber(argv[1])) {
            if (JS_ToUint32(ctx, &len, argv[1]) < 0) return JS_EXCEPTION;
            max_chars = static_cast<size_t>(len);
        }
    }

    auto& sp = get_sp(ctx);
    std::string result = sp.read_mem_string(static_cast<uint64_t>(addr), 2, max_chars);
    return JS_NewString(ctx, result.c_str());
}

JSValue JsEmuObject::write_string_a(JSContext* ctx, JSValueConst this_val,
                                     int argc, JSValueConst* argv) {
    (void)this_val;
    if (argc < 2) {
        return JS_ThrowInternalError(ctx,
            "WriteStringA: takes 2 args - Ex: Emu.WriteStringA(addr, \"string\")");
    }
    if (!JS_IsNumber(argv[0])) {
        return JS_ThrowInternalError(ctx,
            "WriteStringA: first argument must be an address (number)");
    }

    int64_t addr = 0;
    if (JS_ToInt64(ctx, &addr, argv[0]) < 0) return JS_EXCEPTION;

    const char* str = JS_ToCString(ctx, argv[1]);
    if (!str) return JS_EXCEPTION;

    size_t len = strlen(str);
    std::vector<uint8_t> data(len + 1);
    memcpy(data.data(), str, len);
    data[len] = '\0';  // null terminate

    auto& sp = get_sp(ctx);
    sp.mem_write(static_cast<uint64_t>(addr), data);

    JS_FreeCString(ctx, str);
    return JS_NewInt32(ctx, static_cast<int32_t>(len + 1));
}

JSValue JsEmuObject::write_string_w(JSContext* ctx, JSValueConst this_val,
                                     int argc, JSValueConst* argv) {
    (void)this_val;
    if (argc < 2) {
        return JS_ThrowInternalError(ctx,
            "WriteStringW: takes 2 args - Ex: Emu.WriteStringW(addr, \"string\")");
    }
    if (!JS_IsNumber(argv[0])) {
        return JS_ThrowInternalError(ctx,
            "WriteStringW: first argument must be an address (number)");
    }

    int64_t addr = 0;
    if (JS_ToInt64(ctx, &addr, argv[0]) < 0) return JS_EXCEPTION;

    const char* str = JS_ToCString(ctx, argv[1]);
    if (!str) return JS_EXCEPTION;

    // Encode as UTF-16LE
    size_t len = strlen(str);
    std::vector<uint8_t> data((len + 1) * 2);
    for (size_t i = 0; i < len; i++) {
        data[i * 2] = static_cast<uint8_t>(str[i]);
        data[i * 2 + 1] = 0;
    }
    data[len * 2] = 0;
    data[len * 2 + 1] = 0;  // null terminator

    auto& sp = get_sp(ctx);
    sp.mem_write(static_cast<uint64_t>(addr), data);

    JS_FreeCString(ctx, str);
    return JS_NewInt32(ctx, static_cast<int32_t>((len + 1) * 2));
}

// ============================================================================
// Modules
// ============================================================================

JSValue JsEmuObject::load_library(JSContext* ctx, JSValueConst this_val,
                                   int argc, JSValueConst* argv) {
    (void)this_val;
    if (argc < 1) {
        return JS_NewInt64(ctx, 0);
    }
    if (!JS_IsString(argv[0])) {
        return JS_ThrowInternalError(ctx,
            "LoadLibrary: argument must be a string - Ex: Emu.LoadLibrary('kernel32.dll')");
    }

    const char* libname = JS_ToCString(ctx, argv[0]);
    if (!libname) return JS_EXCEPTION;

    // Normalize: extract basename, lowercase, strip extension, add .dll
    std::string name(libname);
    JS_FreeCString(ctx, libname);

    // Simple filename extraction (matches Pascal's ExtractFileName logic)
    auto slash = name.find_last_of("/\\");
    std::string fname = (slash != std::string::npos) ? name.substr(slash + 1) : name;
    auto dot = fname.rfind('.');
    std::string base = (dot != std::string::npos) ? fname.substr(0, dot) : fname;

    // Lowercase
    std::transform(base.begin(), base.end(), base.begin(), ::tolower);
    std::string redirect = base + ".dll";

    auto& sp = get_sp(ctx);
    uint64_t result = sp.load_library(redirect);
    return JS_NewInt64(ctx, static_cast<int64_t>(result));
}

JSValue JsEmuObject::get_module_name(JSContext* ctx, JSValueConst this_val,
                                      int argc, JSValueConst* argv) {
    (void)this_val;
    auto& sp = get_sp(ctx);

    if (argc < 1) {
        // Return current image name
        auto mods = sp.get_user_modules();
        if (!mods.empty() && mods[0]) {
            return JS_NewString(ctx, mods[0]->name.c_str());
        }
        return JS_NewString(ctx, "");
    }

    if (!JS_IsNumber(argv[0])) {
        return JS_ThrowInternalError(ctx,
            "GetModuleName: argument must be a handle (number)");
    }

    int64_t handle = 0;
    if (JS_ToInt64(ctx, &handle, argv[0]) < 0) return JS_EXCEPTION;

    // Check if handle matches the current image base
    auto mods = sp.get_user_modules();
    if (!mods.empty() && mods[0] && mods[0]->base == static_cast<uint64_t>(handle)) {
        return JS_NewString(ctx, mods[0]->name.c_str());
    }

    std::string name = sp.get_module_name_from_handle(static_cast<uint64_t>(handle));
    return JS_NewString(ctx, name.c_str());
}

JSValue JsEmuObject::get_module_handle(JSContext* ctx, JSValueConst this_val,
                                        int argc, JSValueConst* argv) {
    (void)this_val;
    auto& sp = get_sp(ctx);

    if (argc < 1) {
        // Return current image base
        auto mods = sp.get_user_modules();
        if (!mods.empty() && mods[0]) {
            return JS_NewInt64(ctx, static_cast<int64_t>(mods[0]->base));
        }
        return JS_NewInt64(ctx, 0);
    }

    if (!JS_IsString(argv[0])) {
        return JS_ThrowInternalError(ctx,
            "GetModuleHandle: argument must be a string");
    }

    const char* name = JS_ToCString(ctx, argv[0]);
    if (!name) return JS_EXCEPTION;

    uint64_t handle = sp.get_module_handle_by_name(name);
    JS_FreeCString(ctx, name);

    return JS_NewInt64(ctx, static_cast<int64_t>(handle));
}

JSValue JsEmuObject::get_proc_address(JSContext* ctx, JSValueConst this_val,
                                       int argc, JSValueConst* argv) {
    (void)this_val;
    if (argc < 2) {
        return JS_ThrowInternalError(ctx,
            "GetProcAddr: takes 2 args - Ex: Emu.GetProcAddr(handle, 'FunctionName')");
    }

    if (!JS_IsNumber(argv[0])) {
        return JS_ThrowInternalError(ctx,
            "GetProcAddr: first argument must be a handle (number)");
    }

    int64_t handle = 0;
    if (JS_ToInt64(ctx, &handle, argv[0]) < 0) return JS_EXCEPTION;

    const char* fn_name = JS_ToCString(ctx, argv[1]);
    if (!fn_name) return JS_EXCEPTION;

    auto& sp = get_sp(ctx);
    uint64_t result = sp.get_proc_address(static_cast<uint64_t>(handle), fn_name);
    JS_FreeCString(ctx, fn_name);

    return JS_NewInt64(ctx, static_cast<int64_t>(result));
}

// ============================================================================
// Memory Write
// ============================================================================

JSValue JsEmuObject::write_byte(JSContext* ctx, JSValueConst this_val,
                                 int argc, JSValueConst* argv) {
    (void)this_val;
    if (argc < 2) {
        return JS_ThrowInternalError(ctx,
            "WriteByte: takes 2 args - Ex: Emu.WriteByte(addr, value)");
    }
    int64_t addr = 0;
    uint32_t val = 0;
    if (JS_ToInt64(ctx, &addr, argv[0]) < 0) return JS_EXCEPTION;
    if (JS_ToUint32(ctx, &val, argv[1]) < 0) return JS_EXCEPTION;

    auto& sp = get_sp(ctx);
    std::vector<uint8_t> buf = { static_cast<uint8_t>(val) };
    sp.mem_write(static_cast<uint64_t>(addr), buf);
    return JS_NewBool(ctx, true);
}

JSValue JsEmuObject::write_word(JSContext* ctx, JSValueConst this_val,
                                 int argc, JSValueConst* argv) {
    (void)this_val;
    if (argc < 2) {
        return JS_ThrowInternalError(ctx,
            "WriteWord: takes 2 args - Ex: Emu.WriteWord(addr, value)");
    }
    int64_t addr = 0;
    int32_t val = 0;
    if (JS_ToInt64(ctx, &addr, argv[0]) < 0) return JS_EXCEPTION;
    if (JS_ToInt32(ctx, &val, argv[1]) < 0) return JS_EXCEPTION;

    auto& sp = get_sp(ctx);
    uint16_t v16 = static_cast<uint16_t>(val);
    std::vector<uint8_t> buf = { static_cast<uint8_t>(v16 & 0xFF),
                                  static_cast<uint8_t>((v16 >> 8) & 0xFF) };
    sp.mem_write(static_cast<uint64_t>(addr), buf);
    return JS_NewBool(ctx, true);
}

JSValue JsEmuObject::write_dword(JSContext* ctx, JSValueConst this_val,
                                  int argc, JSValueConst* argv) {
    (void)this_val;
    if (argc < 2) {
        return JS_ThrowInternalError(ctx,
            "WriteDword: takes 2 args - Ex: Emu.WriteDword(addr, value)");
    }
    int64_t addr = 0;
    int32_t val = 0;
    if (JS_ToInt64(ctx, &addr, argv[0]) < 0) return JS_EXCEPTION;
    if (JS_ToInt32(ctx, &val, argv[1]) < 0) return JS_EXCEPTION;

    auto& sp = get_sp(ctx);
    uint32_t v32 = static_cast<uint32_t>(val);
    std::vector<uint8_t> buf = { static_cast<uint8_t>(v32 & 0xFF),
                                  static_cast<uint8_t>((v32 >> 8) & 0xFF),
                                  static_cast<uint8_t>((v32 >> 16) & 0xFF),
                                  static_cast<uint8_t>((v32 >> 24) & 0xFF) };
    sp.mem_write(static_cast<uint64_t>(addr), buf);
    return JS_NewBool(ctx, true);
}

JSValue JsEmuObject::write_qword(JSContext* ctx, JSValueConst this_val,
                                  int argc, JSValueConst* argv) {
    (void)this_val;
    if (argc < 2) {
        return JS_ThrowInternalError(ctx,
            "WriteQword: takes 2 args - Ex: Emu.WriteQword(addr, value)");
    }
    int64_t addr = 0, val = 0;
    if (JS_ToInt64(ctx, &addr, argv[0]) < 0) return JS_EXCEPTION;
    if (JS_ToInt64(ctx, &val, argv[1]) < 0) return JS_EXCEPTION;

    auto& sp = get_sp(ctx);
    uint64_t v64 = static_cast<uint64_t>(val);
    std::vector<uint8_t> buf = { static_cast<uint8_t>(v64 & 0xFF),
                                  static_cast<uint8_t>((v64 >> 8) & 0xFF),
                                  static_cast<uint8_t>((v64 >> 16) & 0xFF),
                                  static_cast<uint8_t>((v64 >> 24) & 0xFF),
                                  static_cast<uint8_t>((v64 >> 32) & 0xFF),
                                  static_cast<uint8_t>((v64 >> 40) & 0xFF),
                                  static_cast<uint8_t>((v64 >> 48) & 0xFF),
                                  static_cast<uint8_t>((v64 >> 56) & 0xFF) };
    sp.mem_write(static_cast<uint64_t>(addr), buf);
    return JS_NewBool(ctx, true);
}

JSValue JsEmuObject::write_mem(JSContext* ctx, JSValueConst this_val,
                                int argc, JSValueConst* argv) {
    (void)this_val;
    if (argc < 2) {
        return JS_ThrowInternalError(ctx,
            "WriteMem: takes 2 args - Ex: Emu.WriteMem(addr, [0xC0, 0xDE])");
    }
    if (!JS_IsNumber(argv[0])) {
        return JS_ThrowInternalError(ctx,
            "WriteMem: first argument must be an address (number)");
    }

    int64_t addr = 0;
    if (JS_ToInt64(ctx, &addr, argv[0]) < 0) return JS_EXCEPTION;

    if (!JS_IsObject(argv[1])) {
        return JS_ThrowInternalError(ctx,
            "WriteMem: second argument must be an array of bytes");
    }

    // Check if it's an array
    if (!JS_IsArray(argv[1])) {
        return JS_ThrowInternalError(ctx,
            "WriteMem: second argument must be an Array");
    }

    // Get array length
    JSValue len_val = JS_GetPropertyStr(ctx, argv[1], "length");
    int32_t len = 0;
    if (JS_ToInt32(ctx, &len, len_val) < 0) {
        JS_FreeValue(ctx, len_val);
        return JS_EXCEPTION;
    }
    JS_FreeValue(ctx, len_val);

    auto& sp = get_sp(ctx);
    int32_t written = 0;
    for (int32_t i = 0; i < len; i++) {
        JSValue elem = JS_GetPropertyUint32(ctx, argv[1], static_cast<uint32_t>(i));
        if (JS_IsNumber(elem)) {
            uint32_t val = 0;
            if (JS_ToUint32(ctx, &val, elem) >= 0) {
                std::vector<uint8_t> buf = { static_cast<uint8_t>(val) };
                sp.mem_write(static_cast<uint64_t>(addr) + i, buf);
                written++;
            }
        }
        JS_FreeValue(ctx, elem);
    }

    return JS_NewInt32(ctx, written);
}

// ============================================================================
// Memory Read
// ============================================================================

JSValue JsEmuObject::read_byte(JSContext* ctx, JSValueConst this_val,
                                int argc, JSValueConst* argv) {
    (void)this_val;
    if (argc < 1) {
        return JS_ThrowInternalError(ctx,
            "ReadByte: takes 1 arg - Ex: Emu.ReadByte(addr)");
    }
    int64_t addr = 0;
    if (JS_ToInt64(ctx, &addr, argv[0]) < 0) return JS_EXCEPTION;

    auto& sp = get_sp(ctx);
    auto buf = sp.mem_read(static_cast<uint64_t>(addr), 1);
    if (buf.empty()) return JS_NewInt32(ctx, 0);
    return JS_NewInt32(ctx, buf[0]);
}

JSValue JsEmuObject::read_word(JSContext* ctx, JSValueConst this_val,
                                int argc, JSValueConst* argv) {
    (void)this_val;
    if (argc < 1) {
        return JS_ThrowInternalError(ctx,
            "ReadWord: takes 1 arg - Ex: Emu.ReadWord(addr)");
    }
    int64_t addr = 0;
    if (JS_ToInt64(ctx, &addr, argv[0]) < 0) return JS_EXCEPTION;

    auto& sp = get_sp(ctx);
    auto buf = sp.mem_read(static_cast<uint64_t>(addr), 2);
    return JS_NewInt32(ctx, static_cast<int32_t>(le16(buf)));
}

JSValue JsEmuObject::read_dword(JSContext* ctx, JSValueConst this_val,
                                 int argc, JSValueConst* argv) {
    (void)this_val;
    if (argc < 1) {
        return JS_ThrowInternalError(ctx,
            "ReadDword: takes 1 arg - Ex: Emu.ReadDword(addr)");
    }
    int64_t addr = 0;
    if (JS_ToInt64(ctx, &addr, argv[0]) < 0) return JS_EXCEPTION;

    auto& sp = get_sp(ctx);
    auto buf = sp.mem_read(static_cast<uint64_t>(addr), 4);
    return JS_NewInt32(ctx, static_cast<int32_t>(le32(buf)));
}

JSValue JsEmuObject::read_qword(JSContext* ctx, JSValueConst this_val,
                                 int argc, JSValueConst* argv) {
    (void)this_val;
    if (argc < 1) {
        return JS_ThrowInternalError(ctx,
            "ReadQword: takes 1 arg - Ex: Emu.ReadQword(addr)");
    }
    int64_t addr = 0;
    if (JS_ToInt64(ctx, &addr, argv[0]) < 0) return JS_EXCEPTION;

    auto& sp = get_sp(ctx);
    auto buf = sp.mem_read(static_cast<uint64_t>(addr), 8);
    return JS_NewInt64(ctx, static_cast<int64_t>(le64(buf)));
}

JSValue JsEmuObject::read_mem(JSContext* ctx, JSValueConst this_val,
                               int argc, JSValueConst* argv) {
    (void)this_val;
    if (argc < 2) {
        return JS_ThrowInternalError(ctx,
            "ReadMem: takes 2 args - Ex: Emu.ReadMem(addr, length)");
    }
    int64_t addr = 0;
    uint32_t length = 0;
    if (JS_ToInt64(ctx, &addr, argv[0]) < 0) return JS_EXCEPTION;
    if (JS_ToUint32(ctx, &length, argv[1]) < 0) return JS_EXCEPTION;

    auto& sp = get_sp(ctx);
    auto buf = sp.mem_read(static_cast<uint64_t>(addr), static_cast<size_t>(length));

    // Return as ArrayBuffer
    return JS_NewArrayBufferCopy(ctx, buf.data(), buf.size());
}

// ============================================================================
// Stack
// ============================================================================

JSValue JsEmuObject::push(JSContext* ctx, JSValueConst this_val,
                           int argc, JSValueConst* argv) {
    (void)this_val;
    if (argc < 1) {
        return JS_ThrowInternalError(ctx,
            "push: takes 1 arg - Ex: Emu.push(value)");
    }
    if (!JS_IsNumber(argv[0])) {
        return JS_ThrowInternalError(ctx,
            "push: argument must be a number");
    }

    int64_t val = 0;
    if (JS_ToInt64(ctx, &val, argv[0]) < 0) return JS_EXCEPTION;

    auto& sp = get_sp(ctx);
    sp.push_stack(static_cast<uint64_t>(val));
    return JS_NewBool(ctx, true);
}

JSValue JsEmuObject::pop(JSContext* ctx, JSValueConst this_val,
                          int argc, JSValueConst* argv) {
    (void)this_val;
    (void)argc;
    (void)argv;
    auto& sp = get_sp(ctx);
    uint64_t val = sp.pop_stack();
    return JS_NewInt64(ctx, static_cast<int64_t>(val));
}

// ============================================================================
// Control
// ============================================================================

JSValue JsEmuObject::stop(JSContext* ctx, JSValueConst this_val,
                           int argc, JSValueConst* argv) {
    (void)this_val;
    (void)argc;
    (void)argv;
    auto& sp = get_sp(ctx);
    sp.stop();
    return JS_TRUE;
}

JSValue JsEmuObject::last_error(JSContext* ctx, JSValueConst this_val,
                                 int argc, JSValueConst* argv) {
    (void)this_val;
    (void)argc;
    (void)argv;
    // Return a generic message (the Pascal code uses uc_strerror)
    return JS_NewString(ctx, "no error"); // TODO: track last Unicorn error
}

// ============================================================================
// Debug
// ============================================================================

JSValue JsEmuObject::hex_dump(JSContext* ctx, JSValueConst this_val,
                               int argc, JSValueConst* argv) {
    (void)this_val;
    if (argc < 2) {
        return JS_ThrowInternalError(ctx,
            "HexDump: takes at least 2 args - Ex: Emu.HexDump(addr, len [, cols])");
    }

    int64_t addr = 0;
    uint32_t len = 0;
    uint32_t cols = 16;  // default

    if (JS_ToInt64(ctx, &addr, argv[0]) < 0) return JS_EXCEPTION;
    if (JS_ToUint32(ctx, &len, argv[1]) < 0) return JS_EXCEPTION;
    if (argc >= 3 && JS_IsNumber(argv[2])) {
        if (JS_ToUint32(ctx, &cols, argv[2]) < 0) return JS_EXCEPTION;
    }

    if (len == 0) {
        return JS_ThrowInternalError(ctx, "HexDump: length must be > 0");
    }

    auto& sp = get_sp(ctx);
    auto buf = sp.mem_read(static_cast<uint64_t>(addr), static_cast<size_t>(len));

    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (size_t i = 0; i < buf.size(); i++) {
        if (i % cols == 0) {
            if (i > 0) oss << '\n';
            oss << std::setw(8) << (static_cast<uint64_t>(addr) + i) << "  ";
        }
        oss << std::setw(2) << static_cast<int>(buf[i]) << ' ';
    }
    oss << std::dec;

    PLOG_INFO << "[JS] HexDump:\n" << oss.str();
    return JS_UNDEFINED;
}

JSValue JsEmuObject::stack_dump(JSContext* ctx, JSValueConst this_val,
                                 int argc, JSValueConst* argv) {
    (void)this_val;
    if (argc < 2) {
        return JS_ThrowInternalError(ctx,
            "StackDump: takes 2 args - Ex: Emu.StackDump(addr, len)");
    }

    int64_t addr = 0;
    uint32_t len = 0;
    if (JS_ToInt64(ctx, &addr, argv[0]) < 0) return JS_EXCEPTION;
    if (JS_ToUint32(ctx, &len, argv[1]) < 0) return JS_EXCEPTION;

    if (len == 0) {
        return JS_UNDEFINED;
    }

    auto& sp = get_sp(ctx);
    int ptr_size = sp.get_ptr_size();
    auto buf = sp.mem_read(static_cast<uint64_t>(addr), static_cast<size_t>(len));

    std::ostringstream oss;
    oss << std::hex << std::setfill('0') << "Stack Dump:\n";
    for (size_t i = 0; i + static_cast<size_t>(ptr_size) <= buf.size(); i += ptr_size) {
        uint64_t val = (ptr_size == 8) ? le64(buf, i) : le32(buf, i);
        oss << "  " << std::setw(ptr_size * 2) << (static_cast<uint64_t>(addr) + i)
            << ": " << std::setw(ptr_size * 2) << val << '\n';
    }
    oss << std::dec;

    PLOG_INFO << "[JS] " << oss.str();
    return JS_UNDEFINED;
}

} // namespace speakeasy
