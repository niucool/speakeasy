// jsemuobj.h - Emulator object functions exposed to JavaScript
#ifndef SPEAKEASY_JSEMUOBJ_H
#define SPEAKEASY_JSEMUOBJ_H

#include <quickjs.h>

namespace speakeasy {

/**
 * Static JS-callable functions that form the "Emu.*" API.
 * Each function matches the JSCFunction callback signature:
 *   JSValue func(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv)
 *
 * These mirror the Pascal JSEmuObj functions from jsemuobj.pas,
 * adapted to call through the Speakeasy facade via the runtime opaque pointer.
 */
struct JsEmuObject {
    // === Registers ===
    static JSValue read_reg(JSContext* ctx, JSValueConst this_val,
                            int argc, JSValueConst* argv);
    static JSValue set_reg(JSContext* ctx, JSValueConst this_val,
                           int argc, JSValueConst* argv);

    // === Strings ===
    static JSValue read_string_a(JSContext* ctx, JSValueConst this_val,
                                 int argc, JSValueConst* argv);
    static JSValue read_string_w(JSContext* ctx, JSValueConst this_val,
                                 int argc, JSValueConst* argv);
    static JSValue write_string_a(JSContext* ctx, JSValueConst this_val,
                                  int argc, JSValueConst* argv);
    static JSValue write_string_w(JSContext* ctx, JSValueConst this_val,
                                  int argc, JSValueConst* argv);

    // === Modules ===
    static JSValue load_library(JSContext* ctx, JSValueConst this_val,
                                int argc, JSValueConst* argv);
    static JSValue get_module_name(JSContext* ctx, JSValueConst this_val,
                                   int argc, JSValueConst* argv);
    static JSValue get_module_handle(JSContext* ctx, JSValueConst this_val,
                                     int argc, JSValueConst* argv);
    static JSValue get_proc_address(JSContext* ctx, JSValueConst this_val,
                                    int argc, JSValueConst* argv);

    // === Memory Write ===
    static JSValue write_byte(JSContext* ctx, JSValueConst this_val,
                              int argc, JSValueConst* argv);
    static JSValue write_word(JSContext* ctx, JSValueConst this_val,
                              int argc, JSValueConst* argv);
    static JSValue write_dword(JSContext* ctx, JSValueConst this_val,
                               int argc, JSValueConst* argv);
    static JSValue write_qword(JSContext* ctx, JSValueConst this_val,
                               int argc, JSValueConst* argv);
    static JSValue write_mem(JSContext* ctx, JSValueConst this_val,
                             int argc, JSValueConst* argv);

    // === Memory Read ===
    static JSValue read_byte(JSContext* ctx, JSValueConst this_val,
                             int argc, JSValueConst* argv);
    static JSValue read_word(JSContext* ctx, JSValueConst this_val,
                             int argc, JSValueConst* argv);
    static JSValue read_dword(JSContext* ctx, JSValueConst this_val,
                              int argc, JSValueConst* argv);
    static JSValue read_qword(JSContext* ctx, JSValueConst this_val,
                              int argc, JSValueConst* argv);
    static JSValue read_mem(JSContext* ctx, JSValueConst this_val,
                            int argc, JSValueConst* argv);

    // === Stack ===
    static JSValue push(JSContext* ctx, JSValueConst this_val,
                        int argc, JSValueConst* argv);
    static JSValue pop(JSContext* ctx, JSValueConst this_val,
                       int argc, JSValueConst* argv);

    // === Control ===
    static JSValue stop(JSContext* ctx, JSValueConst this_val,
                        int argc, JSValueConst* argv);
    static JSValue last_error(JSContext* ctx, JSValueConst this_val,
                              int argc, JSValueConst* argv);

    // === Debug ===
    static JSValue hex_dump(JSContext* ctx, JSValueConst this_val,
                            int argc, JSValueConst* argv);
    static JSValue stack_dump(JSContext* ctx, JSValueConst this_val,
                              int argc, JSValueConst* argv);
};

} // namespace speakeasy

#endif // SPEAKEASY_JSEMUOBJ_H
