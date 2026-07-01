// jsemuobj.h - Emulator object functions exposed to JavaScript (quickjspp modernized)
#ifndef SPEAKEASY_JSEMUOBJ_H
#define SPEAKEASY_JSEMUOBJ_H

#include <string>
#include <vector>
#include <cstdint>
#include <quickjspp.hpp>

class Speakeasy;

namespace speakeasy {

    /**
     * High-level C++ class representing the "Emu" object API.
     * Methods accept native types directly, and quickjspp marshals
     * inputs, arguments, exceptions, and return types seamlessly.
     */
    class JsEmuObject {
    public:
        // Pass a reference to Speakeasy upon instantiation or track it via an internal reference
        explicit JsEmuObject(Speakeasy& speakeasy);
        ~JsEmuObject() = default;

        // === Registers ===
        uint64_t read_reg(uint32_t reg_id);
        bool set_reg(uint32_t reg_id, int64_t value);

        // === Strings ===
        std::string read_string_a(int64_t addr, qjs::Value max_chars_val);
        std::string read_string_w(int64_t addr, qjs::Value max_chars_val);
        int32_t write_string_a(int64_t addr, const std::string& str);
        int32_t write_string_w(int64_t addr, const std::string& str);

        // === Modules ===
        int64_t load_library(const std::string& libname);
        std::string get_module_name(qjs::Value handle_val);
        int64_t get_module_handle(qjs::Value name_val);
        int64_t get_proc_address(int64_t handle, const std::string& fn_name);

        // === Memory Write ===
        bool write_byte(int64_t addr, uint32_t val);
        bool write_word(int64_t addr, int32_t val);
        bool write_dword(int64_t addr, int32_t val);
        bool write_qword(int64_t addr, int64_t val);
        int32_t write_mem(int64_t addr, const std::vector<uint8_t>& bytes);

        // === Memory Read ===
        int32_t read_byte(int64_t addr);
        int32_t read_word(int64_t addr);
        int32_t read_dword(int64_t addr);
        int64_t read_qword(int64_t addr);
        qjs::Value read_mem(qjs::Context& ctx, int64_t addr, uint32_t length);

        // === Stack ===
        bool push(int64_t val);
        int64_t pop();

        // === Control ===
        void stop();
        std::string last_error();

        // === Debug ===
        void hex_dump(int64_t addr, uint32_t len, qjs::Value cols_val);
        void stack_dump(int64_t addr, uint32_t len);

    private:
        Speakeasy& sp_;
    };

} // namespace speakeasy

#endif // SPEAKEASY_JSEMUOBJ_H