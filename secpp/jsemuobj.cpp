// jsemuobj.cpp - Emulator object functions exposed to JavaScript (quickjspp modernized)
#include "jsemuobj.h"
#include "speakeasy.h"

#include <cstring>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <plog/Log.h>

namespace speakeasy {

    // Helper: read little-endian values from bytes safely
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

    JsEmuObject::JsEmuObject(Speakeasy& speakeasy) : sp_(speakeasy) {}

    // ============================================================================
    // Registers
    // ============================================================================

    uint64_t JsEmuObject::read_reg(uint32_t reg_id) {
        return sp_.reg_read(static_cast<int>(reg_id));
    }

    bool JsEmuObject::set_reg(uint32_t reg_id, int64_t value) {
        sp_.reg_write(static_cast<int>(reg_id), static_cast<uint64_t>(value));
        return true;
    }

    // ============================================================================
    // Strings
    // ============================================================================

    std::string JsEmuObject::read_string_a(int64_t addr, qjs::Value max_chars_val) {
        size_t max_chars = 0;
        if (!JS_IsUndefined(max_chars_val.v)) {
            max_chars = static_cast<size_t>(static_cast<int32_t>(max_chars_val));
        }
        return sp_.read_mem_string(static_cast<uint64_t>(addr), 1, max_chars);
    }

    std::string JsEmuObject::read_string_w(int64_t addr, qjs::Value max_chars_val) {
        size_t max_chars = 0;
        if (!JS_IsUndefined(max_chars_val.v)) {
            max_chars = static_cast<size_t>(static_cast<int32_t>(max_chars_val));
        }
        return sp_.read_mem_string(static_cast<uint64_t>(addr), 2, max_chars);
    }

    int32_t JsEmuObject::write_string_a(int64_t addr, const std::string& str) {
        size_t len = str.length();
        std::vector<uint8_t> data(len + 1);
        std::memcpy(data.data(), str.c_str(), len);
        data[len] = '\0';

        sp_.mem_write(static_cast<uint64_t>(addr), data);
        return static_cast<int32_t>(len + 1);
    }

    int32_t JsEmuObject::write_string_w(int64_t addr, const std::string& str) {
        size_t len = str.length();
        std::vector<uint8_t> data((len + 1) * 2);
        for (size_t i = 0; i < len; i++) {
            data[i * 2] = static_cast<uint8_t>(str[i]);
            data[i * 2 + 1] = 0;
        }
        data[len * 2] = 0;
        data[len * 2 + 1] = 0;

        sp_.mem_write(static_cast<uint64_t>(addr), data);
        return static_cast<int32_t>((len + 1) * 2);
    }

    // ============================================================================
    // Modules
    // ============================================================================

    int64_t JsEmuObject::load_library(const std::string& libname) {
        auto slash = libname.find_last_of("/\\");
        std::string fname = (slash != std::string::npos) ? libname.substr(slash + 1) : libname;
        auto dot = fname.rfind('.');
        std::string base = (dot != std::string::npos) ? fname.substr(0, dot) : fname;

        std::transform(base.begin(), base.end(), base.begin(), ::tolower);
        std::string redirect = base + ".dll";

        return static_cast<int64_t>(sp_.load_library(redirect));
    }

    std::string JsEmuObject::get_module_name(qjs::Value handle_val) {
        if (JS_IsUndefined(handle_val.v)) {
            auto mods = sp_.get_user_modules();
            if (!mods.empty() && mods[0]) {
                return mods[0]->name;
            }
            return "";
        }

        int64_t handle = static_cast<int64_t>(handle_val);
        auto mods = sp_.get_user_modules();
        if (!mods.empty() && mods[0] && mods[0]->base == static_cast<uint64_t>(handle)) {
            return mods[0]->name;
        }

        return sp_.get_module_name_from_handle(static_cast<uint64_t>(handle));
    }

    int64_t JsEmuObject::get_module_handle(qjs::Value name_val) {
        if (JS_IsUndefined(name_val.v)) {
            auto mods = sp_.get_user_modules();
            if (!mods.empty() && mods[0]) {
                return static_cast<int64_t>(mods[0]->base);
            }
            return 0;
        }

        std::string name = static_cast<std::string>(name_val);
        return static_cast<int64_t>(sp_.get_module_handle_by_name(name));
    }

    int64_t JsEmuObject::get_proc_address(int64_t handle, const std::string& fn_name) {
        return static_cast<int64_t>(sp_.get_proc_address(static_cast<uint64_t>(handle), fn_name));
    }

    // ============================================================================
    // Memory Write
    // ============================================================================

    bool JsEmuObject::write_byte(int64_t addr, uint32_t val) {
        std::vector<uint8_t> buf = { static_cast<uint8_t>(val) };
        sp_.mem_write(static_cast<uint64_t>(addr), buf);
        return true;
    }

    bool JsEmuObject::write_word(int64_t addr, int32_t val) {
        uint16_t v16 = static_cast<uint16_t>(val);
        std::vector<uint8_t> buf = { static_cast<uint8_t>(v16 & 0xFF),
                                     static_cast<uint8_t>((v16 >> 8) & 0xFF) };
        sp_.mem_write(static_cast<uint64_t>(addr), buf);
        return true;
    }

    bool JsEmuObject::write_dword(int64_t addr, int32_t val) {
        uint32_t v32 = static_cast<uint32_t>(val);
        std::vector<uint8_t> buf = { static_cast<uint8_t>(v32 & 0xFF),
                                     static_cast<uint8_t>((v32 >> 8) & 0xFF),
                                     static_cast<uint8_t>((v32 >> 16) & 0xFF),
                                     static_cast<uint8_t>((v32 >> 24) & 0xFF) };
        sp_.mem_write(static_cast<uint64_t>(addr), buf);
        return true;
    }

    bool JsEmuObject::write_qword(int64_t addr, int64_t val) {
        uint64_t v64 = static_cast<uint64_t>(val);
        std::vector<uint8_t> buf = { static_cast<uint8_t>(v64 & 0xFF),
                                     static_cast<uint8_t>((v64 >> 8) & 0xFF),
                                     static_cast<uint8_t>((v64 >> 16) & 0xFF),
                                     static_cast<uint8_t>((v64 >> 24) & 0xFF),
                                     static_cast<uint8_t>((v64 >> 32) & 0xFF),
                                     static_cast<uint8_t>((v64 >> 40) & 0xFF),
                                     static_cast<uint8_t>((v64 >> 48) & 0xFF),
                                     static_cast<uint8_t>((v64 >> 56) & 0xFF) };
        sp_.mem_write(static_cast<uint64_t>(addr), buf);
        return true;
    }

    int32_t JsEmuObject::write_mem(int64_t addr, const std::vector<uint8_t>& bytes) {
        sp_.mem_write(static_cast<uint64_t>(addr), bytes);
        return static_cast<int32_t>(bytes.size());
    }

    // ============================================================================
    // Memory Read
    // ============================================================================

    int32_t JsEmuObject::read_byte(int64_t addr) {
        auto buf = sp_.mem_read(static_cast<uint64_t>(addr), 1);
        if (buf.empty()) return 0;
        return buf[0];
    }

    int32_t JsEmuObject::read_word(int64_t addr) {
        auto buf = sp_.mem_read(static_cast<uint64_t>(addr), 2);
        return static_cast<int32_t>(le16(buf));
    }

    int32_t JsEmuObject::read_dword(int64_t addr) {
        auto buf = sp_.mem_read(static_cast<uint64_t>(addr), 4);
        return static_cast<int32_t>(le32(buf));
    }

    int64_t JsEmuObject::read_qword(int64_t addr) {
        auto buf = sp_.mem_read(static_cast<uint64_t>(addr), 8);
        return static_cast<int64_t>(le64(buf));
    }

    qjs::Value JsEmuObject::read_mem(qjs::Context& ctx, int64_t addr, uint32_t length) {
        auto buf = sp_.mem_read(static_cast<uint64_t>(addr), static_cast<size_t>(length));
        // Create an ArrayBuffer from the raw buffer data
        return qjs::Value{ctx.ctx, JS_NewArrayBufferCopy(ctx.ctx, buf.data(), buf.size())};
    }

    // ============================================================================
    // Stack
    // ============================================================================

    bool JsEmuObject::push(int64_t val) {
        sp_.push_stack(static_cast<uint64_t>(val));
        return true;
    }

    int64_t JsEmuObject::pop() {
        return static_cast<int64_t>(sp_.pop_stack());
    }

    // ============================================================================
    // Control
    // ============================================================================

    void JsEmuObject::stop() {
        sp_.stop();
    }

    std::string JsEmuObject::last_error() {
        return "no error";
    }

    // ============================================================================
    // Debug
    // ============================================================================

    void JsEmuObject::hex_dump(int64_t addr, uint32_t len, qjs::Value cols_val) {
        if (len == 0) return;

        uint32_t cols = 16;
        if (!JS_IsUndefined(cols_val.v)) {
            cols = static_cast<uint32_t>(static_cast<int32_t>(cols_val));
        }

        auto buf = sp_.mem_read(static_cast<uint64_t>(addr), static_cast<size_t>(len));

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
    }

    void JsEmuObject::stack_dump(int64_t addr, uint32_t len) {
        if (len == 0) return;

        int ptr_size = sp_.get_ptr_size();
        auto buf = sp_.mem_read(static_cast<uint64_t>(addr), static_cast<size_t>(len));

        std::ostringstream oss;
        oss << std::hex << std::setfill('0') << "Stack Dump:\n";
        for (size_t i = 0; i + static_cast<size_t>(ptr_size) <= buf.size(); i += ptr_size) {
            uint64_t val = (ptr_size == 8) ? le64(buf, i) : le32(buf, i);
            oss << "  " << std::setw(ptr_size * 2) << (static_cast<uint64_t>(addr) + i)
                << ": " << std::setw(ptr_size * 2) << val << '\n';
        }
        oss << std::dec;

        PLOG_INFO << "[JS] " << oss.str();
    }

} // namespace speakeasy