// struct.h  Emulated structure base class and helpers
//
// Maps to: speakeasy/struct.py
//
// Provides a base class for objects that represent C structures in the
// emulated address space, along with utility templates for reading and
// writing typed data.

#ifndef SPEAKEASY_STRUCT_H
#define SPEAKEASY_STRUCT_H

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <cstdint>
#include <stdexcept>
#include <sstream>
#include <iomanip>

namespace speakeasy {

//  Exception 

class EmuStructException : public std::runtime_error {
public:
    explicit EmuStructException(const std::string& msg)
        : std::runtime_error(msg) {}
};

//  Enum helper 

/**
 * Simple dynamic enum class.  Supports arbitrary attribute access
 * for C-style enum constants.
 */
class EmuEnum {
private:
    std::map<std::string, int> values_;

public:
    EmuEnum() = default;

    void set(const std::string& name, int value) {
        values_[name] = value;
    }

    int get(const std::string& name) const {
        auto it = values_.find(name);
        if (it != values_.end()) return it->second;
        throw EmuStructException("Enum value not found: " + name);
    }

    bool has(const std::string& name) const {
        return values_.count(name) > 0;
    }
};

//  Pointer tag 

/**
 * Tag type to mark fields that are pointers in the emulated address space.
 * The pointed-to type is specified as a template parameter for documentation;
 * the actual pointer value is just a uint64_t address.
 */
template <typename T>
struct EmuPtr {
    uint64_t address = 0;

    EmuPtr() = default;
    explicit EmuPtr(uint64_t addr) : address(addr) {}
    operator uint64_t() const { return address; }
    bool is_null() const { return address == 0; }
};

//  Base class for emulated structures 

/**
 * Base class for objects that represent C structures in emulated memory.
 *
 * Subclasses should define their fields as public members matching the
 * layout of the corresponding C structure.  The virtual methods allow
 * the memory manager to query size and read/write raw bytes.
 */
class EmuStruct {
public:
    virtual ~EmuStruct() = default;

    /**
     * Return the byte size of this structure in the emulated address space.
     * Default implementation returns 0; subclasses with fixed-size POD layout
     * should override.
     */
    virtual size_t sizeof_obj() const { return 0; }

    /**
     * Serialize this structure into a byte vector suitable for writing
     * to emulated memory.  Subclasses MUST override.
     */
    virtual std::vector<uint8_t> get_bytes() const { return {}; }

    /**
     * Deserialize raw bytes into this structure.
     */
    virtual void from_bytes(const std::vector<uint8_t>& /*data*/) {}

    /**
     * Return a human-readable tag for memory map entries.
     */
    virtual std::string get_mem_tag() const { return "struct"; }
};

//  Byte-level helpers 

/** Write a little-endian integer into a byte buffer at offset. */
inline void write_le(std::vector<uint8_t>& buf, size_t offset, uint64_t value, size_t size_bytes) {
    if (offset + size_bytes > buf.size()) buf.resize(offset + size_bytes);
    for (size_t i = 0; i < size_bytes; ++i) {
        buf[offset + i] = static_cast<uint8_t>((value >> (i * 8)) & 0xFF);
    }
}

/** Read a little-endian integer from a byte buffer at offset. */
inline uint64_t read_le(const std::vector<uint8_t>& buf, size_t offset, size_t size_bytes) {
    uint64_t value = 0;
    for (size_t i = 0; i < size_bytes; ++i) {
        if (offset + i >= buf.size()) break;
        value |= static_cast<uint64_t>(buf[offset + i]) << (i * 8);
    }
    return value;
}

/** Write a big-endian integer into a byte buffer at offset. */
inline void write_be(std::vector<uint8_t>& buf, size_t offset, uint64_t value, size_t size_bytes) {
    if (offset + size_bytes > buf.size()) buf.resize(offset + size_bytes);
    for (size_t i = 0; i < size_bytes; ++i) {
        buf[offset + i] = static_cast<uint8_t>((value >> ((size_bytes - 1 - i) * 8)) & 0xFF);
    }
}

/** Read a big-endian integer from a byte buffer at offset. */
inline uint64_t read_be(const std::vector<uint8_t>& buf, size_t offset, size_t size_bytes) {
    uint64_t value = 0;
    for (size_t i = 0; i < size_bytes; ++i) {
        if (offset + i >= buf.size()) break;
        value |= static_cast<uint64_t>(buf[offset + i]) << ((size_bytes - 1 - i) * 8);
    }
    return value;
}

/** Write a string (null-terminated or fixed-length) into a byte buffer. */
inline void write_string(std::vector<uint8_t>& buf, size_t offset, const std::string& s, bool wide = false) {
    if (wide) {
        for (size_t i = 0; i < s.length(); ++i) {
            write_le(buf, offset + i * 2, static_cast<uint16_t>(s[i]), 2);
        }
        write_le(buf, offset + s.length() * 2, 0, 2);  // null terminator
    } else {
        for (size_t i = 0; i < s.length(); ++i) {
            if (offset + i >= buf.size()) buf.resize(offset + i + 1);
            buf[offset + i] = static_cast<uint8_t>(s[i]);
        }
        if (offset + s.length() >= buf.size()) buf.resize(offset + s.length() + 1);
        buf[offset + s.length()] = 0;
    }
}

/**
 * Format a uint64_t as a hex string (e.g. "0x7c000000").
 */
inline std::string hex_str(uint64_t value, bool prefix = true) {
    std::ostringstream oss;
    if (prefix) oss << "0x";
    oss << std::hex << std::uppercase << value;
    return oss.str();
}

/** Directly cast a POD structure from a byte buffer at offset. */
template <typename T>
inline T cast_from_bytes(const std::vector<uint8_t>& buf, size_t offset = 0) {
    if (offset + sizeof(T) > buf.size()) {
        throw EmuStructException("Buffer too small to cast POD type");
    }
    T val;
    std::memcpy(&val, buf.data() + offset, sizeof(T));
    return val;
}

/** Directly cast and write a POD structure to a byte buffer at offset. */
template <typename T>
inline void cast_to_bytes(std::vector<uint8_t>& buf, size_t offset, const T& val) {
    if (offset + sizeof(T) > buf.size()) {
        buf.resize(offset + sizeof(T));
    }
    std::memcpy(buf.data() + offset, &val, sizeof(T));
}

} // namespace speakeasy

#endif // SPEAKEASY_STRUCT_H
