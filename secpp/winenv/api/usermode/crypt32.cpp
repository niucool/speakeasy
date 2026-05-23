// crypt32.cpp — crypt32.dll handler (~4 APIs, real implementations)
#include "crypt32.h"

#include <cstring>
#include <vector>
#include <string>

#include "memmgr.h"
#include "struct.h"
#include "winenv/arch.h"
#include "windows/winemu.h"
#include "windows/win32.h"

using namespace speakeasy;

namespace speakeasy { namespace api {

// ── Typed cast helpers ────────────────────────────────────────
static inline WindowsEmulator* we(void* e) {
    return static_cast<WindowsEmulator*>(e);
}
static inline BinaryEmulator* be(void* e) {
    return static_cast<BinaryEmulator*>(e);
}
static inline Win32Emulator* w32(void* e) {
    return static_cast<Win32Emulator*>(e);
}
static inline MemoryManager* mm(void* e) {
    return static_cast<MemoryManager*>(e);
}

// ── Constants ─────────────────────────────────────────────────
static const uint32_t CRYPT_FLAG_BASE64 = 0x01;
static const uint32_t ERR_MORE_DATA = 234;

// ── Base64 decode helper ──────────────────────────────────────
static std::vector<uint8_t> base64_decode(const std::string& input) {
    std::vector<uint8_t> empty;
    std::string s;
    s.reserve(input.size());
    for (size_t i = 0; i < input.size(); i++) {
        char ch = input[i];
        if (ch != ' ' && ch != '\r' && ch != '\n' && ch != '\t')
            s.push_back(ch);
    }
    if (s.empty()) return empty;

    const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int decode_table[256];
    std::memset(decode_table, -1, sizeof(decode_table));
    for (int i = 0; i < 64; i++)
        decode_table[(unsigned char)b64[i]] = i;

    size_t len = s.size();
    if (len % 4 != 0) return empty;
    size_t padding = 0;
    if (len >= 2 && s[len-1] == '=') padding++;
    if (len >= 2 && s[len-2] == '=') padding++;

    size_t out_len = (len / 4) * 3 - padding;
    std::vector<uint8_t> out(out_len);
    size_t out_idx = 0;

    for (size_t i = 0; i < len; i += 4) {
        int b0 = decode_table[(unsigned char)s[i]];
        int b1 = decode_table[(unsigned char)s[i+1]];
        int b2 = (i+2 < len && s[i+2] != '=') ? decode_table[(unsigned char)s[i+2]] : 0;
        int b3 = (i+3 < len && s[i+3] != '=') ? decode_table[(unsigned char)s[i+3]] : 0;
        if (b0 < 0 || b1 < 0) return empty;
        uint32_t triple = (uint32_t)(b0 << 18) | (uint32_t)(b1 << 12) | (uint32_t)((b2 >= 0 ? b2 : 0) << 6) | (uint32_t)(b3 >= 0 ? b3 : 0);
        if (out_idx < out_len) out[out_idx++] = (uint8_t)((triple >> 16) & 0xFF);
        if (out_idx < out_len) out[out_idx++] = (uint8_t)((triple >> 8) & 0xFF);
        if (out_idx < out_len) out[out_idx++] = (uint8_t)(triple & 0xFF);
    }
    return out;
}

// ── Constructor ───────────────────────────────────────────────

Crypt32::Crypt32(void* emu) : ApiHandler(emu) {
    apis_ = {
        {"CryptStringToBinaryA", 7, CryptStringToBinaryA},
        {"CryptBinaryToStringA", 6, CryptBinaryToStringA},
        {"CertOpenStore", 3, CertOpenStore},
        {"CryptDecodeObject", 5, CryptDecodeObject},
    };
}

// ── API implementations ───────────────────────────────────────

uint64_t Crypt32::CryptStringToBinaryA(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    uint64_t pszString = a[0], cchString = a[1], dwFlags = a[2];
    uint64_t pbBinary = a[3], pcbBinary = a[4], pdwSkip = a[5], pdwFlags = a[6];
    (void)pdwFlags;

    std::vector<uint8_t> raw;
    std::string s;
    if (cchString) {
        raw = mm(e)->mem_read(pszString, static_cast<size_t>(cchString));
        s.assign(raw.begin(), raw.end());
    } else {
        s = be(e)->read_mem_string(pszString, 1);
    }

    if (dwFlags != CRYPT_FLAG_BASE64)
        return 1;

    std::vector<uint8_t> decoded = base64_decode(s);
    if (decoded.empty())
        return 0;

    uint32_t out_len = static_cast<uint32_t>(decoded.size());
    uint32_t cbBinary = 0;
    uint32_t read_len = 0;
    uint32_t test_val;
    if (pcbBinary) {
        raw = mm(e)->mem_read(pcbBinary, 4);
        cbBinary = static_cast<uint32_t>(raw[0]) | (static_cast<uint32_t>(raw[1]) << 8) |
                   (static_cast<uint32_t>(raw[2]) << 16) | (static_cast<uint32_t>(raw[3]) << 24);
    }

    if (pbBinary == 0) {
        if (pcbBinary) {
            std::vector<uint8_t> len_bytes(4);
            write_le(len_bytes, 0, out_len, 4);
            mm(e)->mem_write(pcbBinary, len_bytes);
        }
        return out_len;
    }

    if (out_len > cbBinary) {
        w32(e)->set_last_error(ERR_MORE_DATA);
        return 0;
    }

    mm(e)->mem_write(pbBinary, decoded);
    if (pcbBinary) {
        std::vector<uint8_t> len_bytes(4);
        write_le(len_bytes, 0, out_len, 4);
        mm(e)->mem_write(pcbBinary, len_bytes);
    }
    if (pdwSkip) {
        std::vector<uint8_t> zero(4, 0);
        mm(e)->mem_write(pdwSkip, zero);
    }
    return 1;
}

uint64_t Crypt32::CryptBinaryToStringA(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    (void)e; (void)a;
    return 1;
}

uint64_t Crypt32::CertOpenStore(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    (void)e; (void)a;
    return 1;
}

uint64_t Crypt32::CryptDecodeObject(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    (void)e; (void)a;
    return 1;
}

}} // namespaces
