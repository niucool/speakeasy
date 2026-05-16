// shlwapi.cpp — shlwapi.dll handler (real implementations)
#include "shlwapi.h"
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <algorithm>
#include <cstdio>
#include <cctype>
#include "windows/winemu.h"

// ── Windows SDK macro conflict protection ─────────────────────
#ifdef _WIN32
#pragma push_macro("MAX_PATH")
#pragma push_macro("ERROR_SUCCESS")
#pragma push_macro("ERROR_INSUFFICIENT_BUFFER")
#undef MAX_PATH
#undef ERROR_SUCCESS
#undef ERROR_INSUFFICIENT_BUFFER
#endif

using namespace speakeasy;

namespace speakeasy { namespace api {

static inline WindowsEmulator* we(void* e) { return static_cast<WindowsEmulator*>(e); }
static inline BinaryEmulator* be(void* e) { return static_cast<BinaryEmulator*>(e); }

static constexpr uint32_t SHLWAPI_MAX_PATH = 260;
static constexpr uint32_t SHLWAPI_ERROR_SUCCESS = 0;

// ── Format string helpers (replicated from msvcrt pattern) ────

static int shlwapi_va_arg_count(const std::string& fmt) {
    int count = 0;
    for (size_t i = 0; i < fmt.size(); ++i) {
        if (fmt[i] == '%' && i + 1 < fmt.size() && fmt[i + 1] != '%') {
            ++count;
        }
    }
    return count;
}

static std::string shlwapi_do_str_format(void* e, const std::string& fmt, const std::vector<uint64_t>& argv) {
    (void)e;
    std::string result;
    std::vector<uint64_t> args = argv;
    size_t i = 0;

    while (i < fmt.size()) {
        if (fmt[i] == '%' && i + 1 < fmt.size()) {
            if (fmt[i + 1] == '%') {
                result += '%';
                i += 2;
                continue;
            }
            ++i;

            std::string fmt_mods;
            while (i < fmt.size() && (fmt[i] == 'l' || fmt[i] == 'h' ||
                                       fmt[i] == 'w' || fmt[i] == 'z' ||
                                       fmt[i] == 't' || fmt[i] == 'j')) {
                fmt_mods += fmt[i];
                ++i;
            }
            while (i < fmt.size() && std::isdigit(static_cast<unsigned char>(fmt[i]))) {
                fmt_mods += fmt[i];
                ++i;
            }
            if (i >= fmt.size()) break;

            char conv = fmt[i];
            if (args.empty()) break;

            switch (conv) {
            case 's': {
                uint64_t addr = args[0];
                args.erase(args.begin());
                std::string str_val;
                if (fmt_mods.find('w') != std::string::npos || fmt_mods.find('S') != std::string::npos) {
                    str_val = be(e)->read_mem_string(addr, 2);
                } else {
                    str_val = be(e)->read_mem_string(addr, 1);
                }
                result += str_val;
                break;
            }
            case 'S': {
                uint64_t addr = args[0];
                args.erase(args.begin());
                result += be(e)->read_mem_string(addr, 2);
                break;
            }
            case 'd':
            case 'i':
            case 'u':
            case 'x':
            case 'X': {
                uint64_t val = args[0];
                args.erase(args.begin());
                char buf[32];
                if (conv == 'x')
                    snprintf(buf, sizeof(buf), "%llx", (unsigned long long)val);
                else if (conv == 'X')
                    snprintf(buf, sizeof(buf), "%llX", (unsigned long long)val);
                else
                    snprintf(buf, sizeof(buf), "%lld", (long long)val);
                result += buf;
                break;
            }
            case 'c': {
                uint64_t val = args[0] & 0xFF;
                args.erase(args.begin());
                result += static_cast<char>(val);
                break;
            }
            case 'p':
            case 'P': {
                uint64_t val = args[0];
                args.erase(args.begin());
                char buf[32];
                snprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)val);
                result += buf;
                break;
            }
            default:
                result += '%';
                result += conv;
                break;
            }
            ++i;
        } else {
            result += fmt[i];
            ++i;
        }
    }
    return result;
}

static std::vector<uint64_t> shlwapi_read_va_args(void* e, uint64_t va_list_ptr, int num_args) {
    std::vector<uint64_t> args;
    int ps = be(e)->get_ptr_size();
    uint64_t cursor = va_list_ptr;
    for (int i = 0; i < num_args; ++i) {
        auto raw = we(e)->mem_read(cursor, ps);
        if (raw.size() < static_cast<size_t>(ps)) break;
        args.push_back(read_le(raw, 0, ps));
        cursor += ps;
    }
    return args;
}

// ── Constructor ───────────────────────────────────────────────
Shlwapi::Shlwapi() {
    INIT_API_TABLE(Shlwapi)
    REG(Shlwapi, PathIsRelative, 1)      REG(Shlwapi, StrStr, 2)
    REG(Shlwapi, StrStrI, 2)             REG(Shlwapi, PathFindExtension, 1)
    REG(Shlwapi, StrCmpI, 2)             REG(Shlwapi, PathFindFileName, 1)
    REG(Shlwapi, PathRemoveExtension, 1) REG(Shlwapi, PathStripPath, 1)
    REG(Shlwapi, wvnsprintfA, 4)         REG(Shlwapi, wnsprintf, 4)
    REG(Shlwapi, PathAppend, 2)          REG(Shlwapi, PathCanonicalize, 2)
    REG(Shlwapi, PathRemoveFileSpec, 1)  REG(Shlwapi, PathAddBackslash, 1)
    REG(Shlwapi, PathRenameExtension, 2)
    END_API_TABLE
}

// ═══════════════════════════════════════════════════════════════
//  PathIsRelative
// ═══════════════════════════════════════════════════════════════
uint64_t Shlwapi::PathIsRelative(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    uint64_t pszPath = a[0];
    bool rv = false;

    if (pszPath) {
        std::string pn = be(e)->read_mem_string(pszPath, 1);
        if (pn.find("..") != std::string::npos) {
            rv = true;
        }
    }

    return rv ? 1 : 0;
}

// ═══════════════════════════════════════════════════════════════
//  StrStr
// ═══════════════════════════════════════════════════════════════
uint64_t Shlwapi::StrStr(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    uint64_t hay = a[0];
    uint64_t needle = a[1];

    std::string _hay;
    std::string _needle;

    if (hay) {
        _hay = be(e)->read_mem_string(hay, 1);
    }
    if (needle) {
        _needle = be(e)->read_mem_string(needle, 1);
    }

    size_t ret = _hay.find(_needle);
    if (ret != std::string::npos) {
        return hay + ret;
    }
    return 0;
}

// ═══════════════════════════════════════════════════════════════
//  StrStrI
// ═══════════════════════════════════════════════════════════════
uint64_t Shlwapi::StrStrI(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    uint64_t hay = a[0];
    uint64_t needle = a[1];

    std::string _hay;
    std::string _needle;

    if (hay) {
        _hay = be(e)->read_mem_string(hay, 1);
    }
    if (needle) {
        _needle = be(e)->read_mem_string(needle, 1);
    }

    // Case-insensitive comparison
    std::string hay_lower = _hay;
    std::string needle_lower = _needle;
    for (auto& c : hay_lower) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    for (auto& c : needle_lower) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

    size_t ret = hay_lower.find(needle_lower);
    if (ret != std::string::npos) {
        return hay + ret;
    }
    return 0;
}

// ═══════════════════════════════════════════════════════════════
//  PathFindExtension
// ═══════════════════════════════════════════════════════════════
uint64_t Shlwapi::PathFindExtension(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    uint64_t pszPath = a[0];
    std::string s = be(e)->read_mem_string(pszPath, 1);

    // Find last backslash
    size_t idx1 = s.rfind('\\');
    std::string t = (idx1 == std::string::npos) ? s : s.substr(idx1 + 1);

    // Find last dot in the filename part
    size_t idx2 = t.rfind('.');
    if (idx2 == std::string::npos) {
        // No extension - return pointer to null terminator
        return pszPath + s.size();
    }

    return pszPath + idx1 + 1 + idx2;
}

// ═══════════════════════════════════════════════════════════════
//  StrCmpI
// ═══════════════════════════════════════════════════════════════
uint64_t Shlwapi::StrCmpI(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    uint64_t psz1 = a[0];
    uint64_t psz2 = a[1];

    std::string s1 = be(e)->read_mem_string(psz1, 1);
    std::string s2 = be(e)->read_mem_string(psz2, 1);

    // Case-insensitive comparison
    std::string s1_lower = s1;
    std::string s2_lower = s2;
    for (auto& c : s1_lower) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    for (auto& c : s2_lower) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

    return (s1_lower == s2_lower) ? 0 : 1;
}

// ═══════════════════════════════════════════════════════════════
//  PathFindFileName
// ═══════════════════════════════════════════════════════════════
uint64_t Shlwapi::PathFindFileName(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    uint64_t pszPath = a[0];
    std::string s = be(e)->read_mem_string(pszPath, 1);

    size_t idx = s.rfind('\\');
    if (idx == std::string::npos) {
        return pszPath + s.size();
    }

    return pszPath + idx + 1;
}

// ═══════════════════════════════════════════════════════════════
//  PathRemoveExtension
// ═══════════════════════════════════════════════════════════════
uint64_t Shlwapi::PathRemoveExtension(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    uint64_t pszPath = a[0];
    std::string s = be(e)->read_mem_string(pszPath, 1);

    size_t idx1 = s.rfind('\\');
    std::string t = (idx1 == std::string::npos) ? s : s.substr(idx1 + 1);
    size_t idx2 = t.rfind('.');

    if (idx2 == std::string::npos) {
        return pszPath;
    }

    s = s.substr(0, idx1 + 1 + idx2);
    be(e)->write_mem_string(s, pszPath, 1);
    return pszPath;
}

// ═══════════════════════════════════════════════════════════════
//  PathStripPath
// ═══════════════════════════════════════════════════════════════
uint64_t Shlwapi::PathStripPath(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    uint64_t pszPath = a[0];
    std::string s = be(e)->read_mem_string(pszPath, 1);

    size_t idx = s.rfind('\\');
    std::string mod_name;
    if (idx == std::string::npos) {
        mod_name = s;
    } else {
        mod_name = s.substr(idx + 1);
    }

    be(e)->write_mem_string(mod_name, pszPath, 1);
    return 0;  // void return
}

// ═══════════════════════════════════════════════════════════════
//  wvnsprintfA
// ═══════════════════════════════════════════════════════════════
uint64_t Shlwapi::wvnsprintfA(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    uint64_t buffer = a[0];
    uint64_t count = a[1];
    uint64_t fmt_ptr = a[2];
    uint64_t argptr = a[3];

    std::string fmt_str = be(e)->read_mem_string(fmt_ptr, 1);
    int fmt_cnt = shlwapi_va_arg_count(fmt_str);
    std::vector<uint64_t> vargs = shlwapi_read_va_args(e, argptr, fmt_cnt);

    std::string fin = shlwapi_do_str_format(e, fmt_str, vargs);
    if (fin.size() >= count) {
        fin = fin.substr(0, count - 1);
    }

    uint64_t rv = fin.size();
    be(e)->write_mem_string(fin, buffer, 1);
    return rv;
}

// ═══════════════════════════════════════════════════════════════
//  wnsprintf
// ═══════════════════════════════════════════════════════════════
uint64_t Shlwapi::wnsprintf(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    // int wnsprintf(PSTR pszDest, int cchDest, PCSTR pszFmt, ...);
    uint64_t buf = a[0];
    uint64_t max_buf_size = a[1];
    uint64_t fmt = a[2];

    std::string fmt_str = be(e)->read_mem_string(fmt, 1);
    int fmt_cnt = shlwapi_va_arg_count(fmt_str);

    if (fmt_cnt == 0) {
        // No format args, just write the format string
        be(e)->write_mem_string(fmt_str, buf, 1);
        return fmt_str.size();
    }

    std::vector<uint64_t> vargs;
    int ps = be(e)->get_ptr_size();
    uint64_t cursor = a[3];
    for (int i = 0; i < fmt_cnt; ++i) {
        auto raw = we(e)->mem_read(cursor, ps);
        if (raw.size() < static_cast<size_t>(ps)) break;
        vargs.push_back(read_le(raw, 0, ps));
        cursor += ps;
    }

    std::string fin = shlwapi_do_str_format(e, fmt_str, vargs);
    uint64_t rv = fin.size();

    if (rv <= max_buf_size) {
        be(e)->write_mem_string(fin, buf, 1);
        return rv;
    }

    return static_cast<uint64_t>(-1);  // -1 on failure
}

// ═══════════════════════════════════════════════════════════════
//  PathAppend
// ═══════════════════════════════════════════════════════════════
uint64_t Shlwapi::PathAppend(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    uint64_t pszPath = a[0];
    uint64_t pszMore = a[1];

    std::string path = be(e)->read_mem_string(pszPath, 1);
    std::string more = be(e)->read_mem_string(pszMore, 1);

    // Join paths with backslash
    if (!path.empty() && !more.empty()) {
        if (path.back() != '\\' && more.front() != '\\') {
            path += '\\';
        }
        path += more;
    } else if (path.empty()) {
        path = more;
    }

    be(e)->write_mem_string(path, pszPath, 1);
    return 1;  // TRUE
}

// ═══════════════════════════════════════════════════════════════
//  PathCanonicalize
// ═══════════════════════════════════════════════════════════════
uint64_t Shlwapi::PathCanonicalize(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    uint64_t pszBuf = a[0];
    uint64_t pszPath = a[1];

    std::string path = be(e)->read_mem_string(pszPath, 1);
    be(e)->write_mem_string(path, pszBuf, 1);
    return 1;  // TRUE
}

// ═══════════════════════════════════════════════════════════════
//  PathRemoveFileSpec
// ═══════════════════════════════════════════════════════════════
uint64_t Shlwapi::PathRemoveFileSpec(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    uint64_t pszPath = a[0];
    std::string s = be(e)->read_mem_string(pszPath, 1);

    size_t idx = s.rfind('\\');
    if (idx == std::string::npos) {
        return 0;  // FALSE
    }

    s = s.substr(0, idx);
    be(e)->write_mem_string(s, pszPath, 1);
    return 1;  // TRUE
}

// ═══════════════════════════════════════════════════════════════
//  PathAddBackslash
// ═══════════════════════════════════════════════════════════════
uint64_t Shlwapi::PathAddBackslash(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    uint64_t pszPath = a[0];
    std::string s = be(e)->read_mem_string(pszPath, 1);

    if (!s.empty() && s.back() != '\\') {
        s += '\\';
        if (s.size() > SHLWAPI_MAX_PATH) {
            return 0;  // NULL
        }
    }

    be(e)->write_mem_string(s, pszPath, 1);
    return pszPath;
}

// ═══════════════════════════════════════════════════════════════
//  PathRenameExtension
// ═══════════════════════════════════════════════════════════════
uint64_t Shlwapi::PathRenameExtension(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    uint64_t pszPath = a[0];
    uint64_t pszExt = a[1];

    std::string path = be(e)->read_mem_string(pszPath, 1);
    std::string ext = be(e)->read_mem_string(pszExt, 1);

    // Extension must start with '.'
    if (ext.empty() || ext[0] != '.') {
        return 0;  // FALSE
    }

    size_t i = path.rfind('.');
    if (i == std::string::npos) {
        path += ext;
    } else {
        path = path.substr(0, i) + ext;
    }

    if (path.size() > SHLWAPI_MAX_PATH) {
        return 0;  // FALSE
    }

    be(e)->write_mem_string(path, pszPath, 1);
    return 1;  // TRUE
}

}} // namespaces

// ── Pop SDK macros ────────────────────────────────────────────
#ifdef _WIN32
#pragma pop_macro("ERROR_INSUFFICIENT_BUFFER")
#pragma pop_macro("ERROR_SUCCESS")
#pragma pop_macro("MAX_PATH")
#endif
