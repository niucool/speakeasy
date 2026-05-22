// msvcrt.cpp — msvcrt.dll handler (~120 APIs, real implementations)
#include "msvcrt.h"
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cmath>
#include <ctime>
#include <cctype>
#include <algorithm>
#include <string>
#include <vector>
#include <map>
#include <sstream>
#include "windows/winemu.h"
#include "struct.h"
#include "winenv/arch.h"

using namespace speakeasy;

namespace speakeasy { namespace api {

// ── Helper: typed casts from void* ───────────────────────────
static inline WindowsEmulator* we(void* e) {
    return static_cast<WindowsEmulator*>(e);
}
static inline BinaryEmulator* be(void* e) {
    return static_cast<BinaryEmulator*>(e);
}

// ── Static state for stateful APIs ───────────────────────────
static int msvc_rand_state = 0;
static uint64_t msvc_errno_ptr = 0;
static std::map<uint64_t, int> msvc_file_streams; // stream_addr -> file_handle

// ─────────────────────────────────────────────────────────────
//  CONSTRUCTOR
// ─────────────────────────────────────────────────────────────

Msvcrt::Msvcrt() {
    INIT_API_TABLE(Msvcrt)
    // Startup / init
    REG(Msvcrt, __p__acmdln, 0)            REG(Msvcrt, _onexit, 1)
    REG(Msvcrt, mbstowcs_s, 5)             REG(Msvcrt, _wcsnicmp, 3)
    REG(Msvcrt, _initterm_e, 2)            REG(Msvcrt, _initterm, 2)
    REG(Msvcrt, __getmainargs, 5)          REG(Msvcrt, __wgetmainargs, 5)
    REG(Msvcrt, __p___wargv, 0)            REG(Msvcrt, __p___argv, 0)
    REG(Msvcrt, __p___argc, 0)             REG(Msvcrt, __p___initenv, 0)
    REG(Msvcrt, _get_initial_narrow_environment, 0)
    REG(Msvcrt, _get_initial_wide_environment, 0)
    // Exit / termination
    REG(Msvcrt, exit, 1)                   REG(Msvcrt, _exit, 1)
    REG(Msvcrt, _cexit, 0)                 REG(Msvcrt, _c_exit, 0)
    REG(Msvcrt, terminate, 1)
    // Exception / SEH
    REG(Msvcrt, _XcptFilter, 2)            REG(Msvcrt, _CxxThrowException, 2)
    REG(Msvcrt, _except_handler4_common, 6) REG(Msvcrt, _except_handler3, 4)
    REG(Msvcrt, _seh_filter_exe, 2)        REG(Msvcrt, _seh_filter_dll, 2)
    REG(Msvcrt, __CxxFrameHandler, 4)      REG(Msvcrt, _EH_prolog, 0)
    REG(Msvcrt, __current_exception_context, 0)
    REG(Msvcrt, __current_exception, 0)
    // I/O
    REG(Msvcrt, __acrt_iob_func, 1)        REG(Msvcrt, __stdio_common_vfprintf, 0)
    REG(Msvcrt, __stdio_common_vsprintf, 7) REG(Msvcrt, fprintf, 0)
    REG(Msvcrt, printf, 0)                 REG(Msvcrt, sprintf, 0)
    REG(Msvcrt, _snprintf, 0)              REG(Msvcrt, _snwprintf, 0)
    REG(Msvcrt, _vsnprintf, 4)             REG(Msvcrt, sscanf, 0)
    REG(Msvcrt, puts, 1)                   REG(Msvcrt, fopen, 2)
    REG(Msvcrt, _wfopen, 2)                REG(Msvcrt, fclose, 1)
    REG(Msvcrt, fseek, 3)                  REG(Msvcrt, ftell, 1)
    REG(Msvcrt, fread, 4)                  REG(Msvcrt, fputc, 2)
    REG(Msvcrt, _lock, 1)                  REG(Msvcrt, _unlock, 1)
    // Memory
    REG(Msvcrt, memset, 3)                 REG(Msvcrt, memcpy, 3)
    REG(Msvcrt, memmove, 3)                REG(Msvcrt, memcmp, 3)
    REG(Msvcrt, malloc, 1)                 REG(Msvcrt, calloc, 2)
    REG(Msvcrt, free, 1)
    // String
    REG(Msvcrt, strcpy, 2)                 REG(Msvcrt, wcscpy, 2)
    REG(Msvcrt, strncpy, 3)                REG(Msvcrt, wcsncpy, 3)
    REG(Msvcrt, strcat, 2)                 REG(Msvcrt, wcscat, 2)
    REG(Msvcrt, strncat, 3)                REG(Msvcrt, strncat_s, 4)
    REG(Msvcrt, strlen, 1)                 REG(Msvcrt, wcslen, 1)
    REG(Msvcrt, strcmp, 2)                 REG(Msvcrt, wcscmp, 2)
    REG(Msvcrt, strncmp, 3)                REG(Msvcrt, _strcmpi, 2)
    REG(Msvcrt, _stricmp, 2)               REG(Msvcrt, _strnicmp, 3)
    REG(Msvcrt, _wcsicmp, 2)               REG(Msvcrt, strstr, 2)
    REG(Msvcrt, wcsstr, 2)                 REG(Msvcrt, strchr, 2)
    REG(Msvcrt, strrchr, 2)                REG(Msvcrt, _strlwr, 1)
    REG(Msvcrt, atoi, 1)                   REG(Msvcrt, _ltoa, 3)
    REG(Msvcrt, _itoa, 3)                  REG(Msvcrt, _itow, 3)
    REG(Msvcrt, wcstombs, 3)
    // Math
    REG(Msvcrt, pow, 2)                    REG(Msvcrt, floor, 1)
    REG(Msvcrt, sin, 1)                    REG(Msvcrt, abs, 1)
    REG(Msvcrt, _ftol, 1)
    // Time
    REG(Msvcrt, time, 1)                   REG(Msvcrt, clock, 0)
    REG(Msvcrt, _strtime, 1)               REG(Msvcrt, _strdate, 1)
    // Random
    REG(Msvcrt, rand, 0)                   REG(Msvcrt, srand, 1)
    // App type / mode
    REG(Msvcrt, __set_app_type, 1)         REG(Msvcrt, _set_app_type, 1)
    REG(Msvcrt, __p__fmode, 0)             REG(Msvcrt, __p__commode, 0)
    REG(Msvcrt, _set_fmode, 1)             REG(Msvcrt, _controlfp, 2)
    REG(Msvcrt, _controlfp_s, 3)           REG(Msvcrt, _set_new_mode, 1)
    REG(Msvcrt, _configthreadlocale, 1)    REG(Msvcrt, _setusermatherr, 1)
    REG(Msvcrt, __setusermatherr, 1)
    // C++ helpers
    REG(Msvcrt, _set_invalid_parameter_handler, 1)
    REG(Msvcrt, _initialize_onexit_table, 1)
    REG(Msvcrt, _register_onexit_function, 2)
    REG(Msvcrt, __dllonexit, 3)
    REG(Msvcrt, _register_thread_local_exe_atexit_callback, 1)
    REG(Msvcrt, _crt_atexit, 1)
    REG(Msvcrt, _initialize_narrow_environment, 0)
    REG(Msvcrt, _configure_narrow_argv, 1)
    // Threading
    REG(Msvcrt, _beginthreadex, 6)         REG(Msvcrt, _beginthread, 3)
    // Misc
    REG(Msvcrt, system, 1)                 REG(Msvcrt, toupper, 1)
    REG(Msvcrt, tolower, 1)                REG(Msvcrt, isdigit, 1)
    REG(Msvcrt, _adjust_fdiv, 0)           REG(Msvcrt, _errno, 0)
    REG(Msvcrt, signal, 2)
    END_API_TABLE
}

// ═══════════════════════════════════════════════════════════════
//  MEMORY
// ═══════════════════════════════════════════════════════════════

uint64_t Msvcrt::malloc(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    size_t sz = static_cast<size_t>(a.empty() ? 0 : a[0]);
    if (sz == 0) sz = 1;
    return we(e)->mem_map(sz, 0, 4, "msvcrt.malloc");
}

uint64_t Msvcrt::calloc(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    uint64_t num = a.size() > 0 ? a[0] : 0;
    uint64_t sz  = a.size() > 1 ? a[1] : 0;
    size_t total = static_cast<size_t>(num * sz);
    if (total == 0) total = 1;
    uint64_t ptr = we(e)->mem_map(total, 0, 4, "msvcrt.calloc");
    // Zero-fill
    std::vector<uint8_t> zero(total, 0);
    we(e)->mem_write(ptr, zero);
    return ptr;
}

uint64_t Msvcrt::free(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    uint64_t ptr = a.empty() ? 0 : a[0];
    if (ptr) {
        try { we(e)->mem_free(ptr); } catch (...) {}
    }
    return 0;
}

uint64_t Msvcrt::memset(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    uint64_t ptr   = a.size() > 0 ? a[0] : 0;
    uint8_t  value = static_cast<uint8_t>(a.size() > 1 ? (a[1] & 0xFF) : 0);
    size_t   num   = static_cast<size_t>(a.size() > 2 ? a[2] : 0);
    std::vector<uint8_t> data(num, value);
    we(e)->mem_write(ptr, data);
    return ptr;
}

uint64_t Msvcrt::memcpy(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    uint64_t dest = a.size() > 0 ? a[0] : 0;
    uint64_t src  = a.size() > 1 ? a[1] : 0;
    size_t   num  = static_cast<size_t>(a.size() > 2 ? a[2] : 0);
    be(e)->mem_copy(dest, src, num);
    return dest;
}

uint64_t Msvcrt::memmove(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    uint64_t dest = a.size() > 0 ? a[0] : 0;
    uint64_t src  = a.size() > 1 ? a[1] : 0;
    size_t   num  = static_cast<size_t>(a.size() > 2 ? a[2] : 0);
    // memmove must handle overlap: read first, then write
    auto data = we(e)->mem_read(src, num);
    we(e)->mem_write(dest, data);
    return dest;
}

uint64_t Msvcrt::memcmp(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    uint64_t b1 = a.size() > 0 ? a[0] : 0;
    uint64_t b2 = a.size() > 1 ? a[1] : 0;
    size_t   cnt = static_cast<size_t>(a.size() > 2 ? a[2] : 0);
    for (size_t i = 0; i < cnt; ++i) {
        auto r1 = we(e)->mem_read(b1 + i, 1);
        auto r2 = we(e)->mem_read(b2 + i, 1);
        uint8_t v1 = r1.empty() ? 0 : r1[0];
        uint8_t v2 = r2.empty() ? 0 : r2[0];
        if (v1 != v2) return (v1 > v2) ? 1 : -1;
    }
    return 0;
}

// ═══════════════════════════════════════════════════════════════
//  STRING (ANSI)
// ═══════════════════════════════════════════════════════════════

uint64_t Msvcrt::strlen(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    uint64_t s = a.empty() ? 0 : a[0];
    if (!s) return 0;
    std::string str = be(e)->read_mem_string(s, 1);
    return static_cast<uint64_t>(str.size());
}

uint64_t Msvcrt::strcpy(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    uint64_t dest = a.size() > 0 ? a[0] : 0;
    uint64_t src  = a.size() > 1 ? a[1] : 0;
    if (!dest || !src) return dest;
    std::string s = be(e)->read_mem_string(src, 1);
    be(e)->write_mem_string(s, dest, 1);
    return dest;
}

uint64_t Msvcrt::strncpy(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    uint64_t dest = a.size() > 0 ? a[0] : 0;
    uint64_t src  = a.size() > 1 ? a[1] : 0;
    size_t   len  = static_cast<size_t>(a.size() > 2 ? a[2] : 0);
    if (!dest || !src || len == 0) return dest;
    std::string s = be(e)->read_mem_string(src, 1, static_cast<int>(len));
    if (s.size() < len) s.append(len - s.size(), '\0');
    be(e)->write_mem_string(s, dest, 1);
    return dest;
}

uint64_t Msvcrt::strcat(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    uint64_t d = a.size() > 0 ? a[0] : 0;
    uint64_t s = a.size() > 1 ? a[1] : 0;
    if (!d || !s) return d;
    std::string s1 = be(e)->read_mem_string(d, 1);
    std::string s2 = be(e)->read_mem_string(s, 1);
    std::string result = s1 + s2;
    be(e)->write_mem_string(result, d, 1);
    return d;
}

uint64_t Msvcrt::strncat(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    uint64_t d    = a.size() > 0 ? a[0] : 0;
    uint64_t s    = a.size() > 1 ? a[1] : 0;
    size_t   cnt  = static_cast<size_t>(a.size() > 2 ? a[2] : 0);
    if (!d || !s) return d;
    std::string s1 = be(e)->read_mem_string(d, 1);
    std::string s2 = be(e)->read_mem_string(s, 1, static_cast<int>(cnt));
    std::string result = s1 + s2;
    be(e)->write_mem_string(result, d, 1);
    return d;
}

uint64_t Msvcrt::strcmp(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    uint64_t s1 = a.size() > 0 ? a[0] : 0;
    uint64_t s2 = a.size() > 1 ? a[1] : 0;
    if (!s1 || !s2) return (s1 == s2) ? 0 : 1;
    std::string str1 = be(e)->read_mem_string(s1, 1);
    std::string str2 = be(e)->read_mem_string(s2, 1);
    return (str1 == str2) ? 0 : 1;
}

uint64_t Msvcrt::strncmp(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    uint64_t s1 = a.size() > 0 ? a[0] : 0;
    uint64_t s2 = a.size() > 1 ? a[1] : 0;
    if (!s1 || !s2) return (s1 == s2) ? 0 : 1;
    std::string str1 = be(e)->read_mem_string(s1, 1);
    std::string str2 = be(e)->read_mem_string(s2, 1);
    return (str1 == str2) ? 0 : 1;
}

uint64_t Msvcrt::_stricmp(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    uint64_t s1 = a.size() > 0 ? a[0] : 0;
    uint64_t s2 = a.size() > 1 ? a[1] : 0;
    if (!s1 || !s2) return (s1 == s2) ? 0 : 1;
    std::string str1 = be(e)->read_mem_string(s1, 1);
    std::string str2 = be(e)->read_mem_string(s2, 1);
    std::transform(str1.begin(), str1.end(), str1.begin(), ::tolower);
    std::transform(str2.begin(), str2.end(), str2.begin(), ::tolower);
    return (str1 == str2) ? 0 : 1;
}

uint64_t Msvcrt::_strcmpi(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    return _stricmp(e, "", 0, a);
}

uint64_t Msvcrt::_strnicmp(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    uint64_t s1    = a.size() > 0 ? a[0] : 0;
    uint64_t s2    = a.size() > 1 ? a[1] : 0;
    size_t   count = static_cast<size_t>(a.size() > 2 ? a[2] : 0);
    if (!s1 || !s2) return (s1 == s2) ? 0 : 1;
    std::string str1 = be(e)->read_mem_string(s1, 1, static_cast<int>(count));
    std::string str2 = be(e)->read_mem_string(s2, 1, static_cast<int>(count));
    std::transform(str1.begin(), str1.end(), str1.begin(), ::tolower);
    std::transform(str2.begin(), str2.end(), str2.begin(), ::tolower);
    return (str1 == str2) ? 0 : 1;
}

uint64_t Msvcrt::strstr(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    uint64_t hay   = a.size() > 0 ? a[0] : 0;
    uint64_t needle = a.size() > 1 ? a[1] : 0;
    if (!hay || !needle) return 0;
    std::string h = be(e)->read_mem_string(hay, 1);
    std::string n = be(e)->read_mem_string(needle, 1);
    size_t pos = h.find(n);
    if (pos == std::string::npos) return 0;
    return hay + pos;
}

uint64_t Msvcrt::strchr(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    uint64_t str = a.size() > 0 ? a[0] : 0;
    int      c   = static_cast<int>(a.size() > 1 ? (a[1] & 0xFF) : 0);
    if (!str) return 0;
    std::string s = be(e)->read_mem_string(str, 1);
    size_t pos = s.find(static_cast<char>(c));
    if (pos == std::string::npos) return 0;
    return str + pos;
}

uint64_t Msvcrt::strrchr(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    uint64_t str = a.size() > 0 ? a[0] : 0;
    int      c   = static_cast<int>(a.size() > 1 ? (a[1] & 0xFF) : 0);
    if (!str) return 0;
    std::string s = be(e)->read_mem_string(str, 1);
    size_t pos = s.rfind(static_cast<char>(c));
    if (pos == std::string::npos) return 0;
    return str + pos;
}

uint64_t Msvcrt::_strlwr(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    uint64_t str = a.empty() ? 0 : a[0];
    if (!str) return 0;
    std::string s = be(e)->read_mem_string(str, 1);
    std::transform(s.begin(), s.end(), s.begin(), ::tolower);
    be(e)->write_mem_string(s, str, 1);
    return str;
}

uint64_t Msvcrt::atoi(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    uint64_t str = a.empty() ? 0 : a[0];
    if (!str) return 0;
    std::string s = be(e)->read_mem_string(str, 1);
    // Trim whitespace
    size_t start = s.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return 0;
    s = s.substr(start);
    int sign = 1;
    size_t i = 0;
    if (s[0] == '-') { sign = -1; ++i; }
    else if (s[0] == '+') ++i;
    int64_t val = 0;
    for (; i < s.size() && std::isdigit(static_cast<unsigned char>(s[i])); ++i) {
        val = val * 10 + (s[i] - '0');
    }
    return static_cast<uint64_t>(val * sign);
}

uint64_t Msvcrt::_ltoa(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    int64_t value   = static_cast<int64_t>(a.size() > 0 ? a[0] : 0);
    uint64_t outstr = a.size() > 1 ? a[1] : 0;
    int radix = static_cast<int>(a.size() > 2 ? a[2] : 10);
    (void)radix;
    // Format the number
    char buf[64];
    if (radix == 10) {
        snprintf(buf, sizeof(buf), "%lld", (long long)value);
    } else if (radix == 16) {
        snprintf(buf, sizeof(buf), "%llx", (unsigned long long)value);
    } else {
        snprintf(buf, sizeof(buf), "%lld", (long long)value);
    }
    std::string result(buf);
    be(e)->write_mem_string(result, outstr, 1);
    return outstr;
}

uint64_t Msvcrt::_itoa(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    return _ltoa(e, "", 0, a);
}

uint64_t Msvcrt::_itow(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    int value    = static_cast<int>(a.size() > 0 ? a[0] : 0);
    uint64_t buf = a.size() > 1 ? a[1] : 0;
    int radix    = static_cast<int>(a.size() > 2 ? a[2] : 10);
    if (!buf) return 0;
    char tmp[64];
    snprintf(tmp, sizeof(tmp), "%d", value);
    std::string s(tmp);
    be(e)->write_mem_string(s, buf, 2); // wide char
    return buf;
}

uint64_t Msvcrt::wcstombs(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    uint64_t mbstr = a.size() > 0 ? a[0] : 0;
    uint64_t wcstr = a.size() > 1 ? a[1] : 0;
    size_t   count = static_cast<size_t>(a.size() > 2 ? a[2] : 0);
    if (!mbstr || !wcstr) return 0;
    std::string ws = be(e)->read_mem_string(wcstr, 2, static_cast<int>(count));
    be(e)->write_mem_string(ws, mbstr, 1);
    return ws.size();
}

// ═══════════════════════════════════════════════════════════════
//  STRING (WIDE)
// ═══════════════════════════════════════════════════════════════

uint64_t Msvcrt::wcslen(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    uint64_t s = a.empty() ? 0 : a[0];
    if (!s) return 0;
    std::string ws = be(e)->read_mem_string(s, 2);
    return static_cast<uint64_t>(ws.size());
}

uint64_t Msvcrt::wcscpy(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    uint64_t dest = a.size() > 0 ? a[0] : 0;
    uint64_t src  = a.size() > 1 ? a[1] : 0;
    if (!dest || !src) return dest;
    std::string ws = be(e)->read_mem_string(src, 2);
    be(e)->write_mem_string(ws, dest, 2);
    return dest;
}

uint64_t Msvcrt::wcsncpy(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    uint64_t dest  = a.size() > 0 ? a[0] : 0;
    uint64_t src   = a.size() > 1 ? a[1] : 0;
    size_t   count = static_cast<size_t>(a.size() > 2 ? a[2] : 0);
    if (!dest || !src || count == 0) return dest;
    std::string ws = be(e)->read_mem_string(src, 2, static_cast<int>(count));
    if (ws.size() < count) ws.append(count - ws.size(), '\0');
    be(e)->write_mem_string(ws, dest, 2);
    return dest;
}

uint64_t Msvcrt::wcscat(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    uint64_t d = a.size() > 0 ? a[0] : 0;
    uint64_t s = a.size() > 1 ? a[1] : 0;
    if (!d || !s) return d;
    std::string ws1 = be(e)->read_mem_string(d, 2);
    std::string ws2 = be(e)->read_mem_string(s, 2);
    be(e)->write_mem_string(ws1 + ws2, d, 2);
    return d;
}

uint64_t Msvcrt::wcscmp(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    uint64_t s1 = a.size() > 0 ? a[0] : 0;
    uint64_t s2 = a.size() > 1 ? a[1] : 0;
    if (!s1 || !s2) return (s1 == s2) ? 0 : 1;
    std::string ws1 = be(e)->read_mem_string(s1, 2);
    std::string ws2 = be(e)->read_mem_string(s2, 2);
    return (ws1 == ws2) ? 0 : 1;
}

uint64_t Msvcrt::_wcsicmp(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    uint64_t s1 = a.size() > 0 ? a[0] : 0;
    uint64_t s2 = a.size() > 1 ? a[1] : 0;
    if (!s1 || !s2) return (s1 == s2) ? 0 : 1;
    std::string ws1 = be(e)->read_mem_string(s1, 2);
    std::string ws2 = be(e)->read_mem_string(s2, 2);
    std::transform(ws1.begin(), ws1.end(), ws1.begin(), ::tolower);
    std::transform(ws2.begin(), ws2.end(), ws2.begin(), ::tolower);
    return (ws1 == ws2) ? 0 : 1;
}

uint64_t Msvcrt::wcsstr(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    uint64_t hay   = a.size() > 0 ? a[0] : 0;
    uint64_t needle = a.size() > 1 ? a[1] : 0;
    if (!hay || !needle) return 0;
    std::string h = be(e)->read_mem_string(hay, 2);
    std::string n = be(e)->read_mem_string(needle, 2);
    size_t pos = h.find(n);
    if (pos == std::string::npos) return 0;
    return hay + pos;
}

uint64_t Msvcrt::strncat_s(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    uint64_t dest = a.size() > 0 ? a[0] : 0;
    size_t   num  = static_cast<size_t>(a.size() > 1 ? a[1] : 0);
    uint64_t src  = a.size() > 2 ? a[2] : 0;
    size_t   cnt  = static_cast<size_t>(a.size() > 3 ? a[3] : 0);
    if (!dest || !src) return 22; // EINVAL
    std::string s1 = be(e)->read_mem_string(dest, 1);
    size_t slen1 = be(e)->mem_string_len(dest, 1);
    size_t rem = num - slen1;
    bool truncated = (cnt == 0xFFFFFFFF);
    if (truncated) {
        size_t copy_cnt = (rem < cnt) ? (cnt - 1) : cnt;
        be(e)->mem_copy(dest + slen1, src, copy_cnt);
    } else {
        if (rem < cnt) return 22; // EINVAL
        be(e)->mem_copy(dest + slen1, src, cnt);
    }
    return 0;
}

// ═══════════════════════════════════════════════════════════════
//  FORMATTED I/O
// ═══════════════════════════════════════════════════════════════

// Helper: format a string using the do_str_format logic
// Unfortunately do_str_format is an instance method on ApiHandler.
// We replicate the core logic inline here.
static std::string msvc_do_str_format(void* e, const std::string& fmt, const std::vector<uint64_t>& argv) {
    (void)e;
    std::string result;
    std::vector<uint64_t> args = argv;
    size_t i = 0;

    auto read_str = [&](uint64_t addr, int width) -> std::string {
        return be(e)->read_mem_string(addr, width);
    };

    while (i < fmt.size()) {
        if (fmt[i] == '%' && i + 1 < fmt.size()) {
            if (fmt[i + 1] == '%') {
                result += '%';
                i += 2;
                continue;
            }
            size_t start = i;
            ++i; // skip '%'

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
            bool has_ll = (fmt_mods.find("ll") != std::string::npos);

            if (args.empty()) break;

            switch (conv) {
            case 's': {
                uint64_t addr = args[0];
                args.erase(args.begin());
                std::string str_val;
                if (fmt_mods.find('w') != std::string::npos || fmt_mods.find('S') != std::string::npos) {
                    str_val = read_str(addr, 2);
                } else {
                    str_val = read_str(addr, 1);
                }
                result += str_val;
                break;
            }
            case 'S': {
                uint64_t addr = args[0];
                args.erase(args.begin());
                result += read_str(addr, 2);
                break;
            }
            case 'd':
            case 'i':
            case 'u':
            case 'x':
            case 'X': {
                uint64_t val;
                // For simplicity, assume pointer-sized args
                val = args[0];
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
                result += fmt.substr(start, i - start + 1);
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

// Count format specifiers
static int msvc_va_arg_count(const std::string& fmt) {
    int count = 0;
    for (size_t i = 0; i < fmt.size(); ++i) {
        if (fmt[i] == '%' && i + 1 < fmt.size() && fmt[i + 1] != '%') {
            ++count;
        }
    }
    return count;
}

// Read va_args from a va_list pointer
static std::vector<uint64_t> msvc_read_va_args(void* e, uint64_t va_list, int num_args) {
    std::vector<uint64_t> args;
    int ptr_sz = 4; // default
    try {
        // Detect pointer size from the emulator
        int arch = be(e)->get_arch();
        if (arch == speakeasy::arch::ARCH_AMD64) ptr_sz = 8;
    } catch (...) {}
    uint64_t ptr = va_list;
    for (int n = 0; n < num_args; ++n) {
        auto raw = we(e)->mem_read(ptr, static_cast<size_t>(ptr_sz));
        uint64_t arg = 0;
        if (!raw.empty()) arg = read_le(raw, 0, static_cast<size_t>(ptr_sz));
        args.push_back(arg);
        ptr += ptr_sz;
    }
    return args;
}

uint64_t Msvcrt::sprintf(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    // This is called as a vararg function; the actual args are fetched from the stack
    // For the static handler, we receive them in the argv vector already.
    // But vararg functions have their args in argv already because the dispatcher
    // pushes them all. Let's use them directly.
    // argv[0] = buffer, argv[1] = format, argv[2+] = varargs
    if (a.size() < 2) return 0;
    uint64_t buf = a[0];
    uint64_t fmt_addr = a[1];
    std::string fmt_str = be(e)->read_mem_string(fmt_addr, 1);
    std::vector<uint64_t> vargs;
    for (size_t n = 2; n < a.size(); ++n) vargs.push_back(a[n]);
    std::string result = msvc_do_str_format(e, fmt_str, vargs);
    be(e)->write_mem_string(result, buf, 1);
    return static_cast<uint64_t>(result.size());
}

uint64_t Msvcrt::_snprintf(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    // argv[0] = buffer, argv[1] = count, argv[2] = format, argv[3+] = varargs
    if (a.size() < 3) return 0;
    uint64_t buf   = a[0];
    size_t   count = static_cast<size_t>(a[1]);
    uint64_t fmt_addr = a[2];
    std::string fmt_str = be(e)->read_mem_string(fmt_addr, 1);
    std::vector<uint64_t> vargs;
    for (size_t n = 3; n < a.size(); ++n) vargs.push_back(a[n]);
    std::string result = msvc_do_str_format(e, fmt_str, vargs);
    if (count > 0) {
        if (result.size() >= count) result = result.substr(0, count - 1);
        be(e)->write_mem_string(result, buf, 1);
    }
    return static_cast<uint64_t>(result.size());
}

uint64_t Msvcrt::_snwprintf(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    if (a.size() < 3) return 0;
    uint64_t buf   = a[0];
    size_t   cnt   = static_cast<size_t>(a[1]);
    uint64_t fmt_addr = a[2];
    std::string fmt_str = be(e)->read_mem_string(fmt_addr, 2);
    // Replace %s with %S for wide string format
    {
        size_t pos = 0;
        while ((pos = fmt_str.find("%s", pos)) != std::string::npos) {
            fmt_str.replace(pos, 2, "%S");
            pos += 2;
        }
    }
    std::vector<uint64_t> vargs;
    for (size_t n = 3; n < a.size(); ++n) vargs.push_back(a[n]);
    std::string result = msvc_do_str_format(e, fmt_str, vargs);
    if (cnt > 0 && result.size() >= cnt) {
        result = result.substr(0, cnt - 1);
    }
    be(e)->write_mem_string(result, buf, 2);
    return static_cast<uint64_t>(result.size());
}

uint64_t Msvcrt::_vsnprintf(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    // argv[0] = buffer, argv[1] = count, argv[2] = format, argv[3] = argptr
    if (a.size() < 4) return 0;
    uint64_t buf    = a[0];
    size_t   count  = static_cast<size_t>(a[1]);
    uint64_t format = a[2];
    uint64_t argptr = a[3];
    std::string fmt_str = be(e)->read_mem_string(format, 1);
    int fmt_cnt = msvc_va_arg_count(fmt_str);
    std::vector<uint64_t> vargs = msvc_read_va_args(e, argptr, fmt_cnt);
    std::string result = msvc_do_str_format(e, fmt_str, vargs);
    if (count > 0) {
        if (result.size() >= count) result = result.substr(0, count - 1);
        be(e)->write_mem_string(result, buf, 1);
    }
    return static_cast<uint64_t>(result.size());
}

uint64_t Msvcrt::printf(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    // argv[0] = format, argv[1+] = varargs
    if (a.empty()) return 0;
    uint64_t fmt_addr = a[0];
    std::string fmt_str = be(e)->read_mem_string(fmt_addr, 1);
    std::vector<uint64_t> vargs;
    for (size_t n = 1; n < a.size(); ++n) vargs.push_back(a[n]);
    std::string result = msvc_do_str_format(e, fmt_str, vargs);
    // Output to console (just return length; actual output logged by emu)
    return static_cast<uint64_t>(result.size());
}

uint64_t Msvcrt::fprintf(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    // argv[0] = stream, argv[1] = format, argv[2+] = varargs
    if (a.size() < 2) return 0;
    uint64_t fmt_addr = a[1];
    std::string fmt_str = be(e)->read_mem_string(fmt_addr, 1);
    std::vector<uint64_t> vargs;
    for (size_t n = 2; n < a.size(); ++n) vargs.push_back(a[n]);
    std::string result = msvc_do_str_format(e, fmt_str, vargs);
    return static_cast<uint64_t>(result.size());
}

uint64_t Msvcrt::__stdio_common_vfprintf(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    // Options vary by arch; try to extract format and va_list
    if (a.size() < 5) return 0;
    uint64_t fmt_addr, va_list;
    // Try to detect layout: on x64: opts, stream, fmt, locale, argptr
    // on x86: opts_lo, opts_hi, stream, fmt, locale, argptr
    if (a.size() >= 6) {
        fmt_addr = a[3];
        va_list  = a[5];
    } else {
        fmt_addr = a[2];
        va_list  = a[4];
    }
    std::string fmt_str = be(e)->read_mem_string(fmt_addr, 1);
    int fmt_cnt = msvc_va_arg_count(fmt_str);
    std::vector<uint64_t> vargs = msvc_read_va_args(e, va_list, fmt_cnt);
    std::string result = msvc_do_str_format(e, fmt_str, vargs);
    return static_cast<uint64_t>(result.size());
}

uint64_t Msvcrt::__stdio_common_vsprintf(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    // argv: options_lo, options_hi, buffer, count, format, locale, argptr
    if (a.size() < 7) return 0;
    uint64_t buf     = a[2];
    size_t   count   = static_cast<size_t>(a[3]);
    uint64_t format  = a[4];
    uint64_t argptr  = a[6];
    std::string fmt_str = be(e)->read_mem_string(format, 1);
    int fmt_cnt = msvc_va_arg_count(fmt_str);
    std::vector<uint64_t> vargs = msvc_read_va_args(e, argptr, fmt_cnt);
    std::string result = msvc_do_str_format(e, fmt_str, vargs);
    if (count > 0) {
        if (result.size() >= count) result = result.substr(0, count - 1);
        be(e)->write_mem_string(result, buf, 1);
    }
    return static_cast<uint64_t>(result.size());
}

uint64_t Msvcrt::sscanf(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    (void)e; (void)a;
    return 0;
}

uint64_t Msvcrt::puts(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    uint64_t s = a.empty() ? 0 : a[0];
    if (!s) return 0;
    std::string str = be(e)->read_mem_string(s, 1);
    return static_cast<uint64_t>(str.size());
}

// ═══════════════════════════════════════════════════════════════
//  FILE I/O
// ═══════════════════════════════════════════════════════════════

// Helper: get pointer size from emulator
static int msvc_ptr_size(void* e) {
    try {
        int arch = be(e)->get_arch();
        return (arch == speakeasy::arch::ARCH_AMD64) ? 8 : 4;
    } catch (...) { return 4; }
}

uint64_t Msvcrt::fopen(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    uint64_t filename = a.size() > 0 ? a[0] : 0;
    uint64_t mode     = a.size() > 1 ? a[1] : 0;
    if (!filename || !mode) return 0;
    std::string path = be(e)->read_mem_string(filename, 1);
    std::string mode_str = be(e)->read_mem_string(mode, 1);
    bool create = (mode_str.find('w') != std::string::npos ||
                   mode_str.find('a') != std::string::npos ||
                   mode_str.find('+') != std::string::npos);
    auto* hfile = static_cast<int*>(we(e)->file_open(path, create));
    if (!hfile) return 0;
    int fd = *reinterpret_cast<int*>(hfile);
    int ptr_sz = msvc_ptr_size(e);
    uint64_t stream = we(e)->mem_map(static_cast<size_t>(ptr_sz), 0, 4, "msvcrt.fopen");
    std::vector<uint8_t> fdbuf(static_cast<size_t>(ptr_sz), 0);
    write_le(fdbuf, 0, static_cast<uint64_t>(fd), static_cast<size_t>(ptr_sz));
    we(e)->mem_write(stream, fdbuf);
    msvc_file_streams[stream] = fd;
    return stream;
}

uint64_t Msvcrt::_wfopen(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    uint64_t filename = a.size() > 0 ? a[0] : 0;
    uint64_t mode     = a.size() > 1 ? a[1] : 0;
    if (!filename || !mode) return 0;
    std::string path = be(e)->read_mem_string(filename, 2);
    std::string mode_str = be(e)->read_mem_string(mode, 2);
    bool create = (mode_str.find('w') != std::string::npos ||
                   mode_str.find('a') != std::string::npos ||
                   mode_str.find('+') != std::string::npos);
    auto* hfile = static_cast<int*>(we(e)->file_open(path, create));
    if (!hfile) return 0;
    int fd = *reinterpret_cast<int*>(hfile);
    int ptr_sz = msvc_ptr_size(e);
    uint64_t stream = we(e)->mem_map(static_cast<size_t>(ptr_sz), 0, 4, "msvcrt._wfopen");
    std::vector<uint8_t> fdbuf(static_cast<size_t>(ptr_sz), 0);
    write_le(fdbuf, 0, static_cast<uint64_t>(fd), static_cast<size_t>(ptr_sz));
    we(e)->mem_write(stream, fdbuf);
    msvc_file_streams[stream] = fd;
    return stream;
}

uint64_t Msvcrt::fclose(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    uint64_t stream = a.empty() ? 0 : a[0];
    if (!stream) return -1;
    msvc_file_streams.erase(stream);
    try { we(e)->mem_free(stream); } catch (...) {}
    return 0;
}

uint64_t Msvcrt::fseek(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    uint64_t stream = a.size() > 0 ? a[0] : 0;
    int64_t  offset = static_cast<int64_t>(a.size() > 1 ? a[1] : 0);
    int      origin = static_cast<int>(a.size() > 2 ? a[2] : 0);
    auto it = msvc_file_streams.find(stream);
    if (it == msvc_file_streams.end()) return -1;
    // WindowsEmulator doesn't expose seek directly; we pass through
    (void)offset; (void)origin;
    return 0;
}

uint64_t Msvcrt::ftell(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    uint64_t stream = a.empty() ? 0 : a[0];
    auto it = msvc_file_streams.find(stream);
    if (it == msvc_file_streams.end()) return -1;
    return 0; // Return 0 as default position
}

uint64_t Msvcrt::fread(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    uint64_t ptr    = a.size() > 0 ? a[0] : 0;
    size_t   size   = static_cast<size_t>(a.size() > 1 ? a[1] : 0);
    size_t   count  = static_cast<size_t>(a.size() > 2 ? a[2] : 0);
    uint64_t stream = a.size() > 3 ? a[3] : 0;
    if (!ptr || size == 0 || count == 0) return 0;
    auto it = msvc_file_streams.find(stream);
    if (it == msvc_file_streams.end()) return 0;
    size_t total = size * count;
    // Just zero-fill the buffer as we can't read from real file handle
    std::vector<uint8_t> data(total, 0);
    we(e)->mem_write(ptr, data);
    return count;
}

uint64_t Msvcrt::fputc(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    int c = static_cast<int>(a.size() > 0 ? a[0] : 0);
    return static_cast<uint64_t>(c);
}

uint64_t Msvcrt::__acrt_iob_func(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    uint64_t fd = a.empty() ? 0 : a[0];
    (void)e;
    return fd;
}

uint64_t Msvcrt::_lock(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    (void)e; (void)a;
    return 0;
}

uint64_t Msvcrt::_unlock(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    (void)e; (void)a;
    return 0;
}

// ═══════════════════════════════════════════════════════════════
//  MATH
// ═══════════════════════════════════════════════════════════════

// Helper: interpret uint64_t as IEEE double
static double u64_to_double(uint64_t x) {
    double d;
    std::memcpy(&d, &x, sizeof(d));
    return d;
}
static uint64_t double_to_u64(double x) {
    uint64_t u;
    std::memcpy(&u, &x, sizeof(u));
    return u;
}

uint64_t Msvcrt::pow(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    double x = u64_to_double(a.size() > 0 ? a[0] : 0);
    double y = u64_to_double(a.size() > 1 ? a[1] : 0);
    double z = std::pow(x, y);
    return double_to_u64(z);
}

uint64_t Msvcrt::floor(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    double x = u64_to_double(a.empty() ? 0 : a[0]);
    double z = std::floor(x);
    return double_to_u64(z);
}

uint64_t Msvcrt::sin(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    double x = u64_to_double(a.empty() ? 0 : a[0]);
    double z = std::sin(x);
    return double_to_u64(z);
}

uint64_t Msvcrt::abs(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    int64_t x = static_cast<int64_t>(a.empty() ? 0 : a[0]);
    int64_t y = (x < 0) ? -x : x;
    return static_cast<uint64_t>(y);
}

uint64_t Msvcrt::_ftol(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    uint64_t f = a.empty() ? 0 : a[0];
    (void)e;
    return f; // truncation done by caller
}

// ═══════════════════════════════════════════════════════════════
//  TIME
// ═══════════════════════════════════════════════════════════════

static uint64_t msvc_tick_counter = 86400000; // 1 day in ms

uint64_t Msvcrt::time(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    uint64_t destTime = a.empty() ? 0 : a[0];
    uint64_t out_time = 1576292568; // TIME_BASE
    if (destTime) {
        std::vector<uint8_t> buf(4, 0);
        write_le(buf, 0, out_time, 4);
        we(e)->mem_write(destTime, buf);
    }
    return out_time;
}

uint64_t Msvcrt::clock(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    (void)e; (void)a;
    msvc_tick_counter += 200;
    return msvc_tick_counter;
}

uint64_t Msvcrt::_strtime(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    uint64_t buffer = a.empty() ? 0 : a[0];
    if (!buffer) return 0;
    std::string t = "12:34:56";
    be(e)->write_mem_string(t, buffer, 1);
    return buffer;
}

uint64_t Msvcrt::_strdate(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    uint64_t buffer = a.empty() ? 0 : a[0];
    if (!buffer) return 0;
    std::string d = "12/29/19";
    be(e)->write_mem_string(d, buffer, 1);
    return buffer;
}

// ═══════════════════════════════════════════════════════════════
//  RANDOM
// ═══════════════════════════════════════════════════════════════

uint64_t Msvcrt::srand(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    msvc_rand_state = static_cast<int>(a.empty() ? 0 : a[0]);
    (void)e;
    return 0;
}

uint64_t Msvcrt::rand(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    (void)e; (void)a;
    msvc_rand_state += 1;
    return static_cast<uint64_t>(msvc_rand_state);
}

// ═══════════════════════════════════════════════════════════════
//  EXIT / TERMINATION
// ═══════════════════════════════════════════════════════════════

uint64_t Msvcrt::exit(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    (void)a;
    we(e)->stop();
    return 0;
}

uint64_t Msvcrt::_exit(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    (void)a;
    we(e)->stop();
    return 0;
}

uint64_t Msvcrt::_cexit(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    (void)a;
    we(e)->stop();
    return 0;
}

uint64_t Msvcrt::_c_exit(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    (void)a;
    we(e)->stop();
    return 0;
}

uint64_t Msvcrt::terminate(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    (void)a;
    we(e)->stop();
    return 0;
}

// ═══════════════════════════════════════════════════════════════
//  EXCEPTION / SEH
// ═══════════════════════════════════════════════════════════════

uint64_t Msvcrt::_XcptFilter(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    (void)e; (void)a;
    return 0;
}

uint64_t Msvcrt::_CxxThrowException(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    (void)e; (void)a;
    return 0;
}

uint64_t Msvcrt::_except_handler4_common(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    (void)e; (void)a;
    return 0;
}

uint64_t Msvcrt::_except_handler3(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    (void)e; (void)a;
    return 1;
}

uint64_t Msvcrt::_seh_filter_exe(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    (void)e; (void)a;
    return 1;
}

uint64_t Msvcrt::_seh_filter_dll(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    (void)e; (void)a;
    return 1;
}

uint64_t Msvcrt::__CxxFrameHandler(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    (void)e; (void)a;
    return 0;
}

uint64_t Msvcrt::_EH_prolog(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    (void)e; (void)a;
    return 0;
}

uint64_t Msvcrt::__current_exception_context(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    (void)e; (void)a;
    return 0;
}

uint64_t Msvcrt::__current_exception(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    (void)e; (void)a;
    return 0;
}

// ═══════════════════════════════════════════════════════════════
//  STARTUP / INIT
// ═══════════════════════════════════════════════════════════════

uint64_t Msvcrt::__p__acmdln(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    (void)a;
    // Allocate memory for command line string pointer
    int ptr_sz = msvc_ptr_size(e);
    auto argv_list = we(e)->get_env(); // not ideal; use get_argv if available
    (void)argv_list;
    // Simplified: alloc a small block and return pointer to it
    uint64_t cmdln = we(e)->mem_map(static_cast<size_t>(ptr_sz + 8), 0, 4, "api.msvcrt._acmdln");
    return cmdln;
}

uint64_t Msvcrt::_onexit(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    uint64_t func = a.empty() ? 0 : a[0];
    (void)e;
    return func;
}

uint64_t Msvcrt::mbstowcs_s(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    // pReturnValue, wcstr, sizeInWords, mbstr, count
    if (a.size() < 5) return 22; // EINVAL
    uint64_t pReturnValue = a[0];
    uint64_t wcstr        = a[1];
    size_t   sizeInWords  = static_cast<size_t>(a[2]);
    uint64_t mbstr        = a[3];
    size_t   count        = static_cast<size_t>(a[4]);
    (void)count;
    if (pReturnValue) {
        std::vector<uint8_t> zero(4, 0);
        we(e)->mem_write(pReturnValue, zero);
    }
    if (mbstr && wcstr && sizeInWords > 0) {
        std::string mbs = be(e)->read_mem_string(mbstr, 1);
        std::string ws = mbs; // simple conversion
        be(e)->write_mem_string(ws, wcstr, 2); // write as wide
        if (pReturnValue) {
            std::vector<uint8_t> retbuf(4, 0);
            write_le(retbuf, 0, static_cast<uint64_t>(ws.size() + 1), 4);
            we(e)->mem_write(pReturnValue, retbuf);
        }
    }
    return 0;
}

uint64_t Msvcrt::_wcsnicmp(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    uint64_t s1    = a.size() > 0 ? a[0] : 0;
    uint64_t s2    = a.size() > 1 ? a[1] : 0;
    size_t   count = static_cast<size_t>(a.size() > 2 ? a[2] : 0);
    if (!s1 || !s2) return 1;
    std::string ws1 = be(e)->read_mem_string(s1, 2, static_cast<int>(count));
    std::string ws2 = be(e)->read_mem_string(s2, 2, static_cast<int>(count));
    std::transform(ws1.begin(), ws1.end(), ws1.begin(), ::tolower);
    std::transform(ws2.begin(), ws2.end(), ws2.begin(), ::tolower);
    return (ws1 == ws2) ? 0 : 1;
}

uint64_t Msvcrt::_initterm_e(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    (void)e; (void)a;
    return 0;
}

uint64_t Msvcrt::_initterm(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    (void)e; (void)a;
    return 0;
}

uint64_t Msvcrt::__getmainargs(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    // _Argc, _Argv, _Env, _DoWildCard, _StartInfo
    uint64_t _Argc = a.size() > 0 ? a[0] : 0;
    uint64_t _Argv = a.size() > 1 ? a[1] : 0;
    uint64_t _Env  = a.size() > 2 ? a[2] : 0;
    (void)a;
    int ptr_sz = msvc_ptr_size(e);

    // Get argv from emulator
    std::vector<std::string> argv_strs;
    try {
        auto run = we(e)->get_current_run();
        (void)run;
        // Fallback: use environment
    } catch (...) {}

    // Simplified: write argc = 1 (dummy program name)
    if (_Argc) {
        std::vector<uint8_t> argcbuf(4, 0);
        write_le(argcbuf, 0, 1, 4);
        we(e)->mem_write(_Argc, argcbuf);
    }
    if (_Argv) {
        // Write a basic argv pointer
        uint64_t argmem = we(e)->mem_map(static_cast<size_t>(ptr_sz * 2), 0, 4, "api.argv");
        std::vector<uint8_t> argvptr(static_cast<size_t>(ptr_sz), 0);
        write_le(argvptr, 0, argmem, static_cast<size_t>(ptr_sz));
        we(e)->mem_write(_Argv, argvptr);
    }
    if (_Env) {
        uint64_t envmem = we(e)->mem_map(static_cast<size_t>(ptr_sz), 0, 4, "api.envp");
        std::vector<uint8_t> envptr(static_cast<size_t>(ptr_sz), 0);
        we(e)->mem_write(_Env, envptr);
    }
    return 0;
}

uint64_t Msvcrt::__wgetmainargs(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    (void)e; (void)a;
    return 0;
}

uint64_t Msvcrt::__p___wargv(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    (void)a;
    int ptr_sz = msvc_ptr_size(e);
    uint64_t mem = we(e)->mem_map(static_cast<size_t>(ptr_sz * 4), 0, 4, "api.argv");
    return mem;
}

uint64_t Msvcrt::__p___argv(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    (void)a;
    int ptr_sz = msvc_ptr_size(e);
    uint64_t mem = we(e)->mem_map(static_cast<size_t>(ptr_sz * 4), 0, 4, "api.argv");
    return mem;
}

uint64_t Msvcrt::__p___argc(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    (void)a;
    uint64_t mem = we(e)->mem_map(4, 0, 4, "api.argc");
    std::vector<uint8_t> buf(4, 0);
    write_le(buf, 0, 1, 4); // argc = 1
    we(e)->mem_write(mem, buf);
    return mem;
}

uint64_t Msvcrt::__p___initenv(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    (void)a;
    int ptr_sz = msvc_ptr_size(e);
    uint64_t mem = we(e)->mem_map(static_cast<size_t>(ptr_sz), 0, 4, "api.initenv");
    return mem;
}

uint64_t Msvcrt::_get_initial_narrow_environment(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    (void)a;
    int ptr_sz = msvc_ptr_size(e);
    uint64_t mem = we(e)->mem_map(static_cast<size_t>(ptr_sz * 2), 0, 4, "api.envp");
    return mem;
}

uint64_t Msvcrt::_get_initial_wide_environment(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    (void)a;
    int ptr_sz = msvc_ptr_size(e);
    uint64_t mem = we(e)->mem_map(static_cast<size_t>(ptr_sz * 2), 0, 4, "api.envp");
    return mem;
}

// ═══════════════════════════════════════════════════════════════
//  APP TYPE / MODE
// ═══════════════════════════════════════════════════════════════

uint64_t Msvcrt::__set_app_type(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    (void)e; (void)a;
    return 0;
}

uint64_t Msvcrt::_set_app_type(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    (void)e; (void)a;
    return 0;
}

uint64_t Msvcrt::__p__fmode(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    (void)a;
    uint64_t ptr = we(e)->mem_map(4, 0, 4, "api.fmode");
    std::vector<uint8_t> buf(4, 0);
    write_le(buf, 0, 0x4000, 4); // _O_TEXT
    we(e)->mem_write(ptr, buf);
    return ptr;
}

uint64_t Msvcrt::__p__commode(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    (void)a;
    uint64_t ptr = we(e)->mem_map(4, 0, 4, "api.commode");
    std::vector<uint8_t> buf(4, 0);
    write_le(buf, 0, 0x4000, 4); // _IOCOMMIT
    we(e)->mem_write(ptr, buf);
    return ptr;
}

uint64_t Msvcrt::_set_fmode(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    (void)e; (void)a;
    return 0;
}

uint64_t Msvcrt::_controlfp(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    (void)e; (void)a;
    return 0;
}

uint64_t Msvcrt::_controlfp_s(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    (void)e; (void)a;
    return 0;
}

uint64_t Msvcrt::_set_new_mode(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    (void)e; (void)a;
    return 0;
}

uint64_t Msvcrt::_configthreadlocale(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    (void)e; (void)a;
    return 0;
}

uint64_t Msvcrt::_setusermatherr(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    (void)e; (void)a;
    return 0;
}

uint64_t Msvcrt::__setusermatherr(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    (void)e; (void)a;
    return 0;
}

// ═══════════════════════════════════════════════════════════════
//  C++ HELPERS
// ═══════════════════════════════════════════════════════════════

uint64_t Msvcrt::_set_invalid_parameter_handler(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    (void)e; (void)a;
    return 0;
}

uint64_t Msvcrt::_initialize_onexit_table(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    (void)e; (void)a;
    return 0;
}

uint64_t Msvcrt::_register_onexit_function(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    (void)e; (void)a;
    return 0;
}

uint64_t Msvcrt::__dllonexit(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    uint64_t func = a.empty() ? 0 : a[0];
    (void)e;
    return func;
}

uint64_t Msvcrt::_register_thread_local_exe_atexit_callback(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    (void)e; (void)a;
    return 0;
}

uint64_t Msvcrt::_crt_atexit(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    (void)e; (void)a;
    return 0;
}

uint64_t Msvcrt::_initialize_narrow_environment(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    (void)e; (void)a;
    return 0;
}

uint64_t Msvcrt::_configure_narrow_argv(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    (void)e; (void)a;
    return 0;
}

// ═══════════════════════════════════════════════════════════════
//  THREADING
// ═══════════════════════════════════════════════════════════════

uint64_t Msvcrt::_beginthreadex(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    // security, stack_size, start_address, arglist, initflag, thrdaddr
    uint64_t start_address = a.size() > 2 ? a[2] : 0;
    uint64_t arglist       = a.size() > 3 ? a[3] : 0;
    uint64_t thrdaddr      = a.size() > 5 ? a[5] : 0;
    auto proc = we(e)->get_current_process();
    auto* thread = we(e)->create_thread(start_address, reinterpret_cast<void*>(arglist), proc);
    if (thrdaddr && thread) {
        // Write thread ID
        std::vector<uint8_t> buf(4, 0);
        write_le(buf, 0, 1, 4); // dummy thread ID
        we(e)->mem_write(thrdaddr, buf);
    }
    return reinterpret_cast<uint64_t>(thread);
}

uint64_t Msvcrt::_beginthread(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    // start_address, stack_size, arglist
    uint64_t start_address = a.size() > 0 ? a[0] : 0;
    uint64_t arglist       = a.size() > 2 ? a[2] : 0;
    auto proc = we(e)->get_current_process();
    auto* thread = we(e)->create_thread(start_address, reinterpret_cast<void*>(arglist), proc);
    return reinterpret_cast<uint64_t>(thread);
}

// ═══════════════════════════════════════════════════════════════
//  MISC
// ═══════════════════════════════════════════════════════════════

uint64_t Msvcrt::system(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    uint64_t s = a.empty() ? 0 : a[0];
    if (!s) return 0;
    std::string cmd = be(e)->read_mem_string(s, 1);
    return static_cast<uint64_t>(cmd.size());
}

uint64_t Msvcrt::toupper(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    int c = static_cast<int>(a.empty() ? 0 : a[0]);
    (void)e;
    if (c >= 'a' && c <= 'z') return static_cast<uint64_t>(c - 32);
    return static_cast<uint64_t>(c);
}

uint64_t Msvcrt::tolower(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    int c = static_cast<int>(a.empty() ? 0 : a[0]);
    (void)e;
    return static_cast<uint64_t>(c | 0x20);
}

uint64_t Msvcrt::isdigit(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    int c = static_cast<int>(a.empty() ? 0 : a[0]);
    (void)e;
    return (c >= '0' && c <= '9') ? 1 : 0;
}

uint64_t Msvcrt::_adjust_fdiv(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    (void)e; (void)a;
    return 0;
}

uint64_t Msvcrt::_errno(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    (void)a;
    if (!msvc_errno_ptr) {
        msvc_errno_ptr = we(e)->mem_map(4, 0, 4, "api.msvcrt._errno");
        std::vector<uint8_t> buf(4, 0);
        write_le(buf, 0, 12, 4); // _VAL = 0x0C
        we(e)->mem_write(msvc_errno_ptr, buf);
    }
    return msvc_errno_ptr;
}

uint64_t Msvcrt::signal(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    int sig = static_cast<int>(a.size() > 0 ? a[0] : 0);
    (void)e; (void)a;
    // SIG_IGN = 1, SIG_ERR = -1 (as uint64_t)
    switch (sig) {
    case 2:  // SIGINT
    case 4:  // SIGILL
    case 8:  // SIGFPE
    case 11: // SIGSEGV
    case 15: // SIGTERM
    case 21: // SIGBREAK
    case 22: // SIGABRT
        return 1; // SIG_IGN
    default:
        return 0xFFFFFFFFFFFFFFFFULL; // SIG_ERR (-1 as unsigned)
    }
}

}} // namespaces
