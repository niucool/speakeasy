// msvcrt.h  msvcrt.dll API handler (C runtime, ~120 APIs)
#ifndef SPEAKEASY_MSVCRT_H
#define SPEAKEASY_MSVCRT_H
#include <string>
#include <vector>
#include "../api.h"

namespace speakeasy { namespace api {

class Msvcrt : public ApiHandler {
    API_LIST_BEGIN
    // Startup / init
    API_ENTRY(__p__acmdln, 0)                API_ENTRY(_onexit, 1)
    API_ENTRY(mbstowcs_s, 5)                 API_ENTRY(_wcsnicmp, 3)
    API_ENTRY(_initterm_e, 2)                API_ENTRY(_initterm, 2)
    API_ENTRY(__getmainargs, 5)              API_ENTRY(__wgetmainargs, 5)
    API_ENTRY(__p___wargv, 0)                API_ENTRY(__p___argv, 0)
    API_ENTRY(__p___argc, 0)                 API_ENTRY(__p___initenv, 0)
    API_ENTRY(_get_initial_narrow_environment, 0) API_ENTRY(_get_initial_wide_environment, 0)
    // Exit / termination
    API_ENTRY(exit, 1)                       API_ENTRY(_exit, 1)
    API_ENTRY(_cexit, 0)                     API_ENTRY(_c_exit, 0)
    API_ENTRY(terminate, 1)
    // Exception / SEH
    API_ENTRY(_XcptFilter, 2)                API_ENTRY(_CxxThrowException, 2)
    API_ENTRY(_except_handler4_common, 6)    API_ENTRY(_except_handler3, 4)
    API_ENTRY(_seh_filter_exe, 2)            API_ENTRY(_seh_filter_dll, 2)
    API_ENTRY(__CxxFrameHandler, 4)          API_ENTRY(_EH_prolog, 0)
    API_ENTRY(__current_exception_context, 0) API_ENTRY(__current_exception, 0)
    // I/O
    API_ENTRY(__acrt_iob_func, 1)            API_ENTRY(__stdio_common_vfprintf, 0)
    API_ENTRY(__stdio_common_vsprintf, 7)    API_ENTRY(fprintf, 0)
    API_ENTRY(printf, 0)                     API_ENTRY(sprintf, 0)
    API_ENTRY(_snprintf, 0)                  API_ENTRY(_snwprintf, 0)
    API_ENTRY(_vsnprintf, 4)                 API_ENTRY(sscanf, 0)
    API_ENTRY(puts, 1)                       API_ENTRY(fopen, 2)
    API_ENTRY(_wfopen, 2)                    API_ENTRY(fclose, 1)
    API_ENTRY(fseek, 3)                      API_ENTRY(ftell, 1)
    API_ENTRY(fread, 4)                      API_ENTRY(fputc, 2)
    API_ENTRY(_lock, 1)                      API_ENTRY(_unlock, 1)
    // Memory
    API_ENTRY(memset, 3)                     API_ENTRY(memcpy, 3)
    API_ENTRY(memmove, 3)                    API_ENTRY(memcmp, 3)
    API_ENTRY(malloc, 1)                     API_ENTRY(calloc, 2)
    API_ENTRY(free, 1)
    // String
    API_ENTRY(strcpy, 2)                     API_ENTRY(wcscpy, 2)
    API_ENTRY(strncpy, 3)                    API_ENTRY(wcsncpy, 3)
    API_ENTRY(strcat, 2)                     API_ENTRY(wcscat, 2)
    API_ENTRY(strncat, 3)                    API_ENTRY(strncat_s, 4)
    API_ENTRY(strlen, 1)                     API_ENTRY(wcslen, 1)
    API_ENTRY(strcmp, 2)                     API_ENTRY(wcscmp, 2)
    API_ENTRY(strncmp, 3)                    API_ENTRY(_strcmpi, 2)
    API_ENTRY(_stricmp, 2)                   API_ENTRY(_strnicmp, 3)
    API_ENTRY(_wcsicmp, 2)                   API_ENTRY(strstr, 2)
    API_ENTRY(wcsstr, 2)                     API_ENTRY(strchr, 2)
    API_ENTRY(strrchr, 2)                    API_ENTRY(_strlwr, 1)
    API_ENTRY(atoi, 1)                       API_ENTRY(_ltoa, 3)
    API_ENTRY(_itoa, 3)                      API_ENTRY(_itow, 3)
    API_ENTRY(wcstombs, 3)
    // Math
    API_ENTRY(pow, 2)                        API_ENTRY(floor, 1)
    API_ENTRY(sin, 1)                        API_ENTRY(abs, 1)
    API_ENTRY(_ftol, 1)
    // Time
    API_ENTRY(time, 1)                       API_ENTRY(clock, 0)
    API_ENTRY(_strtime, 1)                   API_ENTRY(_strdate, 1)
    // Random
    API_ENTRY(rand, 0)                       API_ENTRY(srand, 1)
    // App type / mode
    API_ENTRY(__set_app_type, 1)             API_ENTRY(_set_app_type, 1)
    API_ENTRY(__p__fmode, 0)                 API_ENTRY(__p__commode, 0)
    API_ENTRY(_set_fmode, 1)                 API_ENTRY(_controlfp, 2)
    API_ENTRY(_controlfp_s, 3)               API_ENTRY(_set_new_mode, 1)
    API_ENTRY(_configthreadlocale, 1)        API_ENTRY(_setusermatherr, 1)
    API_ENTRY(__setusermatherr, 1)
    // C++ helpers
    API_ENTRY(_set_invalid_parameter_handler, 1)
    API_ENTRY(_initialize_onexit_table, 1)   API_ENTRY(_register_onexit_function, 2)
    API_ENTRY(__dllonexit, 3)
    API_ENTRY(_register_thread_local_exe_atexit_callback, 1)
    API_ENTRY(_crt_atexit, 1)
    API_ENTRY(_initialize_narrow_environment, 0)
    API_ENTRY(_configure_narrow_argv, 1)
    // Threading
    API_ENTRY(_beginthreadex, 6)             API_ENTRY(_beginthread, 3)
    // Misc
    API_ENTRY(system, 1)                     API_ENTRY(toupper, 1)
    API_ENTRY(tolower, 1)                    API_ENTRY(isdigit, 1)
    API_ENTRY(_adjust_fdiv, 0)               API_ENTRY(_errno, 0)
    API_ENTRY(signal, 2)
    API_LIST_END

public:
    Msvcrt(void* emu);
    std::string get_name() const override { return "msvcrt"; }
    const std::vector<ApiEntry>& get_apis() const override { return apis_; }
};

}} // namespaces
#endif
