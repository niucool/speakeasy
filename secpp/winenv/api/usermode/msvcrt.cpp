// msvcrt.cpp — msvcrt.dll handler (~120 APIs, all stubs)
#include "msvcrt.h"

namespace speakeasy { namespace api {

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

// ── Bulk stubs ──────────────────────────────────────────────

#define MSVC_STUB(n) STUB(Msvcrt, n)

MSVC_STUB(__p__acmdln)       MSVC_STUB(_onexit)
MSVC_STUB(mbstowcs_s)        MSVC_STUB(_wcsnicmp)
MSVC_STUB(_initterm_e)       MSVC_STUB(_initterm)
MSVC_STUB(__getmainargs)     MSVC_STUB(__wgetmainargs)
MSVC_STUB(__p___wargv)       MSVC_STUB(__p___argv)
MSVC_STUB(__p___argc)        MSVC_STUB(__p___initenv)
MSVC_STUB(_get_initial_narrow_environment)
MSVC_STUB(_get_initial_wide_environment)

MSVC_STUB(exit)              MSVC_STUB(_exit)
MSVC_STUB(_cexit)            MSVC_STUB(_c_exit)
MSVC_STUB(terminate)

MSVC_STUB(_XcptFilter)       MSVC_STUB(_CxxThrowException)
MSVC_STUB(_except_handler4_common) MSVC_STUB(_except_handler3)
MSVC_STUB(_seh_filter_exe)   MSVC_STUB(_seh_filter_dll)
MSVC_STUB(__CxxFrameHandler) MSVC_STUB(_EH_prolog)
MSVC_STUB(__current_exception_context) MSVC_STUB(__current_exception)

MSVC_STUB(__acrt_iob_func)   MSVC_STUB(__stdio_common_vfprintf)
MSVC_STUB(__stdio_common_vsprintf) MSVC_STUB(fprintf)
MSVC_STUB(printf)            MSVC_STUB(sprintf)
MSVC_STUB(_snprintf)         MSVC_STUB(_snwprintf)
MSVC_STUB(_vsnprintf)        MSVC_STUB(sscanf)
MSVC_STUB(puts)              MSVC_STUB(fopen)
MSVC_STUB(_wfopen)           MSVC_STUB(fclose)
MSVC_STUB(fseek)             MSVC_STUB(ftell)
MSVC_STUB(fread)             MSVC_STUB(fputc)
MSVC_STUB(_lock)             MSVC_STUB(_unlock)

MSVC_STUB(memset)            MSVC_STUB(memcpy)
MSVC_STUB(memmove)           MSVC_STUB(memcmp)
MSVC_STUB(malloc)            MSVC_STUB(calloc)
MSVC_STUB(free)

MSVC_STUB(strcpy)            MSVC_STUB(wcscpy)
MSVC_STUB(strncpy)           MSVC_STUB(wcsncpy)
MSVC_STUB(strcat)            MSVC_STUB(wcscat)
MSVC_STUB(strncat)           MSVC_STUB(strncat_s)
MSVC_STUB(strlen)            MSVC_STUB(wcslen)
MSVC_STUB(strcmp)            MSVC_STUB(wcscmp)
MSVC_STUB(strncmp)           MSVC_STUB(_strcmpi)
MSVC_STUB(_stricmp)          MSVC_STUB(_strnicmp)
MSVC_STUB(_wcsicmp)          MSVC_STUB(strstr)
MSVC_STUB(wcsstr)            MSVC_STUB(strchr)
MSVC_STUB(strrchr)           MSVC_STUB(_strlwr)
MSVC_STUB(atoi)              MSVC_STUB(_ltoa)
MSVC_STUB(_itoa)             MSVC_STUB(_itow)
MSVC_STUB(wcstombs)

MSVC_STUB(pow)               MSVC_STUB(floor)
MSVC_STUB(sin)               MSVC_STUB(abs)
MSVC_STUB(_ftol)

MSVC_STUB(time)              MSVC_STUB(clock)
MSVC_STUB(_strtime)          MSVC_STUB(_strdate)

MSVC_STUB(rand)              MSVC_STUB(srand)

MSVC_STUB(__set_app_type)    MSVC_STUB(_set_app_type)
MSVC_STUB(__p__fmode)        MSVC_STUB(__p__commode)
MSVC_STUB(_set_fmode)        MSVC_STUB(_controlfp)
MSVC_STUB(_controlfp_s)      MSVC_STUB(_set_new_mode)
MSVC_STUB(_configthreadlocale) MSVC_STUB(_setusermatherr)
MSVC_STUB(__setusermatherr)

MSVC_STUB(_set_invalid_parameter_handler)
MSVC_STUB(_initialize_onexit_table) MSVC_STUB(_register_onexit_function)
MSVC_STUB(__dllonexit)
MSVC_STUB(_register_thread_local_exe_atexit_callback)
MSVC_STUB(_crt_atexit)
MSVC_STUB(_initialize_narrow_environment) MSVC_STUB(_configure_narrow_argv)

MSVC_STUB(_beginthreadex)    MSVC_STUB(_beginthread)

MSVC_STUB(system)            MSVC_STUB(toupper)
MSVC_STUB(tolower)           MSVC_STUB(isdigit)
MSVC_STUB(_adjust_fdiv)      MSVC_STUB(_errno)
MSVC_STUB(signal)

}} // namespaces
