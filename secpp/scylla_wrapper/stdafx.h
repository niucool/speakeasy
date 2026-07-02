#pragma once

#include "targetver.h"

#ifdef _WIN32X
// Windows: use the real SDK types
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <imagehlp.h>
#else
// Linux / non-MSVC: use our portable replacement
#include "platform_linux.h"
#endif

// Stubs needed on top of the real SDK (Windows only).
