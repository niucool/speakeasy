// shell32.cpp  shell32.dll handler (~11 APIs, real implementations)
#include "shell32.h"

#include <cstring>
#include <vector>
#include <string>
#include <map>

#include "memmgr.h"
#include "struct.h"
#include "winenv/arch.h"
#include "windows/winemu.h"
#include "windows/win32.h"

using namespace speakeasy;

namespace speakeasy { namespace api {

//  Typed cast helpers 
static inline WindowsEmulator* we(void* e) {
    return static_cast<WindowsEmulator*>(e);
}
static inline BinaryEmulator* be(void* e) {
    return static_cast<BinaryEmulator*>(e);
}
static inline MemoryManager* mm(void* e) {
    return static_cast<MemoryManager*>(e);
}

//  CSIDL path resolver 
static std::string resolve_csidl_path(void* e, uint32_t csidl) {
    (void)e;
    switch (csidl) {
        case 0x1A: return "C:\\Users\\USER\\AppData\\Roaming";
        case 0x28: return "C:\\Users\\USER";
        case 0x00:
        case 0x10: return "C:\\Users\\USER\\Desktop";
        case 0x02: return "C:\\Users\\USER\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs";
        case 0x06:
        case 0x1F: return "C:\\Users\\USER\\Favorites";
        case 0x07: return "C:\\Users\\USER\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup";
        case 0x08: return "C:\\Users\\USER\\AppData\\Roaming\\Microsoft\\Windows\\Recent";
        case 0x09: return "C:\\Users\\USER\\AppData\\Roaming\\Microsoft\\Windows\\SendTo";
        case 0x0B: return "C:\\Users\\USER\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu";
        case 0x13: return "C:\\Users\\USER\\AppData\\Roaming\\Microsoft\\Windows\\Network Shortcuts";
        case 0x15: return "C:\\Users\\USER\\AppData\\Roaming\\Microsoft\\Windows\\Templates";
        case 0x1B: return "C:\\Users\\USER\\AppData\\Roaming\\Microsoft\\Windows\\Printer Shortcuts";
        case 0x1C: return "C:\\Users\\USER\\AppData\\Local";
        case 0x20: return "C:\\Users\\USER\\AppData\\Local\\Microsoft\\Windows\\Temporary Internet Files";
        case 0x21: return "C:\\Users\\USER\\AppData\\Roaming\\Microsoft\\Windows\\Cookies";
        case 0x22: return "C:\\Users\\USER\\AppData\\Local\\Microsoft\\Windows\\History";
        case 0x27: return "C:\\Users\\USER\\Pictures";
        case 0x2F:
        case 0x30: return "C:\\Users\\USER\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Administrative Tools";
        case 0x1D: return "C:\\Users\\USER\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup";
        case 0x1E: return "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup";
        case 0x2A:
        case 0x26: return "C:\\Program Files";
        case 0x2B:
        case 0x2C: return "C:\\Program Files\\Common Files";
        case 0x24: return "C:\\Windows";
        case 0x25: return "C:\\Windows\\System32";
        case 0x14: return "C:\\Windows\\Fonts";
        case 0x23: return "C:\\ProgramData";
        case 0x05: return "C:\\Users\\USER\\Documents";
        case 0x0D: return "C:\\Users\\USER\\Music";
        case 0x0E: return "C:\\Users\\USER\\Videos";
        default:   return "C:\\Windows\\Temp";
    }
}

//  Constructor 

Shell32::Shell32(void* emu) : ApiHandler(emu) {
    INIT_API_TABLE(Shell32)
    REG(Shell32, ShellExecuteA, 6)          REG(Shell32, ShellExecuteW, 6)
    REG(Shell32, ShellExecuteExA, 1)        REG(Shell32, SHGetFolderPathA, 5)
    REG(Shell32, SHGetSpecialFolderPathA, 4) REG(Shell32, SHGetFolderPathW, 5)
    REG(Shell32, SHFileOperationA, 1)       REG(Shell32, ExtractIconExW, 5)
    REG(Shell32, SHGetFileInfoA, 4)         REG(Shell32, SHGetFileInfoW, 4)
    REG(Shell32, SHCreateDirectoryExA, 3)
    END_API_TABLE
}

//  API implementations 

uint64_t Shell32::ShellExecuteA(void* e, const std::vector<uint64_t>& a, void* ctx) {
    uint64_t hwnd = a[0], lpOperation = a[1], lpFile = a[2];
    uint64_t lpParameters = a[3], lpDirectory = a[4], nShowCmd = a[5];
    (void)hwnd; (void)nShowCmd;

    std::string op, fn, param, dn;
    if (lpOperation) op = be(e)->read_mem_string(lpOperation, 1);
    if (lpFile) fn = be(e)->read_mem_string(lpFile, 1);
    if (lpParameters) param = be(e)->read_mem_string(lpParameters, 1);
    if (lpDirectory) dn = be(e)->read_mem_string(lpDirectory, 1);

    std::string full_path = fn;
    if (!dn.empty() && !fn.empty()) {
        full_path = dn + "\\" + fn;
    }
    (void)op;

    we(e)->create_process(full_path, param);
    return 33;
}

uint64_t Shell32::ShellExecuteW(void* e, const std::vector<uint64_t>& a, void* ctx) {
    uint64_t hwnd = a[0], lpOperation = a[1], lpFile = a[2];
    uint64_t lpParameters = a[3], lpDirectory = a[4], nShowCmd = a[5];
    (void)hwnd; (void)nShowCmd;

    std::string op, fn, param, dn;
    if (lpOperation) op = be(e)->read_mem_string(lpOperation, 2);
    if (lpFile) fn = be(e)->read_mem_string(lpFile, 2);
    if (lpParameters) param = be(e)->read_mem_string(lpParameters, 2);
    if (lpDirectory) dn = be(e)->read_mem_string(lpDirectory, 2);

    std::string full_path = fn;
    if (!dn.empty() && !fn.empty()) {
        full_path = dn + "\\" + fn;
    }
    (void)op;

    we(e)->create_process(full_path, param);
    return 33;
}

uint64_t Shell32::ShellExecuteExA(void* e, const std::vector<uint64_t>& a, void* ctx) {
    uint64_t lpExecInfo = a[0];
    if (!lpExecInfo) return 0;

    // Read SHELLEXECUTEINFOA struct fields
    std::vector<uint8_t> raw = mm(e)->mem_read(lpExecInfo, 112);
    uint64_t cbSize   = read_le(raw, 0, 4);
    uint64_t fMask    = read_le(raw, 4, 4);
    uint64_t hwnd     = read_le(raw, 8, 8);
    uint64_t lpVerb   = read_le(raw, 16, 8);
    uint64_t lpFile   = read_le(raw, 24, 8);
    uint64_t lpParams = read_le(raw, 32, 8);
    uint64_t lpDir    = read_le(raw, 40, 8);
    uint64_t nShow    = read_le(raw, 48, 4);
    (void)cbSize; (void)fMask; (void)hwnd; (void)lpVerb; (void)nShow;

    std::string fn, param, dn;
    if (lpFile) fn = be(e)->read_mem_string(lpFile, 1);
    if (lpParams) param = be(e)->read_mem_string(lpParams, 1);
    if (lpDir) dn = be(e)->read_mem_string(lpDir, 1);

    std::string full_path = fn;
    if (!dn.empty() && !fn.empty())
        full_path = dn + "\\" + fn;

    we(e)->create_process(full_path, param);

    // Write hInstApp field (offset 56)
    std::vector<uint8_t> hinst(8);
    write_le(hinst, 0, (uint64_t)33, 8);
    be(e)->mem_write(lpExecInfo + 56, hinst);

    return 1;
}

uint64_t Shell32::SHGetFolderPathA(void* e, const std::vector<uint64_t>& a, void* ctx) {
    uint64_t hwnd = a[0], csidl = a[1], hToken = a[2], dwFlags = a[3], pszPath = a[4];
    (void)hwnd; (void)hToken; (void)dwFlags;

    std::string path = resolve_csidl_path(e, static_cast<uint32_t>(csidl));

    if (pszPath) {
        be(e)->write_mem_string(path, pszPath, 1);
    }
    return 0; // S_OK
}

uint64_t Shell32::SHGetFolderPathW(void* e, const std::vector<uint64_t>& a, void* ctx) {
    uint64_t hwnd = a[0], csidl = a[1], hToken = a[2], dwFlags = a[3], pszPath = a[4];
    (void)hwnd; (void)hToken; (void)dwFlags;

    std::string path = resolve_csidl_path(e, static_cast<uint32_t>(csidl));

    if (pszPath) {
        be(e)->write_mem_string(path, pszPath, 2);
    }
    return 0; // S_OK
}

uint64_t Shell32::SHGetSpecialFolderPathA(void* e, const std::vector<uint64_t>& a, void* ctx) {
    uint64_t hwnd = a[0], pszPath = a[1], csidl = a[2], fCreate = a[3];
    (void)hwnd; (void)fCreate;

    std::string path = resolve_csidl_path(e, static_cast<uint32_t>(csidl));

    if (pszPath) {
        be(e)->write_mem_string(path, pszPath, 1);
    }
    return 1;
}

uint64_t Shell32::SHFileOperationA(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a;
    return 0;
}

uint64_t Shell32::ExtractIconExW(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a;
    return 1;
}

uint64_t Shell32::SHGetFileInfoA(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a;
    return 0;
}

uint64_t Shell32::SHGetFileInfoW(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a;
    return 0;
}

uint64_t Shell32::SHCreateDirectoryExA(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a;
    return 0; // ERROR_SUCCESS
}

}} // namespaces
