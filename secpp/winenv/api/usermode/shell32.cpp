// shell32.cpp  shell32.dll handler — A/W merged, matching Python shell32.py
#include "shell32.h"

#include <cstring>
#include <vector>
#include <string>
#include <map>
#include <sstream>

#include "memmgr.h"
#include "struct.h"
#include "winenv/arch.h"
#include "windows/winemu.h"
#include "windows/win32.h"

using namespace speakeasy;

namespace speakeasy { namespace api {

// Undef Windows SDK A/W macros
#ifdef ShellExecute
#undef ShellExecute
#endif
#ifdef ShellExecuteEx
#undef ShellExecuteEx
#endif
#ifdef SHGetFolderPath
#undef SHGetFolderPath
#endif
#ifdef SHGetSpecialFolderPath
#undef SHGetSpecialFolderPath
#endif
#ifdef SHCreateDirectoryEx
#undef SHCreateDirectoryEx
#endif
#ifdef SHFileOperation
#undef SHFileOperation
#endif
#ifdef SHGetFileInfo
#undef SHGetFileInfo
#endif

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
    REG(Shell32, ShellExecute, 6)
    REG(Shell32, ShellExecuteEx, 1)             REG(Shell32, SHGetFolderPath, 5)
    REG(Shell32, SHGetSpecialFolderPath, 4)     REG(Shell32, SHFileOperation, 1)
    REG(Shell32, ExtractIconEx, 4)              REG(Shell32, ExtractIcon, 3)
    REG(Shell32, SHGetFileInfo, 4)              REG(Shell32, SHCreateDirectoryEx, 3)
    REG(Shell32, SHChangeNotify, 4)             REG(Shell32, IsUserAnAdmin, 0)
    REG(Shell32, SHGetMalloc, 1)                REG(Shell32, CommandLineToArgv, 2)
    END_API_TABLE
}

//  API implementations — A/W merged with get_char_width(ctx)

uint64_t Shell32::ShellExecute(void* e, ArgList& a, void* ctx) {
    // Python shell32.py: ShellExecute  get_char_width, read strings, create process
    int cw = get_char_width(static_cast<ApiContext*>(ctx));
    uint64_t hwnd = a[0], lpOperation = a[1], lpFile = a[2];
    uint64_t lpParameters = a[3], lpDirectory = a[4], nShowCmd = a[5];
    (void)hwnd; (void)nShowCmd;

    if (lpOperation)   a[1] = be(e)->read_mem_string(lpOperation, cw);
    if (lpFile)        a[2] = be(e)->read_mem_string(lpFile, cw);
    if (lpParameters)  a[3] = be(e)->read_mem_string(lpParameters, cw);
    if (lpDirectory)   a[4] = be(e)->read_mem_string(lpDirectory, cw);

    std::string fn = lpFile ? std::get<std::string>(a[2].data) : "";
    std::string param = lpParameters ? std::get<std::string>(a[3].data) : "";
    std::string dn = lpDirectory ? std::get<std::string>(a[4].data) : "";
    if (!dn.empty() && !fn.empty()) fn = dn + "\\" + fn;

    we(e)->create_process(fn, param);
    return 33;
}

uint64_t Shell32::ShellExecuteEx(void* e, ArgList& a, void* ctx) {
    // Python shell32.py: ShellExecuteEx  read SHELLEXECUTEINFO, delegate to ShellExecute
    uint64_t lpExecInfo = a[0];
    if (!lpExecInfo) return 0;

    int cw = get_char_width(static_cast<ApiContext*>(ctx));
    int ps = we(e)->get_ptr_size();
    size_t sei_size = (ps == 8) ? 112 : 60;
    std::vector<uint8_t> raw = mm(e)->mem_read(lpExecInfo, sei_size);
    uint64_t cbSize = read_le(raw, 0, 4);
    (void)cbSize;
    uint64_t lpVerb   = (ps == 8) ? read_le(raw, 16, 8) : read_le(raw, 12, 4);
    uint64_t lpFile   = (ps == 8) ? read_le(raw, 24, 8) : read_le(raw, 16, 4);
    uint64_t lpParams = (ps == 8) ? read_le(raw, 32, 8) : read_le(raw, 20, 4);
    uint64_t lpDir    = (ps == 8) ? read_le(raw, 40, 8) : read_le(raw, 24, 4);

    ArgList args = { uint64_t(0), lpVerb, lpFile, lpParams, lpDir, uint64_t(0) };
    Shell32::ShellExecute(e, args, ctx);

    // Write hInstApp
    uint64_t hInstOff = (ps == 8) ? 56 : 40;
    std::vector<uint8_t> hinst(ps == 8 ? 8 : 4, 0);
    write_le(hinst, 0, (uint64_t)33, (size_t)ps);
    mm(e)->mem_write(lpExecInfo + hInstOff, hinst);
    return 1;
}

uint64_t Shell32::SHGetFolderPath(void* e, ArgList& a, void* ctx) {
    // Python shell32.py: SHGetFolderPath  resolve CSIDL, write path with cw
    uint64_t hwnd = a[0], csidl = a[1], hToken = a[2], dwFlags = a[3], pszPath = a[4];
    (void)hwnd; (void)hToken; (void)dwFlags;
    int cw = get_char_width(static_cast<ApiContext*>(ctx));

    std::string path = resolve_csidl_path(e, static_cast<uint32_t>(csidl));
    if (pszPath) be(e)->write_mem_string(path, pszPath, cw);
    return 0; // S_OK
}

uint64_t Shell32::SHGetSpecialFolderPath(void* e, ArgList& a, void* ctx) {
    // Python shell32.py pattern: resolve CSIDL, write path with cw
    uint64_t hwnd = a[0], pszPath = a[1], csidl = a[2], fCreate = a[3];
    (void)hwnd; (void)fCreate;
    int cw = get_char_width(static_cast<ApiContext*>(ctx));

    std::string path = resolve_csidl_path(e, static_cast<uint32_t>(csidl));
    if (pszPath) be(e)->write_mem_string(path, pszPath, cw);
    return 1;
}

uint64_t Shell32::SHFileOperation(void* e, ArgList& a, void* ctx) {
    (void)e; (void)a; (void)ctx;
    return 0;
}

uint64_t Shell32::ExtractIconEx(void* e, ArgList& a, void* ctx) {
    // Python shell32.py: ExtractIcon  returns a handle
    static uint64_t hnd = 0x2800; hnd += 4;
    (void)e; (void)a; (void)ctx;
    return hnd;
}

uint64_t Shell32::ExtractIcon(void* e, ArgList& a, void* ctx) {
    // Python shell32.py: ExtractIcon (original name, same as ExtractIconEx)
    return ExtractIconEx(e, a, ctx);
}

uint64_t Shell32::SHGetFileInfo(void* e, ArgList& a, void* ctx) {
    (void)e; (void)a; (void)ctx;
    return 0;
}

uint64_t Shell32::SHCreateDirectoryEx(void* e, ArgList& a, void* ctx) {
    // Python shell32.py: SHCreateDirectoryEx  read name with cw, record event
    uint64_t hwnd = a[0], pszPath = a[1], psa = a[2];
    (void)hwnd; (void)psa;
    if (pszPath) {
        int cw = get_char_width(static_cast<ApiContext*>(ctx));
        std::string dn = be(e)->read_mem_string(pszPath, cw);
        a[1] = dn;
    }
    return 0; // ERROR_SUCCESS
}

//  Previously missing Python functions

uint64_t Shell32::SHChangeNotify(void* e, ArgList& a, void* ctx) {
    // Python shell32.py: SHChangeNotify  void — immediate return
    (void)e; (void)a; (void)ctx;
    return 0;
}

uint64_t Shell32::IsUserAnAdmin(void* e, ArgList& a, void* ctx) {
    // Python shell32.py: IsUserAnAdmin  returns config.user.is_admin
    auto usermap = be(e)->get_user();
    return usermap.count("is_admin") ? (usermap.at("is_admin") == "true" ? 1 : 0) : 0;
}

uint64_t Shell32::SHGetMalloc(void* e, ArgList& a, void* ctx) {
    // Python shell32.py: SHGetMalloc  write COM IMalloc interface pointer
    uint64_t ppMalloc = a[0];
    if (ppMalloc) {
        int ps = we(e)->get_ptr_size();
        std::vector<uint8_t> buf((size_t)ps, 0);
        write_le(buf, 0, (uint64_t)0x4000, (size_t)ps); // placeholder COM ptr
        mm(e)->mem_write(ppMalloc, buf);
    }
    (void)ctx;
    return 0; // S_OK
}

uint64_t Shell32::CommandLineToArgv(void* e, ArgList& a, void* ctx) {
    // Python shell32.py: CommandLineToArgv  parse command line, allocate argv array
    uint64_t cmdline = a[0], argc_ptr = a[1];
    if (!cmdline) return 0;
    int cw = get_char_width(static_cast<ApiContext*>(ctx));
    std::string cl = be(e)->read_mem_string(cmdline, cw);

    // Simple split by spaces
    std::vector<std::string> args;
    std::istringstream iss(cl);
    std::string tok;
    while (iss >> tok) args.push_back(tok);
    int nargs = (int)args.size();

    int ps = we(e)->get_ptr_size();
    size_t ptr_array_sz = ((size_t)nargs + 1) * (size_t)ps;
    size_t str_total = 0;
    for (auto& s : args) str_total += (s.size() + 1) * (size_t)cw;
    size_t total = ptr_array_sz + str_total;
    uint64_t buf = mm(e)->mem_map(total, std::nullopt, PERM_MEM_RW, "api.CommandLineToArgv");

    uint64_t ptrs = buf;
    uint64_t strs = buf + ptr_array_sz;
    for (int i = 0; i < nargs; i++) {
        std::vector<uint8_t> pb((size_t)ps, 0);
        write_le(pb, 0, strs, (size_t)ps);
        mm(e)->mem_write(ptrs + (uint64_t)i * (uint64_t)ps, pb);
        std::string s = args[(size_t)i] + '\0';
        if (cw == 2) {
            for (size_t j = 0; j < s.size(); j++) {
                std::vector<uint8_t> w(2, 0);
                write_le(w, 0, (uint16_t)s[j], 2);
                mm(e)->mem_write(strs + j * 2, w);
            }
        } else {
            mm(e)->mem_write(strs, std::vector<uint8_t>(s.begin(), s.end()));
        }
        strs += (uint64_t)((s.size()) * (size_t)cw);
    }
    // NULL terminator for ptr array
    std::vector<uint8_t> nullp((size_t)ps, 0);
    mm(e)->mem_write(ptrs + (uint64_t)nargs * (uint64_t)ps, nullp);

    if (argc_ptr) {
        std::vector<uint8_t> nb(4, 0);
        write_le(nb, 0, (uint64_t)nargs, 4);
        mm(e)->mem_write(argc_ptr, nb);
    }
    return buf;
}

}} // namespaces
