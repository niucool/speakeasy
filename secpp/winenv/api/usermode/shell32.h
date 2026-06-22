// shell32.h  shell32.dll API handler (v2)
#ifndef SPEAKEASY_SHELL32_H
#define SPEAKEASY_SHELL32_H
#include <string>
#include <vector>
#include "../api.h"

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
#ifdef ExtractIcon
#undef ExtractIcon
#endif
#ifdef CommandLineToArgv
#undef CommandLineToArgv
#endif

namespace speakeasy { namespace api {
class Shell32 : public ApiHandler {
public:
    Shell32(void* emu);
    std::string get_name() const override {return "shell32";}
    const std::vector<ApiEntry>& get_apis() const override {return apis_;}
private:
    std::vector<ApiEntry> apis_;
    // A/W merged — use get_char_width(ctx)
    static uint64_t ShellExecute(void*, ArgList&, void* ctx);
    static uint64_t ShellExecuteEx(void*, ArgList&, void* ctx);
    static uint64_t SHGetFolderPath(void*, ArgList&, void* ctx);
    static uint64_t SHGetSpecialFolderPath(void*, ArgList&, void* ctx);
    static uint64_t SHCreateDirectoryEx(void*, ArgList&, void* ctx);
    static uint64_t SHFileOperation(void*, ArgList&, void* ctx);
    static uint64_t ExtractIconEx(void*, ArgList&, void* ctx);
    static uint64_t ExtractIcon(void*, ArgList&, void* ctx);
    static uint64_t SHGetFileInfo(void*, ArgList&, void* ctx);
    // Python functions previously missing
    static uint64_t SHChangeNotify(void*, ArgList&, void* ctx);
    static uint64_t IsUserAnAdmin(void*, ArgList&, void* ctx);
    static uint64_t SHGetMalloc(void*, ArgList&, void* ctx);
    static uint64_t CommandLineToArgv(void*, ArgList&, void* ctx);
};
}}
#endif
