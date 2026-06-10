// shell32.h  shell32.dll API handler (v2)
#ifndef SPEAKEASY_SHELL32_H
#define SPEAKEASY_SHELL32_H
#include <string>
#include <vector>
#include "../api.h"
namespace speakeasy { namespace api {
class Shell32 : public ApiHandler {
public:
    Shell32(void* emu);
    std::string get_name() const override {return "shell32";}
    const std::vector<ApiEntry>& get_apis() const override {return apis_;}
private:
    std::vector<ApiEntry> apis_;
    static uint64_t ShellExecuteA(void*, ArgList&, void* ctx);
    static uint64_t ShellExecuteW(void*, ArgList&, void* ctx);
    static uint64_t ShellExecuteExA(void*, ArgList&, void* ctx);
    static uint64_t SHGetFolderPathA(void*, ArgList&, void* ctx);
    static uint64_t SHGetFolderPathW(void*, ArgList&, void* ctx);
    static uint64_t SHGetSpecialFolderPathA(void*, ArgList&, void* ctx);
    static uint64_t SHFileOperationA(void*, ArgList&, void* ctx);
    static uint64_t ExtractIconExW(void*, ArgList&, void* ctx);
    static uint64_t SHGetFileInfoA(void*, ArgList&, void* ctx);
    static uint64_t SHGetFileInfoW(void*, ArgList&, void* ctx);
    static uint64_t SHCreateDirectoryExA(void*, ArgList&, void* ctx);
    static uint64_t stub(void*, ArgList&, void* ctx);
};
}}
#endif
