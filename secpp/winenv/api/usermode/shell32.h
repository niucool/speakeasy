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
    static uint64_t ShellExecuteA(void*, std::vector<uint64_t>&, void* ctx);
    static uint64_t ShellExecuteW(void*, std::vector<uint64_t>&, void* ctx);
    static uint64_t ShellExecuteExA(void*, std::vector<uint64_t>&, void* ctx);
    static uint64_t SHGetFolderPathA(void*, std::vector<uint64_t>&, void* ctx);
    static uint64_t SHGetFolderPathW(void*, std::vector<uint64_t>&, void* ctx);
    static uint64_t SHGetSpecialFolderPathA(void*, std::vector<uint64_t>&, void* ctx);
    static uint64_t SHFileOperationA(void*, std::vector<uint64_t>&, void* ctx);
    static uint64_t ExtractIconExW(void*, std::vector<uint64_t>&, void* ctx);
    static uint64_t SHGetFileInfoA(void*, std::vector<uint64_t>&, void* ctx);
    static uint64_t SHGetFileInfoW(void*, std::vector<uint64_t>&, void* ctx);
    static uint64_t SHCreateDirectoryExA(void*, std::vector<uint64_t>&, void* ctx);
    static uint64_t stub(void*, std::vector<uint64_t>&, void* ctx);
};
}}
#endif
