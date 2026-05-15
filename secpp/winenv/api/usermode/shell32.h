// shell32.h
#ifndef SPEAKEASY_SHELL32_H
#define SPEAKEASY_SHELL32_H
#include <string>
#include <vector>
#include "api_handler_base.h"
namespace speakeasy { namespace api {
class Shell32 : public ApiHandler {
public: Shell32(); std::string get_name() const override {return "shell32";}
const std::vector<ApiEntry>& get_apis() const override {return apis_;}
private: std::vector<ApiEntry> apis_;
static uint64_t ShellExecuteA(void*,const std::string&,int,const std::vector<uint64_t>&);
static uint64_t ShellExecuteW(void*,const std::string&,int,const std::vector<uint64_t>&);
static uint64_t ShellExecuteExA(void*,const std::string&,int,const std::vector<uint64_t>&);
static uint64_t SHGetFolderPathA(void*,const std::string&,int,const std::vector<uint64_t>&);
static uint64_t SHGetSpecialFolderPathA(void*,const std::string&,int,const std::vector<uint64_t>&);
static uint64_t stub(void*,const std::string&,int,const std::vector<uint64_t>&);
};
}}
#endif
