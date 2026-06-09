// advapi32.h
#ifndef SPEAKEASY_ADVAPI32_H
#define SPEAKEASY_ADVAPI32_H
#include <string>
#include <vector>
#include "../api.h"
namespace speakeasy { namespace api {
class Advapi32 : public ApiHandler {
public: 
    Advapi32(void* emu); 
    std::string get_name() const override {return "advapi32";}
    const std::vector<ApiEntry>& get_apis() const override {return apis_;}

private: 
    std::vector<ApiEntry> apis_;
    static uint64_t RegOpenKeyExA(void*, std::vector<uint64_t>&, void* ctx);
    static uint64_t RegQueryValueExA(void*, std::vector<uint64_t>&, void* ctx);
    static uint64_t RegCloseKey(void*, std::vector<uint64_t>&, void* ctx);
    static uint64_t RegCreateKeyExA(void*, std::vector<uint64_t>&, void* ctx);
    static uint64_t RegSetValueExA(void*, std::vector<uint64_t>&, void* ctx);
    static uint64_t RegDeleteKeyA(void*, std::vector<uint64_t>&, void* ctx);
    static uint64_t OpenProcessToken(void*, std::vector<uint64_t>&, void* ctx);
    static uint64_t LookupPrivilegeValueA(void*, std::vector<uint64_t>&, void* ctx);
    static uint64_t AdjustTokenPrivileges(void*, std::vector<uint64_t>&, void* ctx);
    static uint64_t CryptAcquireContextA(void*, std::vector<uint64_t>&, void* ctx);
    static uint64_t CryptGenRandom(void*, std::vector<uint64_t>&, void* ctx);
    static uint64_t CreateServiceA(void*, std::vector<uint64_t>&, void* ctx);
    static uint64_t StartServiceA(void*, std::vector<uint64_t>&, void* ctx);
    static uint64_t stub(void*, std::vector<uint64_t>&, void* ctx);
};
}} 
#endif
