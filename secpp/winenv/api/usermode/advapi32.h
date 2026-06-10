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
    static uint64_t RegOpenKeyExA(void*, ArgList&, void* ctx);
    static uint64_t RegQueryValueExA(void*, ArgList&, void* ctx);
    static uint64_t RegCloseKey(void*, ArgList&, void* ctx);
    static uint64_t RegCreateKeyExA(void*, ArgList&, void* ctx);
    static uint64_t RegSetValueExA(void*, ArgList&, void* ctx);
    static uint64_t RegDeleteKeyA(void*, ArgList&, void* ctx);
    static uint64_t OpenProcessToken(void*, ArgList&, void* ctx);
    static uint64_t LookupPrivilegeValueA(void*, ArgList&, void* ctx);
    static uint64_t AdjustTokenPrivileges(void*, ArgList&, void* ctx);
    static uint64_t CryptAcquireContextA(void*, ArgList&, void* ctx);
    static uint64_t CryptGenRandom(void*, ArgList&, void* ctx);
    static uint64_t CreateServiceA(void*, ArgList&, void* ctx);
    static uint64_t StartServiceA(void*, ArgList&, void* ctx);
    static uint64_t stub(void*, ArgList&, void* ctx);
};
}} 
#endif
