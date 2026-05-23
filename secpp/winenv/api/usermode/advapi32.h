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
    static uint64_t RegOpenKeyExA(void*,const std::string&,int,const std::vector<uint64_t>&);
    static uint64_t RegQueryValueExA(void*,const std::string&,int,const std::vector<uint64_t>&);
    static uint64_t RegCloseKey(void*,const std::string&,int,const std::vector<uint64_t>&);
    static uint64_t RegCreateKeyExA(void*,const std::string&,int,const std::vector<uint64_t>&);
    static uint64_t RegSetValueExA(void*,const std::string&,int,const std::vector<uint64_t>&);
    static uint64_t RegDeleteKeyA(void*,const std::string&,int,const std::vector<uint64_t>&);
    static uint64_t OpenProcessToken(void*,const std::string&,int,const std::vector<uint64_t>&);
    static uint64_t LookupPrivilegeValueA(void*,const std::string&,int,const std::vector<uint64_t>&);
    static uint64_t AdjustTokenPrivileges(void*,const std::string&,int,const std::vector<uint64_t>&);
    static uint64_t CryptAcquireContextA(void*,const std::string&,int,const std::vector<uint64_t>&);
    static uint64_t CryptGenRandom(void*,const std::string&,int,const std::vector<uint64_t>&);
    static uint64_t CreateServiceA(void*,const std::string&,int,const std::vector<uint64_t>&);
    static uint64_t StartServiceA(void*,const std::string&,int,const std::vector<uint64_t>&);
    static uint64_t stub(void*,const std::string&,int,const std::vector<uint64_t>&);
};
}} 
#endif
