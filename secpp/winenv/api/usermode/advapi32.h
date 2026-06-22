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
    static uint64_t RegOpenKey(void*, ArgList&, void* ctx);
    static uint64_t RegOpenKeyEx(void*, ArgList&, void* ctx);
    //static uint64_t RegOpenKeyExW(void*, ArgList&, void* ctx);
    static uint64_t RegQueryValueEx(void*, ArgList&, void* ctx);
    static uint64_t RegCloseKey(void*, ArgList&, void* ctx);
    static uint64_t RegCreateKey(void*, ArgList&, void* ctx);
    static uint64_t RegCreateKeyEx(void*, ArgList&, void* ctx);
    static uint64_t RegSetValueEx(void*, ArgList&, void* ctx);
    //static uint64_t RegSetValueExW(void*, ArgList&, void* ctx);
    static uint64_t RegDeleteKey(void*, ArgList&, void* ctx);
    static uint64_t RegDeleteValue(void*, ArgList&, void* ctx);
    static uint64_t RegEnumKey(void*, ArgList&, void* ctx);
    static uint64_t RegEnumKeyEx(void*, ArgList&, void* ctx);
    static uint64_t RegGetValue(void*, ArgList&, void* ctx);
    static uint64_t RegQueryInfoKey(void*, ArgList&, void* ctx);
    static uint64_t OpenProcessToken(void*, ArgList&, void* ctx);
    static uint64_t OpenThreadToken(void*, ArgList&, void* ctx);
    static uint64_t LookupPrivilegeValue(void*, ArgList&, void* ctx);
    static uint64_t AdjustTokenPrivileges(void*, ArgList&, void* ctx);
    static uint64_t DuplicateTokenEx(void*, ArgList&, void* ctx);
    static uint64_t SetTokenInformation(void*, ArgList&, void* ctx);
    static uint64_t CryptAcquireContext(void*, ArgList&, void* ctx);
    static uint64_t CryptGenRandom(void*, ArgList&, void* ctx);
    static uint64_t CryptReleaseContext(void*, ArgList&, void* ctx);
    static uint64_t SystemFunction036(void*, ArgList&, void* ctx);
    static uint64_t CreateService(void*, ArgList&, void* ctx);
    //static uint64_t CreateServiceW(void*, ArgList&, void* ctx);
    static uint64_t StartService(void*, ArgList&, void* ctx);
    //static uint64_t StartServiceW(void*, ArgList&, void* ctx);
    static uint64_t ControlService(void*, ArgList&, void* ctx);
    static uint64_t DeleteService(void*, ArgList&, void* ctx);
    static uint64_t QueryServiceStatus(void*, ArgList&, void* ctx);
    static uint64_t CloseServiceHandle(void*, ArgList&, void* ctx);
    static uint64_t ChangeServiceConfig(void*, ArgList&, void* ctx);
    //static uint64_t ChangeServiceConfigW(void*, ArgList&, void* ctx);
    static uint64_t ChangeServiceConfig2(void*, ArgList&, void* ctx);
    //static uint64_t ChangeServiceConfig2W(void*, ArgList&, void* ctx);
    static uint64_t OpenSCManager(void*, ArgList&, void* ctx);
    //static uint64_t OpenSCManagerW(void*, ArgList&, void* ctx);
    static uint64_t RevertToSelf(void*, ArgList&, void* ctx);
    static uint64_t ImpersonateLoggedOnUser(void*, ArgList&, void* ctx);
    static uint64_t AllocateAndInitializeSid(void*, ArgList&, void* ctx);
    static uint64_t CheckTokenMembership(void*, ArgList&, void* ctx);
    static uint64_t FreeSid(void*, ArgList&, void* ctx);
    static uint64_t StartServiceCtrlDispatcher(void*, ArgList&, void*);
    //static uint64_t StartServiceCtrlDispatcherW(void*, ArgList&, void*);
    static uint64_t RegisterServiceCtrlHandler(void*, ArgList&, void*);
    //static uint64_t RegisterServiceCtrlHandlerW(void*, ArgList&, void*);
    static uint64_t RegisterServiceCtrlHandlerEx(void*, ArgList&, void*);
    //static uint64_t RegisterServiceCtrlHandlerExW(void*, ArgList&, void*);
    static uint64_t SetServiceStatus(void*, ArgList&, void*);
    static uint64_t OpenService(void*, ArgList&, void*);
    //static uint64_t OpenServiceW(void*, ArgList&, void*);
    static uint64_t GetUserName(void*, ArgList&, void*);
    //static uint64_t GetUserNameW(void*, ArgList&, void*);
    static uint64_t LookupAccountName(void*, ArgList&, void*);
    //static uint64_t LookupAccountNameW(void*, ArgList&, void*);
    static uint64_t LookupAccountSid(void*, ArgList&, void*);
    //static uint64_t LookupAccountSidW(void*, ArgList&, void*);
    static uint64_t CryptCreateHash(void*, ArgList&, void*);
    static uint64_t CryptDestroyHash(void*, ArgList&, void*);
    static uint64_t CryptGetHashParam(void*, ArgList&, void*);
    static uint64_t CryptHashData(void*, ArgList&, void*);
    static uint64_t CryptDecrypt(void*, ArgList&, void*);
    static uint64_t CryptDeriveKey(void*, ArgList&, void*);
    static uint64_t GetTokenInformation(void*, ArgList&, void*);
    static uint64_t GetCurrentHwProfile(void*, ArgList&, void*);
    static uint64_t CreateProcessAsUser(void*, ArgList&, void*);
    static uint64_t EnumServicesStatus(void*, ArgList&, void*);
    //static uint64_t EnumServicesStatusW(void*, ArgList&, void*);
    static uint64_t QueryServiceConfig(void*, ArgList&, void*);
    //static uint64_t QueryServiceConfigW(void*, ArgList&, void*);
    static uint64_t EqualSid(void*, ArgList&, void*);
    static uint64_t GetSidSubAuthority(void*, ArgList&, void*);
    static uint64_t GetSidSubAuthorityCount(void*, ArgList&, void*);
    static uint64_t GetSidIdentifierAuthority(void*, ArgList&, void*);
    static uint64_t stub(void*, ArgList&, void*);
};
}} 
#endif
