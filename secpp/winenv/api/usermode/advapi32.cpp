// advapi32.cpp
#include "advapi32.h"
namespace speakeasy { namespace api {
#define STUB(n) uint64_t Advapi32::n(void*e,const std::string&,int,const std::vector<uint64_t>&a){(void)e;(void)a;return 1;}
Advapi32::Advapi32(){apis_={
    {"RegOpenKeyExA",5,RegOpenKeyExA},{"RegQueryValueExA",6,RegQueryValueExA},
    {"RegCloseKey",1,RegCloseKey},{"RegCreateKeyExA",9,RegCreateKeyExA},
    {"RegSetValueExA",6,RegSetValueExA},{"RegDeleteKeyA",2,RegDeleteKeyA},
    {"OpenProcessToken",3,OpenProcessToken},{"LookupPrivilegeValueA",3,LookupPrivilegeValueA},
    {"AdjustTokenPrivileges",6,AdjustTokenPrivileges},{"CryptAcquireContextA",5,CryptAcquireContextA},
    {"CryptGenRandom",2,CryptGenRandom},{"CreateServiceA",13,CreateServiceA},{"StartServiceA",2,StartServiceA},
};}
STUB(RegOpenKeyExA) STUB(RegQueryValueExA) STUB(RegCloseKey) STUB(RegCreateKeyExA)
STUB(RegSetValueExA) STUB(RegDeleteKeyA) STUB(OpenProcessToken) STUB(LookupPrivilegeValueA)
STUB(AdjustTokenPrivileges) STUB(CryptAcquireContextA) STUB(CryptGenRandom) STUB(CreateServiceA) STUB(StartServiceA)
uint64_t Advapi32::stub(void*e,const std::string&,int,const std::vector<uint64_t>&a){(void)e;(void)a;return 1;}
}}
