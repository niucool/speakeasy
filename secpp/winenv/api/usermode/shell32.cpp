// shell32.cpp
#include "shell32.h"
namespace speakeasy { namespace api {
#define STUB(n) uint64_t Shell32::n(void*e,const std::string&,int,const std::vector<uint64_t>&a){(void)e;(void)a;return 1;}
Shell32::Shell32(){apis_={
    {"ShellExecuteA",6,ShellExecuteA},{"ShellExecuteW",6,ShellExecuteW},
    {"ShellExecuteExA",1,ShellExecuteExA},{"SHGetFolderPathA",5,SHGetFolderPathA},
    {"SHGetSpecialFolderPathA",4,SHGetSpecialFolderPathA},
};}
STUB(ShellExecuteA) STUB(ShellExecuteW) STUB(ShellExecuteExA) STUB(SHGetFolderPathA) STUB(SHGetSpecialFolderPathA)
uint64_t Shell32::stub(void*e,const std::string&,int,const std::vector<uint64_t>&a){(void)e;(void)a;return 1;}
}}
