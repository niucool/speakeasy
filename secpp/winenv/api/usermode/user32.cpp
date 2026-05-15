// user32.cpp
#include "user32.h"
namespace speakeasy { namespace api {
#define STUB(n) uint64_t User32::n(void*e,const std::string&,int,const std::vector<uint64_t>&a){(void)e;(void)a;return 1;}
User32::User32(){apis_={
    {"MessageBoxA",4,MessageBoxA},{"MessageBoxW",4,MessageBoxW},
    {"GetMessageA",4,GetMessageA},{"PeekMessageA",5,PeekMessageA},
    {"FindWindowA",2,FindWindowA},{"SendMessageA",4,SendMessageA},
    {"GetWindowTextA",3,GetWindowTextA},{"SetWindowTextA",2,SetWindowTextA},
    {"GetForegroundWindow",0,GetForegroundWindow},
};}
STUB(MessageBoxA) STUB(MessageBoxW) STUB(GetMessageA) STUB(PeekMessageA) STUB(FindWindowA)
STUB(SendMessageA) STUB(GetWindowTextA) STUB(SetWindowTextA) STUB(GetForegroundWindow)
uint64_t User32::stub(void*e,const std::string&,int,const std::vector<uint64_t>&a){(void)e;(void)a;return 1;}
}}
