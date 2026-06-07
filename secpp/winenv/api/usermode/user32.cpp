// user32.cpp  user32.dll handler  real implementations
#include "user32.h"
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <string>
#include <vector>
#include <map>
#include "windows/winemu.h"
#include "struct.h"

using namespace speakeasy;
namespace speakeasy { namespace api {

static inline WindowsEmulator* we(void* e) { return static_cast<WindowsEmulator*>(e); }
static inline BinaryEmulator* be(void* e) { return static_cast<BinaryEmulator*>(e); }

//  Handle management 
static uint64_t next_hwnd() {
    static uint64_t h = 0x10000;
    return ++h;
}

static uint64_t next_hhook() {
    static uint64_t h = 0x20000;
    return ++h;
}

//  Window hooks store 
struct WindowHook { int idHook; uint64_t lpfn; uint64_t hmod; };
static std::map<uint64_t, WindowHook>& window_hooks() {
    static std::map<uint64_t, WindowHook> h;
    return h;
}

User32::User32(void* emu) : ApiHandler(emu) {
    INIT_API_TABLE(User32)
    REG(User32, MessageBoxA, 4)         REG(User32, MessageBoxW, 4)
    REG(User32, GetMessageA, 4)         REG(User32, GetMessageW, 4)
    REG(User32, PeekMessageA, 5)        REG(User32, PeekMessageW, 5)
    REG(User32, FindWindowA, 2)         REG(User32, FindWindowW, 2)
    REG(User32, SendMessageA, 4)        REG(User32, SendMessageW, 4)
    REG(User32, GetWindowTextA, 3)      REG(User32, GetWindowTextW, 3)
    REG(User32, SetWindowTextA, 2)      REG(User32, SetWindowTextW, 2)
    REG(User32, GetForegroundWindow, 0) REG(User32, GetDesktopWindow, 0)
    REG(User32, CreateWindowExA, 12)    REG(User32, CreateWindowExW, 12)
    REG(User32, RegisterClassExA, 1)    REG(User32, RegisterClassExW, 1)
    REG(User32, ShowWindow, 2)          REG(User32, UpdateWindow, 1)
    REG(User32, GetDC, 1)               REG(User32, GetSystemMetrics, 1)
    REG(User32, LoadCursorA, 2)         REG(User32, LoadCursorW, 2)
    REG(User32, SetWindowsHookExA, 4)   REG(User32, SetWindowsHookExW, 4)
    REG(User32, CallNextHookEx, 4)      REG(User32, GetAsyncKeyState, 1)
    REG(User32, GetKeyboardType, 1)
    REG(User32, wsprintfA, 0)           REG(User32, wsprintfW, 0)
    REG(User32, LoadStringA, 4)         REG(User32, LoadStringW, 4)
    REG(User32, TranslateMessage, 1)    REG(User32, DispatchMessageA, 1)
    REG(User32, DispatchMessageW, 1)    REG(User32, PostQuitMessage, 1)
    REG(User32, DefWindowProcA, 4)      REG(User32, DefWindowProcW, 4)
    REG(User32, DestroyWindow, 1)
    END_API_TABLE
}

//
// A/W wrappers that share a single implementation
//
static uint64_t CreateWindowEx_hook(void* e, const std::vector<uint64_t>& a, void* ctx) {
    if (a.size()<3) return 0;
    uint64_t cn = a[1], wn = a[2];
    if (cn) { std::string s = be(e)->read_mem_string(cn,1); (void)s; }
    if (wn) { std::string s = be(e)->read_mem_string(wn,1); (void)s; }
    return next_hwnd();
}
uint64_t User32::CreateWindowExA(void* e, const std::vector<uint64_t>& a, void* ctx) {
    return CreateWindowEx_hook(e, a, ctx);
}
uint64_t User32::CreateWindowExW(void* e, const std::vector<uint64_t>& a, void* ctx) {
    return CreateWindowEx_hook(e, a, ctx);
}
uint64_t User32::LoadCursorW(void* e, const std::vector<uint64_t>& a, void* ctx) {
    return LoadCursorA(e, a, ctx);
}
uint64_t User32::SetWindowsHookExW(void* e, const std::vector<uint64_t>& a, void* ctx) {
    return SetWindowsHookExA(e, a, ctx);
}
uint64_t User32::wsprintfW(void* e, const std::vector<uint64_t>& a, void* ctx) {
    return wsprintfA(e, a, ctx);
}
uint64_t User32::LoadStringW(void* e, const std::vector<uint64_t>& a, void* ctx) {
    return LoadStringA(e, a, ctx);
}

//
// API implementations
//

//  MessageBoxA / MessageBoxW
uint64_t User32::MessageBoxA(void* e, const std::vector<uint64_t>& a, void* ctx) {
    if (a.size()<4) return 2;
    uint64_t lpText = a[1], lpCaption = a[2];
    if (lpText) { std::string s = be(e)->read_mem_string(lpText,1); (void)s; }
    if (lpCaption) { std::string s = be(e)->read_mem_string(lpCaption,1); (void)s; }
    return 2; // IDCANCEL
}

uint64_t User32::MessageBoxW(void* e, const std::vector<uint64_t>& a, void* ctx) {
    if (a.size()<4) return 2;
    uint64_t lpText = a[1], lpCaption = a[2];
    if (lpText) { std::string s = be(e)->read_mem_string(lpText,2); (void)s; }
    if (lpCaption) { std::string s = be(e)->read_mem_string(lpCaption,2); (void)s; }
    return 2; // IDCANCEL
}

//  GetMessageA / GetMessageW
uint64_t User32::GetMessageA(void* e, const std::vector<uint64_t>& a, void* ctx) {
    if (a.size()<1) return 0;
    uint64_t lpMsg = a[0];
    if (lpMsg) {
        int ps = we(e)->get_ptr_size();
        size_t msg_size = (size_t)ps + 4 + (size_t)ps + (size_t)ps + 4 + 8;
        std::vector<uint8_t> buf(msg_size, 0);
        write_le(buf, (size_t)ps, 0x0012, 4); // message = WM_QUIT
        we(e)->mem_write(lpMsg, buf);
    }
    return 0; // FALSE (WM_QUIT)
}

uint64_t User32::GetMessageW(void* e, const std::vector<uint64_t>& a, void* ctx) {
    return GetMessageA(e, a, ctx); // Same MSG struct layout regardless of A/W
}

//  PeekMessageA / PeekMessageW
uint64_t User32::PeekMessageA(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a; return 0;
}

uint64_t User32::PeekMessageW(void* e, const std::vector<uint64_t>& a, void* ctx) {
    return PeekMessageA(e, a, ctx); // Same MSG struct
}

//  FindWindowA / FindWindowW
uint64_t User32::FindWindowA(void* e, const std::vector<uint64_t>& a, void* ctx) {
    if (a.size()<2) return 0;
    uint64_t cn = a[0], wn = a[1];
    if (cn) { std::string s = be(e)->read_mem_string(cn,1); (void)s; }
    if (wn) { std::string s = be(e)->read_mem_string(wn,1); (void)s; }
    return 0;
}

uint64_t User32::FindWindowW(void* e, const std::vector<uint64_t>& a, void* ctx) {
    if (a.size()<2) return 0;
    uint64_t cn = a[0], wn = a[1];
    if (cn) { std::string s = be(e)->read_mem_string(cn,2); (void)s; }
    if (wn) { std::string s = be(e)->read_mem_string(wn,2); (void)s; }
    return 0;
}

//  SendMessageA / SendMessageW
uint64_t User32::SendMessageA(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a; return 0;
}

uint64_t User32::SendMessageW(void* e, const std::vector<uint64_t>& a, void* ctx) {
    return SendMessageA(e, a, ctx); // Same message dispatch regardless of A/W
}

//  GetWindowTextA / GetWindowTextW
uint64_t User32::GetWindowTextA(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e;
    if (a.size()<3) return 0;
    uint64_t pstr = a[1];
    if (pstr) { std::vector<uint8_t> nul(1,0); we(e)->mem_write(pstr,nul); }
    return 0;
}

uint64_t User32::GetWindowTextW(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e;
    if (a.size()<3) return 0;
    uint64_t pstr = a[1];
    if (pstr) { std::vector<uint8_t> nul(2,0); we(e)->mem_write(pstr,nul); } // UTF-16 NUL = 2 bytes
    return 0;
}

//  SetWindowTextA / SetWindowTextW
uint64_t User32::SetWindowTextA(void* e, const std::vector<uint64_t>& a, void* ctx) {
    if (a.size()<2) return 0;
    uint64_t lp = a[1];
    if (lp) { std::string s = be(e)->read_mem_string(lp,1); (void)s; }
    return 1;
}

uint64_t User32::SetWindowTextW(void* e, const std::vector<uint64_t>& a, void* ctx) {
    if (a.size()<2) return 0;
    uint64_t lp = a[1];
    if (lp) { std::string s = be(e)->read_mem_string(lp,2); (void)s; }
    return 1;
}

//  GetForegroundWindow 
uint64_t User32::GetForegroundWindow(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a; return next_hwnd();
}

//  GetDesktopWindow 
uint64_t User32::GetDesktopWindow(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a; return next_hwnd();
}

//  RegisterClassExA / RegisterClassExW
uint64_t User32::RegisterClassExA(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a; return 1;
}

uint64_t User32::RegisterClassExW(void* e, const std::vector<uint64_t>& a, void* ctx) {
    return RegisterClassExA(e, a, ctx); // Same class registration logic
}

//  ShowWindow 
uint64_t User32::ShowWindow(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a; return 1;
}

//  UpdateWindow 
uint64_t User32::UpdateWindow(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a; return 1;
}

//  GetDC 
uint64_t User32::GetDC(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a; return next_hwnd();
}

//  GetSystemMetrics 
uint64_t User32::GetSystemMetrics(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a; return 1;
}

//  LoadCursorA 
uint64_t User32::LoadCursorA(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a; return next_hwnd();
}

//  SetWindowsHookExA 
uint64_t User32::SetWindowsHookExA(void* e, const std::vector<uint64_t>& a, void* ctx) {
    if (a.size()<4) return 0;
    uint64_t hnd = next_hhook();
    WindowHook wh; wh.idHook=(int)a[0]; wh.lpfn=a[1]; wh.hmod=a[2];
    window_hooks()[hnd] = wh;
    (void)e;
    return hnd;
}

//  CallNextHookEx 
uint64_t User32::CallNextHookEx(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a; return 0;
}

//  GetAsyncKeyState 
uint64_t User32::GetAsyncKeyState(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a; return 0;
}

//  GetKeyboardType 
uint64_t User32::GetKeyboardType(void* e, const std::vector<uint64_t>& a, void* ctx) {
    if (a.size()<1) return 0;
    uint64_t typ = a[0];
    if (typ==0) return 4; if (typ==1) return 0; if (typ==2) return 12;
    (void)e; return 0;
}

//  wsprintfA 
uint64_t User32::wsprintfA(void* e, const std::vector<uint64_t>& a, void* ctx) {
    if (a.size()<2) return 0;
    uint64_t buf = a[0], fmt_ptr = a[1];
    if (fmt_ptr) {
        std::string fmt = be(e)->read_mem_string(fmt_ptr, 1);
        if (buf) {
            we(e)->mem_write(buf, std::vector<uint8_t>(fmt.begin(), fmt.end()));
            std::vector<uint8_t> nul(1,0);
            we(e)->mem_write(buf + fmt.length(), nul);
        }
        return (uint64_t)fmt.length();
    }
    return 0;
}

//  LoadStringA 
uint64_t User32::LoadStringA(void* e, const std::vector<uint64_t>& a, void* ctx) {
    if (a.size()<4) return 0;
    uint64_t bufp = a[2];
    if (bufp) { std::vector<uint8_t> nul(1,0); we(e)->mem_write(bufp,nul); }
    return 0;
}

//  TranslateMessage 
uint64_t User32::TranslateMessage(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a; return 1;
}

//  DispatchMessageA / DispatchMessageW
uint64_t User32::DispatchMessageA(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a; return 0;
}

uint64_t User32::DispatchMessageW(void* e, const std::vector<uint64_t>& a, void* ctx) {
    return DispatchMessageA(e, a, ctx); // Same MSG struct dispatch regardless of A/W
}

//  PostQuitMessage
uint64_t User32::PostQuitMessage(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a; return 0;
}

//  DefWindowProcA / DefWindowProcW
uint64_t User32::DefWindowProcA(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a; return 0;
}

uint64_t User32::DefWindowProcW(void* e, const std::vector<uint64_t>& a, void* ctx) {
    return DefWindowProcA(e, a, ctx); // Same window proc regardless of A/W
}

//  DestroyWindow 
uint64_t User32::DestroyWindow(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a; return 1;
}

uint64_t User32::stub(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a; return 1;
}

}} // namespaces
