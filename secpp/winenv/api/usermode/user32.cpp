// user32.cpp — user32.dll handler — real implementations
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

// ── Handle management ────────────────────────────────────────
static uint64_t next_hwnd() {
    static uint64_t h = 0x10000;
    return ++h;
}

static uint64_t next_hhook() {
    static uint64_t h = 0x20000;
    return ++h;
}

// ── Window hooks store ───────────────────────────────────────
struct WindowHook { int idHook; uint64_t lpfn; uint64_t hmod; };
static std::map<uint64_t, WindowHook>& window_hooks() {
    static std::map<uint64_t, WindowHook> h;
    return h;
}

// ── Constructor ──────────────────────────────────────────────
User32::User32() {
    apis_.push_back({"MessageBoxA",4,MessageBoxA});
    apis_.push_back({"MessageBoxW",4,MessageBoxW});
    apis_.push_back({"GetMessageA",4,GetMessageA});
    apis_.push_back({"PeekMessageA",5,PeekMessageA});
    apis_.push_back({"FindWindowA",2,FindWindowA});
    apis_.push_back({"SendMessageA",4,SendMessageA});
    apis_.push_back({"GetWindowTextA",3,GetWindowTextA});
    apis_.push_back({"SetWindowTextA",2,SetWindowTextA});
    apis_.push_back({"GetForegroundWindow",0,GetForegroundWindow});
    apis_.push_back({"GetDesktopWindow",0,GetDesktopWindow});
    apis_.push_back({"CreateWindowExA",12,CreateWindowEx_hook});
    apis_.push_back({"CreateWindowExW",12,CreateWindowEx_hook});
    apis_.push_back({"RegisterClassExA",1,RegisterClassExA});
    apis_.push_back({"ShowWindow",2,ShowWindow});
    apis_.push_back({"UpdateWindow",1,UpdateWindow});
    apis_.push_back({"GetDC",1,GetDC});
    apis_.push_back({"GetSystemMetrics",1,GetSystemMetrics});
    apis_.push_back({"LoadCursorA",2,LoadCursorA});
    apis_.push_back({"LoadCursorW",2,LoadCursorA});
    apis_.push_back({"SetWindowsHookExA",4,SetWindowsHookExA});
    apis_.push_back({"SetWindowsHookExW",4,SetWindowsHookExA});
    apis_.push_back({"CallNextHookEx",4,CallNextHookEx});
    apis_.push_back({"GetAsyncKeyState",1,GetAsyncKeyState});
    apis_.push_back({"GetKeyboardType",1,GetKeyboardType});
    apis_.push_back({"wsprintfA",0,wsprintfA});
    apis_.push_back({"wsprintfW",0,wsprintfA});
    apis_.push_back({"LoadStringA",4,LoadStringA});
    apis_.push_back({"LoadStringW",4,LoadStringA});
    apis_.push_back({"TranslateMessage",1,TranslateMessage});
    apis_.push_back({"DispatchMessageA",1,DispatchMessageA});
    apis_.push_back({"PostQuitMessage",1,PostQuitMessage});
    apis_.push_back({"DefWindowProcA",4,DefWindowProcA});
    apis_.push_back({"DestroyWindow",1,DestroyWindow});
}

// ═══════════════════════════════════════════════════════════════
// API implementations
// ═══════════════════════════════════════════════════════════════

// ── MessageBoxA / MessageBoxW ──────────────────────────────
uint64_t User32::MessageBoxA(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    if (a.size()<4) return 2;
    uint64_t lpText = a[1], lpCaption = a[2];
    if (lpText) { std::string s = be(e)->read_mem_string(lpText,1); (void)s; }
    if (lpCaption) { std::string s = be(e)->read_mem_string(lpCaption,1); (void)s; }
    return 2; // IDCANCEL
}

uint64_t User32::MessageBoxW(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    if (a.size()<4) return 2;
    uint64_t lpText = a[1], lpCaption = a[2];
    if (lpText) { std::string s = be(e)->read_mem_string(lpText,2); (void)s; }
    if (lpCaption) { std::string s = be(e)->read_mem_string(lpCaption,2); (void)s; }
    return 2; // IDCANCEL
}

// ── GetMessageA ─────────────────────────────────────────────
uint64_t User32::GetMessageA(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
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

// ── PeekMessageA ───────────────────────────────────────────
uint64_t User32::PeekMessageA(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    (void)e; (void)a; return 0;
}

// ── FindWindowA ─────────────────────────────────────────────
uint64_t User32::FindWindowA(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    if (a.size()<2) return 0;
    uint64_t cn = a[0], wn = a[1];
    if (cn) { std::string s = be(e)->read_mem_string(cn,1); (void)s; }
    if (wn) { std::string s = be(e)->read_mem_string(wn,1); (void)s; }
    return 0;
}

// ── SendMessageA ────────────────────────────────────────────
uint64_t User32::SendMessageA(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    (void)e; (void)a; return 0;
}

// ── GetWindowTextA ──────────────────────────────────────────
uint64_t User32::GetWindowTextA(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    (void)e;
    if (a.size()<3) return 0;
    uint64_t pstr = a[1];
    if (pstr) { std::vector<uint8_t> nul(1,0); we(e)->mem_write(pstr,nul); }
    return 0;
}

// ── SetWindowTextA ──────────────────────────────────────────
uint64_t User32::SetWindowTextA(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    if (a.size()<2) return 0;
    uint64_t lp = a[1];
    if (lp) { std::string s = be(e)->read_mem_string(lp,1); (void)s; }
    return 1;
}

// ── GetForegroundWindow ─────────────────────────────────────
uint64_t User32::GetForegroundWindow(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    (void)e; (void)a; return next_hwnd();
}

// ── GetDesktopWindow ───────────────────────────────────────
uint64_t User32::GetDesktopWindow(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    (void)e; (void)a; return next_hwnd();
}

// ── CreateWindowEx_hook ───────────────────────────────────────
uint64_t User32::CreateWindowEx_hook(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    if (a.size()<3) return 0;
    uint64_t cn = a[1], wn = a[2];
    if (cn) { std::string s = be(e)->read_mem_string(cn,1); (void)s; }
    if (wn) { std::string s = be(e)->read_mem_string(wn,1); (void)s; }
    return next_hwnd();
}

// ── RegisterClassExA ────────────────────────────────────────
uint64_t User32::RegisterClassExA(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    (void)e; (void)a; return 1;
}

// ── ShowWindow ──────────────────────────────────────────────
uint64_t User32::ShowWindow(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    (void)e; (void)a; return 1;
}

// ── UpdateWindow ────────────────────────────────────────────
uint64_t User32::UpdateWindow(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    (void)e; (void)a; return 1;
}

// ── GetDC ───────────────────────────────────────────────────
uint64_t User32::GetDC(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    (void)e; (void)a; return next_hwnd();
}

// ── GetSystemMetrics ────────────────────────────────────────
uint64_t User32::GetSystemMetrics(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    (void)e; (void)a; return 1;
}

// ── LoadCursorA ─────────────────────────────────────────────
uint64_t User32::LoadCursorA(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    (void)e; (void)a; return next_hwnd();
}

// ── SetWindowsHookExA ───────────────────────────────────────
uint64_t User32::SetWindowsHookExA(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    if (a.size()<4) return 0;
    uint64_t hnd = next_hhook();
    WindowHook wh; wh.idHook=(int)a[0]; wh.lpfn=a[1]; wh.hmod=a[2];
    window_hooks()[hnd] = wh;
    (void)e;
    return hnd;
}

// ── CallNextHookEx ──────────────────────────────────────────
uint64_t User32::CallNextHookEx(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    (void)e; (void)a; return 0;
}

// ── GetAsyncKeyState ────────────────────────────────────────
uint64_t User32::GetAsyncKeyState(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    (void)e; (void)a; return 0;
}

// ── GetKeyboardType ─────────────────────────────────────────
uint64_t User32::GetKeyboardType(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    if (a.size()<1) return 0;
    uint64_t typ = a[0];
    if (typ==0) return 4; if (typ==1) return 0; if (typ==2) return 12;
    (void)e; return 0;
}

// ── wsprintfA ───────────────────────────────────────────────
uint64_t User32::wsprintfA(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
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

// ── LoadStringA ─────────────────────────────────────────────
uint64_t User32::LoadStringA(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    if (a.size()<4) return 0;
    uint64_t bufp = a[2];
    if (bufp) { std::vector<uint8_t> nul(1,0); we(e)->mem_write(bufp,nul); }
    return 0;
}

// ── TranslateMessage ───────────────────────────────────────
uint64_t User32::TranslateMessage(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    (void)e; (void)a; return 1;
}

// ── DispatchMessageA ────────────────────────────────────────
uint64_t User32::DispatchMessageA(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    (void)e; (void)a; return 0;
}

// ── PostQuitMessage ─────────────────────────────────────────
uint64_t User32::PostQuitMessage(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    (void)e; (void)a; return 0;
}

// ── DefWindowProcA ──────────────────────────────────────────
uint64_t User32::DefWindowProcA(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    (void)e; (void)a; return 0;
}

// ── DestroyWindow ───────────────────────────────────────────
uint64_t User32::DestroyWindow(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    (void)e; (void)a; return 1;
}

uint64_t User32::stub(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    (void)e; (void)a; return 1;
}

}} // namespaces
