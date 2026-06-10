// user32.h
#ifndef SPEAKEASY_USER32_H
#define SPEAKEASY_USER32_H
#include <string>
#include <vector>
#include "../api.h"
namespace speakeasy { namespace api {
class User32 : public ApiHandler {
public: User32(void* emu); std::string get_name() const override {return "user32";}
const std::vector<ApiEntry>& get_apis() const override {return apis_;}
private: std::vector<ApiEntry> apis_;
static uint64_t MessageBoxA(void*, ArgList&, void* ctx);
static uint64_t MessageBoxW(void*, ArgList&, void* ctx);
static uint64_t GetMessageA(void*, ArgList&, void* ctx);
static uint64_t GetMessageW(void*, ArgList&, void* ctx);
static uint64_t PeekMessageA(void*, ArgList&, void* ctx);
static uint64_t PeekMessageW(void*, ArgList&, void* ctx);
static uint64_t FindWindowA(void*, ArgList&, void* ctx);
static uint64_t FindWindowW(void*, ArgList&, void* ctx);
static uint64_t SendMessageA(void*, ArgList&, void* ctx);
static uint64_t SendMessageW(void*, ArgList&, void* ctx);
static uint64_t GetWindowTextA(void*, ArgList&, void* ctx);
static uint64_t GetWindowTextW(void*, ArgList&, void* ctx);
static uint64_t SetWindowTextA(void*, ArgList&, void* ctx);
static uint64_t SetWindowTextW(void*, ArgList&, void* ctx);
static uint64_t GetForegroundWindow(void*, ArgList&, void* ctx);
static uint64_t GetDesktopWindow(void*, ArgList&, void* ctx);
static uint64_t CreateWindowExA(void*, ArgList&, void* ctx);
static uint64_t CreateWindowExW(void*, ArgList&, void* ctx);
static uint64_t RegisterClassExA(void*, ArgList&, void* ctx);
static uint64_t RegisterClassExW(void*, ArgList&, void* ctx);
static uint64_t ShowWindow(void*, ArgList&, void* ctx);
static uint64_t UpdateWindow(void*, ArgList&, void* ctx);
static uint64_t GetDC(void*, ArgList&, void* ctx);
static uint64_t GetSystemMetrics(void*, ArgList&, void* ctx);
static uint64_t LoadCursorA(void*, ArgList&, void* ctx);
static uint64_t LoadCursorW(void*, ArgList&, void* ctx);
static uint64_t SetWindowsHookExA(void*, ArgList&, void* ctx);
static uint64_t SetWindowsHookExW(void*, ArgList&, void* ctx);
static uint64_t CallNextHookEx(void*, ArgList&, void* ctx);
static uint64_t GetAsyncKeyState(void*, ArgList&, void* ctx);
static uint64_t GetKeyboardType(void*, ArgList&, void* ctx);
static uint64_t wsprintfA(void*, ArgList&, void* ctx);
static uint64_t wsprintfW(void*, ArgList&, void* ctx);
static uint64_t LoadStringA(void*, ArgList&, void* ctx);
static uint64_t LoadStringW(void*, ArgList&, void* ctx);
static uint64_t TranslateMessage(void*, ArgList&, void* ctx);
static uint64_t DispatchMessageA(void*, ArgList&, void* ctx);
static uint64_t DispatchMessageW(void*, ArgList&, void* ctx);
static uint64_t PostQuitMessage(void*, ArgList&, void* ctx);
static uint64_t DefWindowProcA(void*, ArgList&, void* ctx);
static uint64_t DefWindowProcW(void*, ArgList&, void* ctx);
static uint64_t DestroyWindow(void*, ArgList&, void* ctx);
static uint64_t stub(void*, ArgList&, void* ctx);
};
}} 
#endif
