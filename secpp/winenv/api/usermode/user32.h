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
static uint64_t MessageBoxA(void*, std::vector<uint64_t>&, void* ctx);
static uint64_t MessageBoxW(void*, std::vector<uint64_t>&, void* ctx);
static uint64_t GetMessageA(void*, std::vector<uint64_t>&, void* ctx);
static uint64_t GetMessageW(void*, std::vector<uint64_t>&, void* ctx);
static uint64_t PeekMessageA(void*, std::vector<uint64_t>&, void* ctx);
static uint64_t PeekMessageW(void*, std::vector<uint64_t>&, void* ctx);
static uint64_t FindWindowA(void*, std::vector<uint64_t>&, void* ctx);
static uint64_t FindWindowW(void*, std::vector<uint64_t>&, void* ctx);
static uint64_t SendMessageA(void*, std::vector<uint64_t>&, void* ctx);
static uint64_t SendMessageW(void*, std::vector<uint64_t>&, void* ctx);
static uint64_t GetWindowTextA(void*, std::vector<uint64_t>&, void* ctx);
static uint64_t GetWindowTextW(void*, std::vector<uint64_t>&, void* ctx);
static uint64_t SetWindowTextA(void*, std::vector<uint64_t>&, void* ctx);
static uint64_t SetWindowTextW(void*, std::vector<uint64_t>&, void* ctx);
static uint64_t GetForegroundWindow(void*, std::vector<uint64_t>&, void* ctx);
static uint64_t GetDesktopWindow(void*, std::vector<uint64_t>&, void* ctx);
static uint64_t CreateWindowExA(void*, std::vector<uint64_t>&, void* ctx);
static uint64_t CreateWindowExW(void*, std::vector<uint64_t>&, void* ctx);
static uint64_t RegisterClassExA(void*, std::vector<uint64_t>&, void* ctx);
static uint64_t RegisterClassExW(void*, std::vector<uint64_t>&, void* ctx);
static uint64_t ShowWindow(void*, std::vector<uint64_t>&, void* ctx);
static uint64_t UpdateWindow(void*, std::vector<uint64_t>&, void* ctx);
static uint64_t GetDC(void*, std::vector<uint64_t>&, void* ctx);
static uint64_t GetSystemMetrics(void*, std::vector<uint64_t>&, void* ctx);
static uint64_t LoadCursorA(void*, std::vector<uint64_t>&, void* ctx);
static uint64_t LoadCursorW(void*, std::vector<uint64_t>&, void* ctx);
static uint64_t SetWindowsHookExA(void*, std::vector<uint64_t>&, void* ctx);
static uint64_t SetWindowsHookExW(void*, std::vector<uint64_t>&, void* ctx);
static uint64_t CallNextHookEx(void*, std::vector<uint64_t>&, void* ctx);
static uint64_t GetAsyncKeyState(void*, std::vector<uint64_t>&, void* ctx);
static uint64_t GetKeyboardType(void*, std::vector<uint64_t>&, void* ctx);
static uint64_t wsprintfA(void*, std::vector<uint64_t>&, void* ctx);
static uint64_t wsprintfW(void*, std::vector<uint64_t>&, void* ctx);
static uint64_t LoadStringA(void*, std::vector<uint64_t>&, void* ctx);
static uint64_t LoadStringW(void*, std::vector<uint64_t>&, void* ctx);
static uint64_t TranslateMessage(void*, std::vector<uint64_t>&, void* ctx);
static uint64_t DispatchMessageA(void*, std::vector<uint64_t>&, void* ctx);
static uint64_t DispatchMessageW(void*, std::vector<uint64_t>&, void* ctx);
static uint64_t PostQuitMessage(void*, std::vector<uint64_t>&, void* ctx);
static uint64_t DefWindowProcA(void*, std::vector<uint64_t>&, void* ctx);
static uint64_t DefWindowProcW(void*, std::vector<uint64_t>&, void* ctx);
static uint64_t DestroyWindow(void*, std::vector<uint64_t>&, void* ctx);
static uint64_t stub(void*, std::vector<uint64_t>&, void* ctx);
};
}} 
#endif
