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
static uint64_t MessageBoxA(void*, const std::vector<uint64_t>&, void* ctx);
static uint64_t MessageBoxW(void*, const std::vector<uint64_t>&, void* ctx);
static uint64_t GetMessageA(void*, const std::vector<uint64_t>&, void* ctx);
static uint64_t PeekMessageA(void*, const std::vector<uint64_t>&, void* ctx);
static uint64_t FindWindowA(void*, const std::vector<uint64_t>&, void* ctx);
static uint64_t SendMessageA(void*, const std::vector<uint64_t>&, void* ctx);
static uint64_t GetWindowTextA(void*, const std::vector<uint64_t>&, void* ctx);
static uint64_t SetWindowTextA(void*, const std::vector<uint64_t>&, void* ctx);
static uint64_t GetForegroundWindow(void*, const std::vector<uint64_t>&, void* ctx);
static uint64_t GetDesktopWindow(void*, const std::vector<uint64_t>&, void* ctx);
static uint64_t CreateWindowEx_hook(void*, const std::vector<uint64_t>&, void* ctx);
static uint64_t RegisterClassExA(void*, const std::vector<uint64_t>&, void* ctx);
static uint64_t ShowWindow(void*, const std::vector<uint64_t>&, void* ctx);
static uint64_t UpdateWindow(void*, const std::vector<uint64_t>&, void* ctx);
static uint64_t GetDC(void*, const std::vector<uint64_t>&, void* ctx);
static uint64_t GetSystemMetrics(void*, const std::vector<uint64_t>&, void* ctx);
static uint64_t LoadCursorA(void*, const std::vector<uint64_t>&, void* ctx);
static uint64_t SetWindowsHookExA(void*, const std::vector<uint64_t>&, void* ctx);
static uint64_t CallNextHookEx(void*, const std::vector<uint64_t>&, void* ctx);
static uint64_t GetAsyncKeyState(void*, const std::vector<uint64_t>&, void* ctx);
static uint64_t GetKeyboardType(void*, const std::vector<uint64_t>&, void* ctx);
static uint64_t wsprintfA(void*, const std::vector<uint64_t>&, void* ctx);
static uint64_t LoadStringA(void*, const std::vector<uint64_t>&, void* ctx);
static uint64_t TranslateMessage(void*, const std::vector<uint64_t>&, void* ctx);
static uint64_t DispatchMessageA(void*, const std::vector<uint64_t>&, void* ctx);
static uint64_t PostQuitMessage(void*, const std::vector<uint64_t>&, void* ctx);
static uint64_t DefWindowProcA(void*, const std::vector<uint64_t>&, void* ctx);
static uint64_t DestroyWindow(void*, const std::vector<uint64_t>&, void* ctx);
static uint64_t stub(void*, const std::vector<uint64_t>&, void* ctx);
};
}} 
#endif
