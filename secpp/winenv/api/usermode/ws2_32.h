// ws2_32.h  ws2_32.dll (Winsock) API handler
#ifndef SPEAKEASY_WS2_32_H
#define SPEAKEASY_WS2_32_H
#include <string>
#include <vector>
#include "../api.h"
namespace speakeasy { namespace api {
class Ws2_32 : public ApiHandler {
public:
    Ws2_32(void* emu);
    std::string get_name() const override { return "ws2_32"; }
    const std::vector<ApiEntry>& get_apis() const override { return apis_; }
private:
    std::vector<ApiEntry> apis_;
    static uint64_t WSAStartup(void*, ArgList&, void* ctx);
    static uint64_t WSASocketA(void*, ArgList&, void* ctx);
    static uint64_t connect(void*, ArgList&, void* ctx);
    static uint64_t send(void*, ArgList&, void* ctx);
    static uint64_t recv(void*, ArgList&, void* ctx);
    static uint64_t closesocket(void*, ArgList&, void* ctx);
    static uint64_t bind(void*, ArgList&, void* ctx);
    static uint64_t listen(void*, ArgList&, void* ctx);
    static uint64_t accept(void*, ArgList&, void* ctx);
    static uint64_t gethostbyname(void*, ArgList&, void* ctx);
    static uint64_t WSAGetLastError(void*, ArgList&, void* ctx);
    static uint64_t inet_addr(void*, ArgList&, void* ctx);
    static uint64_t htons(void*, ArgList&, void* ctx);
    static uint64_t select(void*, ArgList&, void* ctx);
    static uint64_t stub(void*, ArgList&, void* ctx);
};
}} // namespaces
#endif
