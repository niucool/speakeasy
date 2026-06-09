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
    static uint64_t WSAStartup(void*, std::vector<uint64_t>&, void* ctx);
    static uint64_t WSASocketA(void*, std::vector<uint64_t>&, void* ctx);
    static uint64_t connect(void*, std::vector<uint64_t>&, void* ctx);
    static uint64_t send(void*, std::vector<uint64_t>&, void* ctx);
    static uint64_t recv(void*, std::vector<uint64_t>&, void* ctx);
    static uint64_t closesocket(void*, std::vector<uint64_t>&, void* ctx);
    static uint64_t bind(void*, std::vector<uint64_t>&, void* ctx);
    static uint64_t listen(void*, std::vector<uint64_t>&, void* ctx);
    static uint64_t accept(void*, std::vector<uint64_t>&, void* ctx);
    static uint64_t gethostbyname(void*, std::vector<uint64_t>&, void* ctx);
    static uint64_t WSAGetLastError(void*, std::vector<uint64_t>&, void* ctx);
    static uint64_t inet_addr(void*, std::vector<uint64_t>&, void* ctx);
    static uint64_t htons(void*, std::vector<uint64_t>&, void* ctx);
    static uint64_t select(void*, std::vector<uint64_t>&, void* ctx);
    static uint64_t stub(void*, std::vector<uint64_t>&, void* ctx);
};
}} // namespaces
#endif
