// ws2_32.h — ws2_32.dll (Winsock) API handler
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
    static uint64_t WSAStartup(void*,const std::string&,int,const std::vector<uint64_t>&);
    static uint64_t WSASocketA(void*,const std::string&,int,const std::vector<uint64_t>&);
    static uint64_t connect(void*,const std::string&,int,const std::vector<uint64_t>&);
    static uint64_t send(void*,const std::string&,int,const std::vector<uint64_t>&);
    static uint64_t recv(void*,const std::string&,int,const std::vector<uint64_t>&);
    static uint64_t closesocket(void*,const std::string&,int,const std::vector<uint64_t>&);
    static uint64_t bind(void*,const std::string&,int,const std::vector<uint64_t>&);
    static uint64_t listen(void*,const std::string&,int,const std::vector<uint64_t>&);
    static uint64_t accept(void*,const std::string&,int,const std::vector<uint64_t>&);
    static uint64_t gethostbyname(void*,const std::string&,int,const std::vector<uint64_t>&);
    static uint64_t WSAGetLastError(void*,const std::string&,int,const std::vector<uint64_t>&);
    static uint64_t inet_addr(void*,const std::string&,int,const std::vector<uint64_t>&);
    static uint64_t htons(void*,const std::string&,int,const std::vector<uint64_t>&);
    static uint64_t select(void*,const std::string&,int,const std::vector<uint64_t>&);
    static uint64_t stub(void*,const std::string&,int,const std::vector<uint64_t>&);
};
}} // namespaces
#endif
