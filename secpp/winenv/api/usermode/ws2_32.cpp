// ws2_32.cpp
#include "ws2_32.h"
namespace speakeasy { namespace api {
#define STUB(n) uint64_t Ws2_32::n(void*e,const std::string&,int,const std::vector<uint64_t>&a){(void)e;(void)a;return 1;}
Ws2_32::Ws2_32(){apis_={
    {"WSAStartup",4,WSAStartup},{"WSASocketA",6,WSASocketA},{"connect",3,connect},
    {"send",4,send},{"recv",4,recv},{"closesocket",1,closesocket},
    {"bind",3,bind},{"listen",2,listen},{"accept",3,accept},
    {"gethostbyname",1,gethostbyname},{"WSAGetLastError",0,WSAGetLastError},
    {"inet_addr",1,inet_addr},{"htons",1,htons},{"select",5,select},
};}
STUB(WSAStartup) STUB(WSASocketA) STUB(connect) STUB(send) STUB(recv)
STUB(closesocket) STUB(bind) STUB(listen) STUB(accept) STUB(gethostbyname)
STUB(WSAGetLastError) STUB(inet_addr) STUB(htons) STUB(select)
uint64_t Ws2_32::stub(void*e,const std::string&,int,const std::vector<uint64_t>&a){(void)e;(void)a;return 1;}
}}
