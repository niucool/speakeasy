// ws2_32.cpp  ws2_32.dll (Winsock) API handler  real implementations
#include "ws2_32.h"
#include <cstring>
#include <cstdint>
#include <string>
#include <vector>
#include <map>
#include "windows/winemu.h"
#include "struct.h"

using namespace speakeasy;

namespace speakeasy { namespace api {

static inline WindowsEmulator* we(void* e) { return static_cast<WindowsEmulator*>(e); }
static inline BinaryEmulator* be(void* e) { return static_cast<BinaryEmulator*>(e); }

//  Socket handle management 
static int next_socket_handle() {
    static int h = 0x100;
    return ++h;
}

//  WSAStartup 
// int WSAStartup(WORD wVersionRequired, LPWSADATA lpWSAData);
uint64_t Ws2_32::WSAStartup(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    if (a.size() < 2) return -1;
    uint64_t lpWSAData = a[1];
    if (lpWSAData) {
        // WSAData layout: { WORD wVersion, WORD wHighVersion, char szDescription[257],
        //                   char szSystemStatus[129], USHORT iMaxSockets, USHORT iMaxUdpDg,
        //                   char FAR* lpVendorInfo }
        std::vector<uint8_t> buf(512, 0);
        write_le(buf, 0, 0x0101, 2);   // wVersion = 1.1
        write_le(buf, 2, 0x0202, 2);   // wHighVersion = 2.2
        write_le(buf, 4, 0, 257);      // szDescription (empty)
        write_le(buf, 261, 0, 129);    // szSystemStatus (empty)
        write_le(buf, 390, 0x1000, 2); // iMaxSockets
        write_le(buf, 392, 0x1000, 2); // iMaxUdpDg
        write_le(buf, 394, 0, we(e)->get_ptr_size()); // lpVendorInfo
        we(e)->mem_write(lpWSAData, buf);
    }
    return 0; // ERROR_SUCCESS
}

//  WSASocketA 
// SOCKET WSASocketA(int af, int type, int protocol, LPWSAPROTOCOL_INFO lpProtocolInfo,
//                    GROUP g, DWORD dwFlags);
uint64_t Ws2_32::WSASocketA(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    (void)e;
    if (a.size() < 1) return -1;
    return static_cast<uint64_t>(next_socket_handle());
}

//  connect 
// int connect(SOCKET s, const sockaddr* name, int namelen);
uint64_t Ws2_32::connect(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    if (a.size() < 3) return -1;
    uint64_t s = a[0];
    uint64_t pname = a[1];
    uint64_t namelen = a[2];
    (void)s; (void)namelen;

    // Try to read sockaddr_in to log the connection
    if (pname) {
        auto raw = we(e)->mem_read(pname, namelen > 16 ? 8 : static_cast<size_t>(namelen));
        if (raw.size() >= 8) {
            // sockaddr_in: { short sin_family; unsigned short sin_port; struct in_addr sin_addr; ... }
            uint16_t port = static_cast<uint16_t>(read_be(raw, 2, 2));
            (void)port;
        }
    }
    // Log network event via profiler
    auto prof = be(e)->get_profiler();
    if (prof) {
        auto run = std::static_pointer_cast<Run>(we(e)->get_current_run());
        prof->log_network(run, "connected", 0, "connect", "tcp", {}, "winsock.connect");
    }
    return 0; // ERROR_SUCCESS
}

//  send 
// int send(SOCKET s, const char* buf, int len, int flags);
uint64_t Ws2_32::send(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    if (a.size() < 4) return -1;
    uint64_t s = a[0];
    uint64_t buf = a[1];
    uint64_t blen = a[2];
    uint64_t flags = a[3];
    (void)s; (void)flags;

    std::vector<uint8_t> data;
    if (buf && blen) {
        data = we(e)->mem_read(buf, static_cast<size_t>(blen));
    }

    auto prof = be(e)->get_profiler();
    if (prof) {
        auto run = std::static_pointer_cast<Run>(we(e)->get_current_run());
        prof->log_network(run, "", 0, "data_out", "tcp", data, "winsock.send");
    }
    return blen;
}

//  recv 
// int recv(SOCKET s, char* buf, int len, int flags);
uint64_t Ws2_32::recv(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    if (a.size() < 4) return -1;
    uint64_t s = a[0];
    uint64_t buf = a[1];
    uint64_t blen = a[2];
    uint64_t flags = a[3];
    (void)s; (void)flags;
    (void)buf; (void)blen;

    // Return 0 (no data available)  keeps most malware running
    return 0;
}

//  closesocket 
// int closesocket(SOCKET s);
uint64_t Ws2_32::closesocket(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    (void)e;
    if (a.size() < 1) return -1;
    return 0;
}

//  bind 
// int bind(SOCKET s, const sockaddr* addr, int namelen);
uint64_t Ws2_32::bind(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    if (a.size() < 3) return -1;
    uint64_t s = a[0];
    uint64_t pname = a[1];
    uint64_t namelen = a[2];
    (void)s; (void)namelen;

    // Log bind event
    if (pname) {
        auto raw = we(e)->mem_read(pname, namelen > 16 ? 8 : static_cast<size_t>(namelen));
        if (raw.size() >= 8) {
            uint16_t port = static_cast<uint16_t>(read_be(raw, 2, 2));
            auto prof = be(e)->get_profiler();
            if (prof) {
                auto run = std::static_pointer_cast<Run>(we(e)->get_current_run());
                prof->log_network(run, "0.0.0.0", port, "bind", "tcp", {}, "winsock.bind");
            }
        }
    }
    return 0;
}

//  listen 
// int listen(SOCKET s, int backlog);
uint64_t Ws2_32::listen(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    (void)e;
    if (a.size() < 2) return -1;
    return 0;
}

//  accept 
// SOCKET accept(SOCKET s, sockaddr* addr, int* addrlen);
uint64_t Ws2_32::accept(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    if (a.size() < 1) return -1;
    uint64_t addr = a.size() > 1 ? a[1] : 0;

    // Write a fake sockaddr_in if addr is provided
    if (addr) {
        std::vector<uint8_t> sa_buf(16, 0);
        write_le(sa_buf, 0, 2, 2);          // sin_family = AF_INET
        write_le(sa_buf, 2, 0x5C11, 2); // sin_port = 4444 (4444 = 0x115C, but htons = 0x5C11)
        // sin_addr.s_addr = inet_addr("127.0.0.1") = 0x0100007F
        write_le(sa_buf, 4, 0x0100007F, 4);
        we(e)->mem_write(addr, sa_buf);
    }

    // Return a new socket handle
    return static_cast<uint64_t>(next_socket_handle());
}

//  gethostbyname 
// struct hostent* gethostbyname(const char* name);
uint64_t Ws2_32::gethostbyname(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    if (a.size() < 1) return 0;
    uint64_t name_ptr = a[0];

    std::string name;
    if (name_ptr) {
        name = be(e)->read_mem_string(name_ptr, 1);
    }

    if (!name.empty()) {
        auto prof = be(e)->get_profiler();
        if (prof) {
            auto run = std::static_pointer_cast<Run>(we(e)->get_current_run());
            prof->log_dns(run, name, "");
        }
    }

    // Return 0 (failure)  the caller will handle it
    return 0;
}

//  WSAGetLastError 
// int WSAGetLastError();
uint64_t Ws2_32::WSAGetLastError(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    (void)e; (void)a;
    return 0;
}

//  inet_addr 
// unsigned long inet_addr(const char* cp);
uint64_t Ws2_32::inet_addr(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    if (a.size() < 1) return 0xFFFFFFFF;
    uint64_t cp = a[0];
    if (!cp) return 0xFFFFFFFF;

    std::string ip_str = be(e)->read_mem_string(cp, 1);
    if (ip_str.empty()) return 0xFFFFFFFF;

    // Simple IPv4 parsing
    unsigned int b[4] = {0,0,0,0};
    int parsed = sscanf(ip_str.c_str(), "%u.%u.%u.%u", &b[0], &b[1], &b[2], &b[3]);
    if (parsed != 4) return 0xFFFFFFFF;
    for (int i = 0; i < 4; i++) if (b[i] > 255) return 0xFFFFFFFF;

    // Return in network byte order (big-endian), stored as little-endian on x86
    uint32_t ip = (b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3];
    return static_cast<uint64_t>(ip);
}

//  htons 
// u_short htons(u_short hostshort);
uint64_t Ws2_32::htons(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    (void)e;
    if (a.size() < 1) return 0;
    uint16_t val = static_cast<uint16_t>(a[0] & 0xFFFF);
    return static_cast<uint64_t>((val >> 8) | (val << 8));
}
//  select 
// int select(int nfds, fd_set* readfds, fd_set* writefds, fd_set* exceptfds, const timeval* timeout);
uint64_t Ws2_32::select(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    if (a.size() < 5) return 0;
    uint64_t readfds = a[1];
    uint64_t writefds = a[2];
    uint64_t exceptfds = a[3];
    (void)readfds; (void)writefds; (void)exceptfds;

    // Return 0 (no ready handles)  keeps most malware in a loop but won't crash
    return 0;
}

uint64_t Ws2_32::stub(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    (void)e; (void)a; return 1;
}

Ws2_32::Ws2_32(void* emu) : ApiHandler(emu) {
    INIT_API_TABLE(Ws2_32)
    REG(Ws2_32, WSAStartup, 2)
    REG(Ws2_32, WSASocketA, 6)
    REG(Ws2_32, connect, 3)
    REG(Ws2_32, send, 4)
    REG(Ws2_32, recv, 4)
    REG(Ws2_32, closesocket, 1)
    REG(Ws2_32, bind, 3)
    REG(Ws2_32, listen, 2)
    REG(Ws2_32, accept, 3)
    REG(Ws2_32, gethostbyname, 1)
    REG(Ws2_32, WSAGetLastError, 0)
    REG(Ws2_32, inet_addr, 1)
    REG(Ws2_32, htons, 1)
    REG(Ws2_32, select, 5)
    REG(Ws2_32, stub, 0)
    END_API_TABLE
}

}} // namespaces
