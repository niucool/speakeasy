// wsk.cpp  Winsock Kernel handler (implemented)
#include "wsk.h"

#include <cstdint>
#include <vector>
#include <string>

#include "memmgr.h"
#include "struct.h"
#include "winenv/arch.h"
#include "windows/winemu.h"

using namespace speakeasy;

namespace speakeasy { namespace api { namespace kernelmode {

//  Typed cast helpers 
static inline WindowsEmulator* we(void* e) { return static_cast<WindowsEmulator*>(e); }
static inline BinaryEmulator* be(void* e) { return static_cast<BinaryEmulator*>(e); }
static inline MemoryManager* mm(void* e) { return static_cast<MemoryManager*>(e); }
static inline int ptr_sz(void* e) { return we(e)->get_ptr_size(); }

Wsk::Wsk(void* emu) : ApiHandler(emu) {
    INIT_API_TABLE(Wsk)
    REG(Wsk, WskRegister, 2)
    REG(Wsk, WskCaptureProviderNPI, 3)
    REG(Wsk, WskReleaseProviderNPI, 1)
    REG(Wsk, WskDeregister, 1)
    REG(Wsk, WskSocket, 11)
    REG(Wsk, WskSocketConnect, 12)
    REG(Wsk, WskControlClient, 8)
    REG(Wsk, WskGetAddressInfo, 10)
    REG(Wsk, WskFreeAddressInfo, 2)
    REG(Wsk, WskGetNameInfo, 9)
    REG(Wsk, WskControlSocket, 10)
    REG(Wsk, WskCloseSocket, 2)
    REG(Wsk, WskBind, 4)
    REG(Wsk, WskSendTo, 7)
    REG(Wsk, WskReceiveFrom, 8)
    REG(Wsk, WskRelease, 2)
    REG(Wsk, WskGetLocalAddress, 2)
    END_API_TABLE
}

//  Internal helpers 
static constexpr int WSK_SUCCESS = 0;

//  Implementations 

uint64_t Wsk::WskRegister(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // NTSTATUS WskRegister(WSK_CLIENT_NPI *ClientNpi, WSK_REGISTRATION *WskRegistration)
    (void)e; (void)a;
    return WSK_SUCCESS;
}

uint64_t Wsk::WskCaptureProviderNPI(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // NTSTATUS WskCaptureProviderNPI(WSK_REGISTRATION *WskRegistration, ULONG WaitTimeout, WSK_PROVIDER_NPI *WskProviderNpi)
    uint64_t wsk_provider = a[2];
    if (wsk_provider) {
        // Allocate a WSK_PROVIDER_NPI structure  just write a dummy dispatch table pointer
        size_t psz = static_cast<size_t>(ptr_sz(e));
        auto data = std::vector<uint8_t>(psz, 0);
        // Write a dummy dispatch pointer
        uint64_t dummy_dispatch = mm(e)->mem_map(psz, 0, common::PERM_MEM_RWX, "wsk.dispatch");
        write_le(data, 0, dummy_dispatch, psz);
        mm(e)->mem_write(wsk_provider, data);
    }
    return WSK_SUCCESS;
}

uint64_t Wsk::WskReleaseProviderNPI(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // VOID WskReleaseProviderNPI(WSK_REGISTRATION *WskRegistration)
    (void)e; (void)a;
    return WSK_SUCCESS;
}

uint64_t Wsk::WskDeregister(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // NTSTATUS WskDeregister(WSK_REGISTRATION *WskRegistration)
    (void)e; (void)a;
    return WSK_SUCCESS;
}

uint64_t Wsk::WskSocket(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // PWSK_SOCKET WskSocket(...)
    // Return a dummy socket pointer
    size_t psz = static_cast<size_t>(ptr_sz(e));
    (void)psz;
    uint64_t sock = mm(e)->mem_map(256, 0, common::PERM_MEM_RWX, "wsk.socket");
    return sock;
}

uint64_t Wsk::WskSocketConnect(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // PWSK_SOCKET WskSocketConnect(...)
    (void)e; (void)a;
    return 0;
}

uint64_t Wsk::WskControlClient(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // NTSTATUS WskControlClient(...)
    (void)e; (void)a;
    return WSK_SUCCESS;
}

uint64_t Wsk::WskGetAddressInfo(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // NTSTATUS WskGetAddressInfo(...)
    (void)e; (void)a;
    return 0x000000C0000135L; // STATUS_NOT_FOUND
}

uint64_t Wsk::WskFreeAddressInfo(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // VOID WskFreeAddressInfo(...)
    (void)e; (void)a;
    return WSK_SUCCESS;
}

uint64_t Wsk::WskGetNameInfo(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // NTSTATUS WskGetNameInfo(...)
    (void)e; (void)a;
    return 0x000000C0000135L; // STATUS_NOT_FOUND
}

uint64_t Wsk::WskControlSocket(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // NTSTATUS WskControlSocket(...)
    (void)e; (void)a;
    return WSK_SUCCESS;
}

uint64_t Wsk::WskCloseSocket(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // NTSTATUS WskCloseSocket(PWSK_SOCKET Socket, ...)
    (void)e; (void)a;
    return WSK_SUCCESS;
}

uint64_t Wsk::WskBind(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // NTSTATUS WskBind(...)
    (void)e; (void)a;
    return WSK_SUCCESS;
}

uint64_t Wsk::WskSendTo(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // NTSTATUS WskSendTo(...)
    (void)e; (void)a;
    return WSK_SUCCESS;
}

uint64_t Wsk::WskReceiveFrom(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // NTSTATUS WskReceiveFrom(...)
    (void)e; (void)a;
    return WSK_SUCCESS;
}

uint64_t Wsk::WskRelease(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // VOID WskRelease(...)
    (void)e; (void)a;
    return WSK_SUCCESS;
}

uint64_t Wsk::WskGetLocalAddress(void* e, const std::vector<uint64_t>& a, void* ctx) {
    // NTSTATUS WskGetLocalAddress(...)
    (void)e; (void)a;
    return WSK_SUCCESS;
}

}}} // namespaces
