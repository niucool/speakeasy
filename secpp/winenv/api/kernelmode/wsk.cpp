// wsk.cpp — Winsock Kernel handler (STUB)
#include "wsk.h"

namespace speakeasy { namespace api { namespace kernelmode {

Wsk::Wsk() {
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

#define WK_STUB(n) KERNEL_STUB(Wsk, n)
WK_STUB(WskRegister)            WK_STUB(WskCaptureProviderNPI)
WK_STUB(WskReleaseProviderNPI)  WK_STUB(WskDeregister)
WK_STUB(WskSocket)              WK_STUB(WskSocketConnect)
WK_STUB(WskControlClient)       WK_STUB(WskGetAddressInfo)
WK_STUB(WskFreeAddressInfo)     WK_STUB(WskGetNameInfo)
WK_STUB(WskControlSocket)       WK_STUB(WskCloseSocket)
WK_STUB(WskBind)                WK_STUB(WskSendTo)
WK_STUB(WskReceiveFrom)         WK_STUB(WskRelease)
WK_STUB(WskGetLocalAddress)

}}} // namespaces
