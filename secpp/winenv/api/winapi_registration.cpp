// winapi_registration.cpp
#include "api_handler_registry.h"

// Usermode headers
#include "usermode/advapi32.h"
#include "usermode/advpack.h"
#include "usermode/bcrypt.h"
#include "usermode/bcryptprimitives.h"
#include "usermode/com_api.h"
#include "usermode/comctl32.h"
#include "usermode/crypt32.h"
#include "usermode/dnsapi.h"
#include "usermode/gdi32.h"
#include "usermode/iphlpapi.h"
#include "usermode/kernel32.h"
#include "usermode/lz32.h"
#include "usermode/mpr.h"
#include "usermode/mscoree.h"
#include "usermode/msi32.h"
#include "usermode/msimg32.h"
#include "usermode/msvcrt.h"
#include "usermode/msvfw32.h"
#include "usermode/ncrypt.h"
#include "usermode/netapi32.h"
#include "usermode/netutils.h"
#include "usermode/ntdll.h"
#include "usermode/ole32.h"
#include "usermode/oleaut32.h"
#include "usermode/psapi.h"
#include "usermode/rpcrt4.h"
#include "usermode/secur32.h"
#include "usermode/sfc.h"
#include "usermode/sfc_os.h"
#include "usermode/shell32.h"
#include "usermode/shlwapi.h"
#include "usermode/urlmon.h"
#include "usermode/user32.h"
#include "usermode/winhttp.h"
#include "usermode/wininet.h"
#include "usermode/winmm.h"
#include "usermode/wkscli.h"
#include "usermode/ws2_32.h"
#include "usermode/wtsapi32.h"

// Kernelmode headers
#include "kernelmode/fwpkclnt.h"
#include "kernelmode/hal.h"
#include "kernelmode/ndis.h"
#include "kernelmode/netio.h"
#include "kernelmode/ntoskrnl.h"
#include "kernelmode/usbd.h"
#include "kernelmode/wdfldr.h"
#include "kernelmode/wsk.h"

namespace speakeasy {
namespace api {

void register_all_api_handlers() {
    static bool registered = false;
    if (registered) return;
    registered = true;
    using namespace speakeasy::api::kernelmode;

    auto reg = [](const std::string& name, std::function<::ApiHandler*(void*)> factory) {
        ApiHandlerRegistry::register_handler(name, [factory](void* emu) {
            auto* handler = factory(emu);
            return handler;
        });
    };

    //  Usermode Handlers 
    reg("advapi32", [](void* emu) { return new Advapi32(emu); });
    reg("advpack", [](void* emu) { return new Advpack(emu); });
    reg("bcrypt", [](void* emu) { return new Bcrypt(emu); });
    reg("bcryptprimitives", [](void* emu) { return new Bcryptprimitives(emu); });
    reg("com_api", [](void* emu) { return new ComApi(emu); });
    reg("comctl32", [](void* emu) { return new Comctl32(emu); });
    reg("crypt32", [](void* emu) { return new Crypt32(emu); });
    reg("dnsapi", [](void* emu) { return new DnsApi(emu); });
    reg("gdi32", [](void* emu) { return new GDI32(emu); });
    reg("iphlpapi", [](void* emu) { return new Iphlpapi(emu); });
    reg("kernel32", [](void* emu) { return new Kernel32(emu); });
    reg("lz32", [](void* emu) { return new Lz32(emu); });
    reg("mpr", [](void* emu) { return new Mpr(emu); });
    reg("mscoree", [](void* emu) { return new Mscoree(emu); });
    reg("msi32", [](void* emu) { return new Msi32(emu); });
    reg("msimg32", [](void* emu) { return new Msimg32(emu); });
    reg("msvcrt", [](void* emu) { return new Msvcrt(emu); });
    reg("msvfw32", [](void* emu) { return new Msvfw32(emu); });
    reg("ncrypt", [](void* emu) { return new Ncrypt(emu); });
    reg("netapi32", [](void* emu) { return new NetApi32(emu); });
    reg("netutils", [](void* emu) { return new NetUtils(emu); });
    reg("ntdll", [](void* emu) { return new Ntdll(emu); });
    reg("ole32", [](void* emu) { return new Ole32(emu); });
    reg("oleaut32", [](void* emu) { return new Oleaut32(emu); });
    reg("psapi", [](void* emu) { return new Psapi(emu); });
    reg("rpcrt4", [](void* emu) { return new Rpcrt4(emu); });
    reg("secur32", [](void* emu) { return new Secur32(emu); });
    reg("sfc", [](void* emu) { return new Sfc(emu); });
    reg("sfc_os", [](void* emu) { return new Sfc_os(emu); });
    reg("shell32", [](void* emu) { return new Shell32(emu); });
    reg("shlwapi", [](void* emu) { return new Shlwapi(emu); });
    reg("urlmon", [](void* emu) { return new Urlmon(emu); });
    reg("user32", [](void* emu) { return new User32(emu); });
    reg("winhttp", [](void* emu) { return new WinHttp(emu); });
    reg("wininet", [](void* emu) { return new Wininet(emu); });
    reg("winmm", [](void* emu) { return new Winmm(emu); });
    reg("wkscli", [](void* emu) { return new Wkscli(emu); });
    reg("ws2_32", [](void* emu) { return new Ws2_32(emu); });
    reg("wtsapi32", [](void* emu) { return new Wtsapi32(emu); });

    //  Kernelmode Handlers 
    reg("fwpkclnt", [](void* emu) { return new Fwpkclnt(emu); });
    reg("hal", [](void* emu) { return new Hal(emu); });
    reg("ndis", [](void* emu) { return new Ndis(emu); });
    reg("netio", [](void* emu) { return new Netio(emu); });
    reg("ntoskrnl", [](void* emu) { return new Ntoskrnl(emu); });
    reg("usbd", [](void* emu) { return new Usbd(emu); });
    reg("wdfldr", [](void* emu) { return new Wdfldr(emu); });
    reg("wsk", [](void* emu) { return new Wsk(emu); });
}

} // namespace api
} // namespace speakeasy
