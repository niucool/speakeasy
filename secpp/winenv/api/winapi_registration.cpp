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
            if (handler) {
                handler->set_emu(emu);
            }
            return handler;
        });
    };

    // ── Usermode Handlers ────────────────────────────────────
    reg("advapi32", [](void*) { return new Advapi32(); });
    reg("advpack", [](void*) { return new Advpack(); });
    reg("bcrypt", [](void*) { return new Bcrypt(); });
    reg("bcryptprimitives", [](void*) { return new Bcryptprimitives(); });
    reg("com_api", [](void*) { return new ComApi(); });
    reg("comctl32", [](void*) { return new Comctl32(); });
    reg("crypt32", [](void*) { return new Crypt32(); });
    reg("dnsapi", [](void*) { return new DnsApi(); });
    reg("gdi32", [](void*) { return new GDI32(); });
    reg("iphlpapi", [](void*) { return new Iphlpapi(); });
    reg("kernel32", [](void*) { return new Kernel32(); });
    reg("lz32", [](void*) { return new Lz32(); });
    reg("mpr", [](void*) { return new Mpr(); });
    reg("mscoree", [](void*) { return new Mscoree(); });
    reg("msi32", [](void*) { return new Msi32(); });
    reg("msimg32", [](void*) { return new Msimg32(); });
    reg("msvcrt", [](void*) { return new Msvcrt(); });
    reg("msvfw32", [](void*) { return new Msvfw32(); });
    reg("ncrypt", [](void*) { return new Ncrypt(); });
    reg("netapi32", [](void*) { return new NetApi32(); });
    reg("netutils", [](void*) { return new NetUtils(); });
    reg("ntdll", [](void*) { return new Ntdll(); });
    reg("ole32", [](void*) { return new Ole32(); });
    reg("oleaut32", [](void*) { return new Oleaut32(); });
    reg("psapi", [](void*) { return new Psapi(); });
    reg("rpcrt4", [](void*) { return new Rpcrt4(); });
    reg("secur32", [](void*) { return new Secur32(); });
    reg("sfc", [](void*) { return new Sfc(); });
    reg("sfc_os", [](void*) { return new Sfc_os(); });
    reg("shell32", [](void*) { return new Shell32(); });
    reg("shlwapi", [](void*) { return new Shlwapi(); });
    reg("urlmon", [](void*) { return new Urlmon(); });
    reg("user32", [](void*) { return new User32(); });
    reg("winhttp", [](void*) { return new WinHttp(); });
    reg("wininet", [](void*) { return new Wininet(); });
    reg("winmm", [](void*) { return new Winmm(); });
    reg("wkscli", [](void*) { return new Wkscli(); });
    reg("ws2_32", [](void*) { return new Ws2_32(); });
    reg("wtsapi32", [](void*) { return new Wtsapi32(); });

    // ── Kernelmode Handlers ──────────────────────────────────
    reg("fwpkclnt", [](void*) { return new Fwpkclnt(); });
    reg("hal", [](void*) { return new Hal(); });
    reg("ndis", [](void*) { return new Ndis(); });
    reg("netio", [](void*) { return new Netio(); });
    reg("ntoskrnl", [](void*) { return new Ntoskrnl(); });
    reg("usbd", [](void*) { return new Usbd(); });
    reg("wdfldr", [](void*) { return new Wdfldr(); });
    reg("wsk", [](void*) { return new Wsk(); });
}

} // namespace api
} // namespace speakeasy
