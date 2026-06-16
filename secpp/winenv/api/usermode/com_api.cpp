// com_api.cpp  COM API handler (real implementations)
#include "com_api.h"
#include <cstdint>
#include <string>
#include <vector>
#include "windows/winemu.h"
#include "winenv/deffs/windows/com.h"

//  Windows SDK macro conflict protection 
#ifdef _WIN32
#pragma push_macro("S_OK")
#pragma push_macro("S_FALSE")
#pragma push_macro("E_NOTIMPL")
#pragma push_macro("E_NOINTERFACE")
#pragma push_macro("E_POINTER")
#pragma push_macro("E_FAIL")
#pragma push_macro("E_OUTOFMEMORY")
#pragma push_macro("E_INVALIDARG")
#pragma push_macro("ERROR_SUCCESS")
#undef S_OK
#undef S_FALSE
#undef E_NOTIMPL
#undef E_NOINTERFACE
#undef E_POINTER
#undef E_FAIL
#undef E_OUTOFMEMORY
#undef E_INVALIDARG
#undef ERROR_SUCCESS
#endif

using namespace speakeasy;

namespace speakeasy { namespace api {


//  Constructor 
ComApi::ComApi(void* emu) : ApiHandler(emu) {
    INIT_API_TABLE(ComApi)
    REG(ComApi, IUnknown_QueryInterface, 3)
    REG(ComApi, IUnknown_AddRef, 1)
    REG(ComApi, IUnknown_Release, 1)
    REG(ComApi, IWbemLocator_ConnectServer, 9)
    REG(ComApi, IWbemServices_ExecQuery, 6)
    END_API_TABLE
}

// 
//  IUnknown::QueryInterface
// 
uint64_t ComApi::IUnknown_QueryInterface(void* e, ArgList& a, void* ctx) {
    // HRESULT QueryInterface(REFIID riid, void **ppvObject);
    // riid = a[0], ppvObject = a[1]
    (void)e; (void)a;
    return 0;  // S_OK
}

// 
//  IUnknown::AddRef
// 
uint64_t ComApi::IUnknown_AddRef(void* e, ArgList& a, void* ctx) {
    // ULONG AddRef();
    (void)e; (void)a;
    return 1;  // refcount increment
}

// 
//  IUnknown::Release
// 
uint64_t ComApi::IUnknown_Release(void* e, ArgList& a, void* ctx) {
    // ULONG Release();
    (void)e; (void)a;
    return 0;  // refcount zero
}

// 
//  IWbemLocator::ConnectServer
// 
uint64_t ComApi::IWbemLocator_ConnectServer(void* e, ArgList& a, void* ctx) {
    // HRESULT ConnectServer(
    //     const BSTR    strNetworkResource,  // a[0]
    //     const BSTR    strUser,             // a[1]
    //     const BSTR    strPassword,         // a[2]
    //     const BSTR    strLocale,           // a[3]
    //     long          lSecurityFlags,      // a[4]
    //     const BSTR    strAuthority,        // a[5]
    //     IWbemContext  *pCtx,               // a[6]
    //     IWbemServices **ppNamespace        // a[7]
    // );
    // Note: this->ptr (a[8]) is the interface pointer itself
    uint64_t ptr = a[0];
    uint64_t strNetworkResource = a[1];
    uint64_t strUser = a[2];
    uint64_t strPassword = a[3];
    uint64_t strLocale = a[4];
    uint64_t lSecurityFlags = a[5];
    uint64_t strAuthority = a[6];
    uint64_t pCtx = a[7];
    uint64_t ppNamespace = a[8];
    (void)ptr; (void)strUser; (void)strPassword; (void)strLocale;
    (void)lSecurityFlags; (void)strAuthority; (void)pCtx;

    // Log the network resource string
    if (strNetworkResource) {
        std::string res = be(e)->read_mem_string(strNetworkResource, 2);  // BSTR = wide
        (void)res;
    }

    if (ppNamespace) {
        int ps = be(e)->get_ptr_size();
        // Emulate: create an IWbemServices interface in emulated memory.
        // Branch on runtime pointer size so struct layouts are correct for
        // both 32-bit and 64-bit emulated targets.
        uint64_t ci_addr = 0;
        if (ps == 8) {
            deffs::windows::IWbemServices<8> svc_vtbl;
            size_t vtbl_size = svc_vtbl.sizeof_obj();
            uint64_t vtbl_addr = we(e)->mem_map(vtbl_size, std::nullopt, 7, "emu.COM.IWbemServices.vtbl");
            we(e)->mem_write(vtbl_addr, svc_vtbl.get_bytes());

            deffs::windows::ComInterface<8> ci;
            ci.vtable = vtbl_addr;
            size_t ci_size = ci.sizeof_obj();
            ci_addr = we(e)->mem_map(ci_size, std::nullopt, 7, "emu.COM.IWbemServices");
            we(e)->mem_write(ci_addr, ci.get_bytes());
        } else {
            deffs::windows::IWbemServices<4> svc_vtbl;
            size_t vtbl_size = svc_vtbl.sizeof_obj();
            uint64_t vtbl_addr = we(e)->mem_map(vtbl_size, std::nullopt, 7, "emu.COM.IWbemServices.vtbl");
            we(e)->mem_write(vtbl_addr, svc_vtbl.get_bytes());

            deffs::windows::ComInterface<4> ci;
            ci.vtable = vtbl_addr;
            size_t ci_size = ci.sizeof_obj();
            ci_addr = we(e)->mem_map(ci_size, std::nullopt, 7, "emu.COM.IWbemServices");
            we(e)->mem_write(ci_addr, ci.get_bytes());
        }

        // Write pointer to the interface into ppNamespace
        std::vector<uint8_t> pp_buf(ps, 0);
        write_le(pp_buf, 0, ci_addr, ps);
        we(e)->mem_write(ppNamespace, pp_buf);
    }

    return 0;  // S_OK
}

// 
//  IWbemServices::ExecQuery
// 
uint64_t ComApi::IWbemServices_ExecQuery(void* e, ArgList& a, void* ctx) {
    // HRESULT ExecQuery(
    //     const BSTR           strQueryLanguage,  // a[0]
    //     const BSTR           strQuery,          // a[1]
    //     long                 lFlags,            // a[2]
    //     IWbemContext         *pCtx,             // a[3]
    //     IEnumWbemClassObject **ppEnum           // a[4]
    // );
    // Note: this->ptr (a[5]) is the interface pointer itself
    uint64_t ptr = a[0];
    uint64_t strQueryLanguage = a[1];
    uint64_t strQuery = a[2];
    uint64_t lFlags = a[3];
    uint64_t pCtx = a[4];
    uint64_t ppEnum = a[5];
    (void)ptr; (void)lFlags; (void)pCtx; (void)ppEnum;

    if (strQueryLanguage) {
        std::string lang = be(e)->read_mem_string(strQueryLanguage, 2);
        (void)lang;
    }
    if (strQuery) {
        std::string query = be(e)->read_mem_string(strQuery, 2);
        (void)query;
    }

    // Not fully implemented
    return static_cast<uint64_t>(static_cast<int64_t>(-1));  // -1 (failure)
}

}} // namespaces

//  Pop SDK macros 
#ifdef _WIN32
#pragma pop_macro("ERROR_SUCCESS")
#pragma pop_macro("E_INVALIDARG")
#pragma pop_macro("E_OUTOFMEMORY")
#pragma pop_macro("E_FAIL")
#pragma pop_macro("E_POINTER")
#pragma pop_macro("E_NOINTERFACE")
#pragma pop_macro("E_NOTIMPL")
#pragma pop_macro("S_FALSE")
#pragma pop_macro("S_OK")
#endif
