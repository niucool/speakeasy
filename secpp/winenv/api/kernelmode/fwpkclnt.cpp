// fwpkclnt.cpp  Windows Filtering Platform handler (implemented)
#include "fwpkclnt.h"

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

// FWP error constants (KERN_ prefix to avoid Windows SDK macro conflicts)
static constexpr uint32_t KERN_FWP_CALLOUT_NOT_FOUND    = 0x80320001;
static constexpr uint32_t KERN_FWP_FILTER_NOT_FOUND     = 0x80320003;
static constexpr uint32_t KERN_FWP_LAYER_NOT_FOUND      = 0x80320004;
static constexpr uint32_t KERN_FWP_SUBLAYER_NOT_FOUND   = 0x80320007;
static constexpr uint32_t KERN_FWP_NOT_FOUND             = 0x80320008;

Fwpkclnt::Fwpkclnt(void* emu) : ApiHandler(emu) {
    INIT_API_TABLE(Fwpkclnt)
    REG(Fwpkclnt, FwpmEngineOpen0, 5)
    REG(Fwpkclnt, FwpmEngineClose0, 1)
    REG(Fwpkclnt, FwpmSubLayerAdd0, 3)
    REG(Fwpkclnt, FwpmSubLayerDeleteByKey0, 2)
    REG(Fwpkclnt, FwpmCalloutAdd0, 4)
    REG(Fwpkclnt, FwpmCalloutDeleteById0, 2)
    REG(Fwpkclnt, FwpmFilterAdd0, 4)
    REG(Fwpkclnt, FwpmFilterDeleteById0, 2)
    REG(Fwpkclnt, FwpsCalloutRegister1, 3)
    REG(Fwpkclnt, FwpsCalloutUnregisterById0, 1)
    REG(Fwpkclnt, FwpsInjectionHandleCreate0, 3)
    REG(Fwpkclnt, FwpsInjectionHandleDestroy0, 1)
    END_API_TABLE
}

//  Internal helpers 
static uint32_t fwp_next_handle = 4;
static inline uint32_t fwp_new_id() {
    uint32_t h = fwp_next_handle;
    fwp_next_handle += 4;
    return h;
}

//  Implementations 

uint64_t Fwpkclnt::FwpmEngineOpen0(void* e, ArgList& a, void* ctx) {
    // DWORD FwpmEngineOpen0(serverName, authnService, authIdentity, session, engineHandle)
    uint64_t eng = a[4];
    if (eng) {
        uint32_t h = fwp_new_id();
        auto data = std::vector<uint8_t>(static_cast<size_t>(ptr_sz(e)));
        write_le(data, 0, static_cast<uint64_t>(h), ptr_sz(e));
        mm(e)->mem_write(eng, data);
    }
    return 0; // STATUS_SUCCESS
}

uint64_t Fwpkclnt::FwpmEngineClose0(void* e, ArgList& a, void* ctx) {
    // DWORD FwpmEngineClose0(HANDLE engineHandle)
    (void)e; (void)a;
    return 0;
}

uint64_t Fwpkclnt::FwpmSubLayerAdd0(void* e, ArgList& a, void* ctx) {
    // DWORD FwpmSubLayerAdd0(engineHandle, subLayer, sd)
    uint64_t sl = a[1];
    if (sl) {
        // Read display data name/description from sublayer struct
        // FWPM_SUBLAYER0 layout (x64):
        //   +0x000 subLayerKey    : Guid (16 bytes)
        //   +0x010 displayData    : FWPM_DISPLAY_DATA0 (name_ptr + desc_ptr + name_len + desc_len) = 2*ptr + 2*u16
        size_t off = 16; // offset of displayData
        (void)off;
        // Currently just acknowledge the sublayer
    }
    return 0; // STATUS_SUCCESS
}

uint64_t Fwpkclnt::FwpmSubLayerDeleteByKey0(void* e, ArgList& a, void* ctx) {
    // DWORD FwpmSubLayerDeleteByKey0(HANDLE engineHandle, const GUID* key)
    (void)e; (void)a;
    return 0;
}

uint64_t Fwpkclnt::FwpmCalloutAdd0(void* e, ArgList& a, void* ctx) {
    // DWORD FwpmCalloutAdd0(engineHandle, callout, sd, flags)
    (void)e; (void)a;
    return 0; // STATUS_SUCCESS
}

uint64_t Fwpkclnt::FwpmCalloutDeleteById0(void* e, ArgList& a, void* ctx) {
    // DWORD FwpmCalloutDeleteById0(engineHandle, UINT32 id)
    (void)e; (void)a;
    return 0;
}

uint64_t Fwpkclnt::FwpmFilterAdd0(void* e, ArgList& a, void* ctx) {
    // DWORD FwpmFilterAdd0(engineHandle, filter, sd, id)
    uint64_t p_id = a[3];
    if (p_id) {
        uint32_t h = fwp_new_id();
        auto data = std::vector<uint8_t>(4);
        write_le(data, 0, static_cast<uint64_t>(h), 4);
        mm(e)->mem_write(p_id, data);
    }
    return 0; // STATUS_SUCCESS
}

uint64_t Fwpkclnt::FwpmFilterDeleteById0(void* e, ArgList& a, void* ctx) {
    // DWORD FwpmFilterDeleteById0(engineHandle, UINT32 id)
    (void)e; (void)a;
    return 0;
}

uint64_t Fwpkclnt::FwpsCalloutRegister1(void* e, ArgList& a, void* ctx) {
    // NTSTATUS FwpsCalloutRegister1(deviceObject, callout, calloutId)
    uint64_t callout_id_ptr = a[2];
    if (callout_id_ptr) {
        uint32_t cid = fwp_new_id();
        auto data = std::vector<uint8_t>(4);
        write_le(data, 0, static_cast<uint64_t>(cid), 4);
        mm(e)->mem_write(callout_id_ptr, data);
    }
    return 0; // STATUS_SUCCESS
}

uint64_t Fwpkclnt::FwpsCalloutUnregisterById0(void* e, ArgList& a, void* ctx) {
    // NTSTATUS FwpsCalloutUnregisterById0(UINT32 calloutId)
    (void)e; (void)a;
    return 0;
}

uint64_t Fwpkclnt::FwpsInjectionHandleCreate0(void* e, ArgList& a, void* ctx) {
    // NTSTATUS FwpsInjectionHandleCreate0(addressFamily, flags, injectionHandle)
    uint64_t inj_handle = a[2];
    if (inj_handle) {
        uint32_t h = fwp_new_id();
        auto data = std::vector<uint8_t>(static_cast<size_t>(ptr_sz(e)));
        write_le(data, 0, static_cast<uint64_t>(h), ptr_sz(e));
        mm(e)->mem_write(inj_handle, data);
    }
    return 0; // STATUS_SUCCESS
}

uint64_t Fwpkclnt::FwpsInjectionHandleDestroy0(void* e, ArgList& a, void* ctx) {
    // NTSTATUS FwpsInjectionHandleDestroy0(HANDLE injectionHandle)
    (void)e; (void)a;
    return 0;
}

}}} // namespaces
