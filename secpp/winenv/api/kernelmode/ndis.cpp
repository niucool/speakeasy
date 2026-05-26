// ndis.cpp  Network Driver Interface Specification handler (implemented)
#include "ndis.h"

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

Ndis::Ndis(void* emu) : ApiHandler(emu) {
    INIT_API_TABLE(Ndis)
    REG(Ndis, NdisGetVersion, 0)
    REG(Ndis, NdisGetRoutineAddress, 1)
    REG(Ndis, NdisMRegisterMiniportDriver, 5)
    REG(Ndis, NdisInitializeWrapper, 4)
    REG(Ndis, NdisTerminateWrapper, 2)
    REG(Ndis, NdisInitializeReadWriteLock, 1)
    REG(Ndis, NdisMRegisterUnloadHandler, 2)
    REG(Ndis, NdisRegisterProtocol, 4)
    REG(Ndis, NdisIMRegisterLayeredMiniport, 4)
    REG(Ndis, NdisIMAssociateMiniport, 2)
    REG(Ndis, NdisAllocateGenericObject, 3)
    REG(Ndis, NdisAllocateMemoryWithTag, 3)
    REG(Ndis, NdisAllocateNetBufferListPool, 2)
    REG(Ndis, NdisFreeNetBufferListPool, 1)
    REG(Ndis, NdisFreeMemory, 3)
    REG(Ndis, NdisFreeGenericObject, 1)
    END_API_TABLE
}

//  Internal helpers 
static uint32_t ndis_next_handle = 4;
static inline uint32_t ndis_new_id() {
    uint32_t h = ndis_next_handle;
    ndis_next_handle += 4;
    return h;
}

static inline std::string ndis_tag_to_str(uint32_t tag) {
    if (!tag) return "0x00";
    char buf[5] = {0};
    buf[0] = static_cast<char>(tag & 0xFF);
    buf[1] = static_cast<char>((tag >> 8) & 0xFF);
    buf[2] = static_cast<char>((tag >> 16) & 0xFF);
    buf[3] = static_cast<char>((tag >> 24) & 0xFF);
    for (int i = 0; i < 4; i++) if (buf[i] < 0x20 || buf[i] > 0x7e) buf[i] = '.';
    return std::string(buf);
}

//  Implementations 

uint64_t Ndis::NdisGetVersion(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    // UINT NdisGetVersion();
    (void)a;
    int arch = be(e)->get_arch();
    (void)arch;
    // Return NDIS 6.x version
    return (6 << 16) | 0x51; // NDIS 6.51 for Win10+
}

uint64_t Ndis::NdisGetRoutineAddress(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    // PVOID NdisGetRoutineAddress(PNDIS_STRING NdisRoutineName);
    // Read the unicode string and look up the function
    uint64_t routine_name = a[0];
    if (!routine_name) return 0;
    
    // Try to read as UNICODE_STRING (pointer, length, maxlen)
    auto raw = mm(e)->mem_read(routine_name, ptr_sz(e) + 4);
    uint64_t buf_ptr = 0;
    if (ptr_sz(e) == 8) {
        buf_ptr = static_cast<uint64_t>(read_le(raw, 0, 8));
    } else {
        buf_ptr = static_cast<uint64_t>(read_le(raw, 0, 4));
    }
    
    if (!buf_ptr) return 0;
    
    // Try to resolve the function name
    return reinterpret_cast<uint64_t>(we(e)->get_proc("ndis", ""));
}

uint64_t Ndis::NdisMRegisterMiniportDriver(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    // NDIS_STATUS NdisMRegisterMiniportDriver(...)
    uint64_t phnd = a[4];
    if (phnd) {
        uint32_t h = ndis_new_id();
        auto data = std::vector<uint8_t>(4);
        write_le(data, 0, static_cast<uint64_t>(h), 4);
        mm(e)->mem_write(phnd, data);
    }
    return 0; // NDIS_STATUS_SUCCESS
}

uint64_t Ndis::NdisInitializeWrapper(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    // VOID NdisInitializeWrapper(...)
    uint64_t p_handle = a[0];
    if (p_handle) {
        uint32_t h = ndis_new_id();
        auto data = std::vector<uint8_t>(static_cast<size_t>(ptr_sz(e)));
        write_le(data, 0, static_cast<uint64_t>(h), ptr_sz(e));
        mm(e)->mem_write(p_handle, data);
    }
    return 0;
}

uint64_t Ndis::NdisTerminateWrapper(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    (void)e; (void)a;
    return 0;
}

uint64_t Ndis::NdisInitializeReadWriteLock(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    (void)e; (void)a;
    return 0;
}

uint64_t Ndis::NdisMRegisterUnloadHandler(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    (void)e; (void)a;
    return 0;
}

uint64_t Ndis::NdisRegisterProtocol(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    // NDIS_STATUS NdisRegisterProtocol(...)
    uint64_t p_status = a[0];
    uint64_t p_proto = a[1];
    uint64_t p_chars = a[2];
    uint64_t clen = a[3];
    
    if (p_status) {
        auto data = std::vector<uint8_t>(4, 0);
        mm(e)->mem_write(p_status, data); // STATUS_SUCCESS
    }
    if (p_proto) {
        uint32_t h = ndis_new_id();
        auto data = std::vector<uint8_t>(4);
        write_le(data, 0, static_cast<uint64_t>(h), 4);
        mm(e)->mem_write(p_proto, data);
    }
    (void)p_chars; (void)clen;
    return 0;
}

uint64_t Ndis::NdisIMRegisterLayeredMiniport(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    // NDIS_STATUS NdisIMRegisterLayeredMiniport(...)
    uint64_t drv_hnd = a[3];
    if (drv_hnd) {
        uint32_t h = ndis_new_id();
        auto data = std::vector<uint8_t>(4);
        write_le(data, 0, static_cast<uint64_t>(h), 4);
        mm(e)->mem_write(drv_hnd, data);
    }
    return 0; // NDIS_STATUS_SUCCESS
}

uint64_t Ndis::NdisIMAssociateMiniport(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    (void)e; (void)a;
    return 0;
}

uint64_t Ndis::NdisAllocateGenericObject(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    // PNDIS_GENERIC_OBJECT NdisAllocateGenericObject(DRIVER_OBJECT, Tag, Size)
    uint64_t drv = a[0];
    uint32_t tag = static_cast<uint32_t>(a[1]);
    uint16_t size = static_cast<uint16_t>(a[2]);
    (void)drv;
    
    // NDIS_GENERIC_OBJECT has 2 pointers (16/8 bytes) + size bytes of data
    size_t hdr_sz = static_cast<size_t>(ptr_sz(e)) * 2; // DriverObject + Reserved
    size_t total = hdr_sz + static_cast<size_t>(size);
    
    std::string tag_str = ndis_tag_to_str(tag);
    uint64_t ptr = mm(e)->mem_map(total, 0, common::PERM_MEM_RWX,
                                  "api.struct.NDIS_GENERIC_OBJECT." + tag_str);
    
    // Write DriverObject pointer at offset 0
    auto data = std::vector<uint8_t>(static_cast<size_t>(ptr_sz(e)));
    write_le(data, 0, drv, ptr_sz(e));
    mm(e)->mem_write(ptr, data);
    
    return ptr;
}

uint64_t Ndis::NdisAllocateMemoryWithTag(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    // NDIS_STATUS NdisAllocateMemoryWithTag(PVOID *VirtualAddress, UINT Length, ULONG Tag)
    uint64_t pva = a[0];
    uint64_t length = a[1];
    uint32_t tag = static_cast<uint32_t>(a[2]);
    
    std::string tag_str = ndis_tag_to_str(tag);
    uint64_t ptr = mm(e)->mem_map(length, 0, common::PERM_MEM_RWX,
                                  "api.ndis_pool." + tag_str);
    
    // Write the pointer
    auto data = std::vector<uint8_t>(static_cast<size_t>(ptr_sz(e)));
    write_le(data, 0, ptr, ptr_sz(e));
    mm(e)->mem_write(pva, data);
    
    return 0; // STATUS_SUCCESS
}

uint64_t Ndis::NdisAllocateNetBufferListPool(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    // NDIS_HANDLE NdisAllocateNetBufferListPool(...)
    // Allocate a NET_BUFFER_LIST structure
    size_t nbl_size = static_cast<size_t>(ptr_sz(e)) * 8; // rough estimate
    uint64_t ptr = mm(e)->mem_map(nbl_size, 0, common::PERM_MEM_RWX,
                                  "api.struct.NET_BUFFER_LIST");
    return ptr;
}

uint64_t Ndis::NdisFreeNetBufferListPool(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    // VOID NdisFreeNetBufferListPool(NDIS_HANDLE PoolHandle)
    uint64_t handle = a[0];
    mm(e)->mem_free(handle);
    return 0;
}

uint64_t Ndis::NdisFreeMemory(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    // VOID NdisFreeMemory(PVOID VirtualAddress, UINT Length, ULONG Tag)
    uint64_t addr = a[0];
    mm(e)->mem_free(addr);
    return 0;
}

uint64_t Ndis::NdisFreeGenericObject(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    // VOID NdisFreeGenericObject(PNDIS_GENERIC_OBJECT GenericObject)
    uint64_t obj = a[0];
    mm(e)->mem_free(obj);
    return 0;
}

}}} // namespaces
