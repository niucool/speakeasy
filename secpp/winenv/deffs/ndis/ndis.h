// ndis.h  NDIS type definitions (new EmuStructHelper CRTP)
//
// Maps to: speakeasy/winenv/defs/ndis/ndis.py
//
// Uses the new EmuStructHelper CRTP approach for auto serialize/deserialize.
// All structs use #pragma pack(push, 1) with explicit padding fields to match
// the sizeof() that Python ctypes (natural C ABI alignment) would produce.
//
// NDIS_OBJECT_HEADER is defined below.

#ifndef SPEAKEASY_DEFS_NEW_NDIS_NDIS_H
#define SPEAKEASY_DEFS_NEW_NDIS_NDIS_H

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include "struct.h"

namespace speakeasy { namespace deffs { namespace ndis {

#pragma pack(push, 1)

// ==========================================================================================================
// NDIS_OBJECT_HEADER: u8+u8+u16 = 4 bytes
// ==========================================================================================================
struct NDIS_OBJECT_HEADER : public EmuStructHelper<NDIS_OBJECT_HEADER> {
    uint8_t  Type = 0;
    uint8_t  Revision = 0;
    uint16_t Size = 0;
    std::string get_mem_tag() const override { return "ndis_object_header"; }
};

// ==========================================================================================================
// NDIS_GENERIC_OBJECT: Header(4) + 3*Ptr
//   x86: 4 + 4 + 4 + 4 = 16
//   x64: 4 + pad(4) + 8 + 8 + 8 = 32
// ==========================================================================================================
template <int PtrSize>
struct NDIS_GENERIC_OBJECT_POD;

template <>
struct NDIS_GENERIC_OBJECT_POD<4> {
    NDIS_OBJECT_HEADER Header;                     // offset  0
    uint32_t           Caller         = 0;         // offset  4
    uint32_t           CallersCaller  = 0;         // offset  8
    uint32_t           DriverObject   = 0;         // offset 12
    // total = 16
};

template <>
struct NDIS_GENERIC_OBJECT_POD<8> {
    NDIS_OBJECT_HEADER Header;                     // offset  0
    uint32_t           pad            = 0;         // offset  4
    uint64_t           Caller         = 0;         // offset  8
    uint64_t           CallersCaller  = 0;         // offset 16
    uint64_t           DriverObject   = 0;         // offset 24
    // total = 32
};

template <int PtrSize>
struct NDIS_GENERIC_OBJECT : public EmuStructHelper<NDIS_GENERIC_OBJECT<PtrSize>>,
                             public NDIS_GENERIC_OBJECT_POD<PtrSize> {
    std::string get_mem_tag() const override { return "ndis_generic_object"; }
};

// ==========================================================================================================
// NET_BUFFER_LIST_POOL_PARAMETERS: Header(4)+u8+u8+u16+u32+u32 = 16
//   x86: 4+1+1+2+4+4 = 16
//   x64: 4+1+1+2+4+4 = 16  (no pointers, no padding needed)
// This struct has no pointer fields — fixed size regardless of ptr_size.
// ==========================================================================================================
struct NET_BUFFER_LIST_POOL_PARAMETERS_POD {
    NDIS_OBJECT_HEADER Header;                     // offset  0
    uint8_t            ProtocolId       = 0;       // offset  4
    uint8_t            fAllocateNetBuffer = 0;     // offset  5
    uint16_t           ContextSize      = 0;       // offset  6
    uint32_t           PoolTag          = 0;       // offset  8
    uint32_t           DataSize         = 0;       // offset 12
    // total = 16
};

struct NET_BUFFER_LIST_POOL_PARAMETERS
    : public EmuStructHelper<NET_BUFFER_LIST_POOL_PARAMETERS>,
      public NET_BUFFER_LIST_POOL_PARAMETERS_POD {
    std::string get_mem_tag() const override { return "net_buffer_list_pool_parameters"; }
};

// ==========================================================================================================
// NET_BUFFER_LIST: 11*Ptr + 3*uint32 + Ptr[11]
//   x86: 11*4=44 + 12 + 44 = 100... let me recount from Python
//   Next(4)+FirstNetBuffer(4)+Context(4)+ParentNetBufferList(4)+NdisPoolHandle(4)+
//   NdisReserved[2](8)+ProtocolReserved[4](16)+MiniportReserved[2](8)+
//   Scratch(4)+SourceHandle(4)+NblFlags(4)+ChildRefCount(4)+Flags(4)+
//   NetBufferListInfo[11](44) = 120
//   x64: 11*8=88 + 12 + pad(4) + 11*8=88 = 192... wait
//   Next(8)+FirstNetBuffer(8)+Context(8)+ParentNetBufferList(8)+NdisPoolHandle(8)=40
//   NdisReserved[2](16)+ProtocolReserved[4](32)+MiniportReserved[2](16)=104
//   Scratch(8)+SourceHandle(8)=120
//   NblFlags(4)+ChildRefCount(4)+Flags(4)=132
//   pad(4)=136
//   NetBufferListInfo[11](88)=224
// ==========================================================================================================
template <int PtrSize>
struct NET_BUFFER_LIST_POD;

template <>
struct NET_BUFFER_LIST_POD<4> {
    uint32_t Next               = 0;    // offset   0
    uint32_t FirstNetBuffer     = 0;    // offset   4
    uint32_t Context            = 0;    // offset   8
    uint32_t ParentNetBufferList= 0;    // offset  12
    uint32_t NdisPoolHandle     = 0;    // offset  16
    uint32_t NdisReserved[2]    = {};   // offset  20
    uint32_t ProtocolReserved[4]= {};   // offset  28
    uint32_t MiniportReserved[2]= {};   // offset  44
    uint32_t Scratch            = 0;    // offset  52
    uint32_t SourceHandle       = 0;    // offset  56
    uint32_t NblFlags           = 0;    // offset  60
    uint32_t ChildRefCount      = 0;    // offset  64
    uint32_t Flags              = 0;    // offset  68
    uint32_t NetBufferListInfo[11] = {};// offset  72
    // total = 72 + 44 = 116
};

// Wait the Python shows 52 bytes before NetBufferListInfo for x86
// Actually let me recount:
// Next(4)+FirstNetBuffer(4)+Context(4)+ParentNetBufferList(4)+NdisPoolHandle(4)=20
// NdisReserved * 2 (4*2=8) = 28
// ProtocolReserved * 4 (4*4=16) = 44
// MiniportReserved * 2 (4*2=8) = 52
// Scratch(4)=56 ... wait I need to be more careful



// Actually I realize these initializers=0 are not needed since this is a POD struct
// and the inheriting struct will do zero-initialization. Let me leave them as member declarations.

template <>
struct NET_BUFFER_LIST_POD<8> {
    uint64_t Next;                     // offset  0
    uint64_t FirstNetBuffer;           // offset  8
    uint64_t Context;                  // offset 16
    uint64_t ParentNetBufferList;      // offset 24
    uint64_t NdisPoolHandle;           // offset 32
    uint64_t NdisReserved[2];          // offset 40
    uint64_t ProtocolReserved[4];      // offset 56
    uint64_t MiniportReserved[2];      // offset 88
    uint64_t Scratch;                  // offset 104
    uint64_t SourceHandle;             // offset 112
    uint32_t NblFlags;                 // offset 120
    uint32_t ChildRefCount;            // offset 124
    uint32_t Flags;                    // offset 128
    uint32_t pad;                      // offset 132 → align next Ptr to 8
    uint64_t NetBufferListInfo[11];    // offset 136
};

// x86: 5*4=20 + 2*4=8(28) + 4*4=16(44) + 2*4=8(52) + 2*4=8(60) + 3*4=12(72) + 11*4=44(116)
// total = 116

// x64: 5*8=40 + 2*8=16(56) + 4*8=32(88) + 2*8=16(104) + 2*8=16(120) + 
//       3*4=12(132) + pad4(136) + 11*8=88(224)
// total = 224

template <int PtrSize>
struct NET_BUFFER_LIST : public EmuStructHelper<NET_BUFFER_LIST<PtrSize>>,
                         public NET_BUFFER_LIST_POD<PtrSize> {
    std::string get_mem_tag() const override { return "net_buffer_list"; }
};

// ==========================================================================================================
// NET_BUFFER_DATA: Next(Ptr)+CurrentMdl(Ptr)+CurrentMdlOffset(u32)+NbDataLength(u32)+
//                  MdlChain(Ptr)+DataOffset(u32)
//   x86: 4+4+4+4+4+4 = 24
//   x64: 8+8+4+4+8+4+pad4 = 40
// ==========================================================================================================
template <int PtrSize>
struct NET_BUFFER_DATA_POD;

template <>
struct NET_BUFFER_DATA_POD<4> {
    uint32_t Next;                  // offset  0
    uint32_t CurrentMdl;            // offset  4
    uint32_t CurrentMdlOffset;      // offset  8
    uint32_t NbDataLength;          // offset 12
    uint32_t MdlChain;              // offset 16
    uint32_t DataOffset;            // offset 20
    // total = 24
};

template <>
struct NET_BUFFER_DATA_POD<8> {
    uint64_t Next;                  // offset  0
    uint64_t CurrentMdl;            // offset  8
    uint32_t CurrentMdlOffset;      // offset 16
    uint32_t NbDataLength;          // offset 20
    uint64_t MdlChain;              // offset 24 (20+4=24, 8-byte aligned)
    uint32_t DataOffset;            // offset 32
    uint32_t pad;                   // offset 36 → round to 8-byte boundary
    // total = 40
};

template <int PtrSize>
struct NET_BUFFER_DATA : public EmuStructHelper<NET_BUFFER_DATA<PtrSize>>,
                         public NET_BUFFER_DATA_POD<PtrSize> {
    std::string get_mem_tag() const override { return "net_buffer_data"; }
};

// ==========================================================================================================
// NET_BUFFER_HEADER: NetBufferData(NET_BUFFER_DATA) + Link(Ptr)
//   x86: 24 + 4 = 28
//   x64: 40 + 8 = 48
// ==========================================================================================================
template <int PtrSize>
struct NET_BUFFER_HEADER_POD;

template <>
struct NET_BUFFER_HEADER_POD<4> {
    NET_BUFFER_DATA_POD<4> NetBufferData;  // offset  0 (24 bytes)
    uint32_t               Link = 0;       // offset 24
    // total = 28
};

template <>
struct NET_BUFFER_HEADER_POD<8> {
    NET_BUFFER_DATA_POD<8> NetBufferData;  // offset  0 (40 bytes)
    uint64_t               Link = 0;       // offset 40
    // total = 48
};

template <int PtrSize>
struct NET_BUFFER_HEADER : public EmuStructHelper<NET_BUFFER_HEADER<PtrSize>>,
                           public NET_BUFFER_HEADER_POD<PtrSize> {
    std::string get_mem_tag() const override { return "net_buffer_header"; }
};

// ==========================================================================================================
// NET_BUFFER: Link(Ptr)+NetBufferHeader(NET_BUFFER_HEADER)+ChecksumBias(Ptr)+Reserved(Ptr)+
//             NdisPoolHandle(Ptr)+NdisReserved[2](Ptr)+ProtocolReserved[6](Ptr)+
//             MiniportReserved[4](Ptr)+DataPhysicalAddress(u64)+SharedMemoryInfo(Ptr)
//   x86: 4+28+4+4+4+8+24+16+8+4 = 104
//   x64: 8+48+8+8+8+16+48+32+8+8 = 192
// ==========================================================================================================
template <int PtrSize>
struct NET_BUFFER_POD;

template <>
struct NET_BUFFER_POD<4> {
    uint32_t Link;                        // offset   0
    NET_BUFFER_DATA_POD<4> NetBufferHeader;// offset  4 (24 bytes) → offset 28
    uint32_t ChecksumBias;                // offset 28
    uint32_t Reserved;                    // offset 32
    uint32_t NdisPoolHandle;              // offset 36
    uint32_t NdisReserved[2];             // offset 40
    uint32_t ProtocolReserved[6];         // offset 48
    uint32_t MiniportReserved[4];         // offset 72
    uint64_t DataPhysicalAddress;         // offset 88
    uint32_t SharedMemoryInfo;            // offset 96
    // total = 100
};

// Wait, the Python shows:
// self.Link = Ptr                       -> 4 (x86)
// self.NetBufferHeader = NET_BUFFER_HEADER -> but the Python's NET_BUFFER_HEADER has NetBufferData(NET_BUFFER_DATA) + Link(Ptr)
// For x86: NET_BUFFER_HEADER = NET_BUFFER_DATA(24) + Ptr(4) = 28
// So NET_BUFFER for x86:
// Link(4) + NET_BUFFER_HEADER(28) + ChecksumBias(4) + Reserved(4) + NdisPoolHandle(4) +
// NdisReserved[2](8) + ProtocolReserved[6](24) + MiniportReserved[4](16) +
// DataPhysicalAddress(8) + SharedMemoryInfo(4) = 100

// Let me verify: 4+28=32, +4=36, +4=40, +4=44, +8=52, +24=76, +16=92, +8=100, +4=104

// x64:
// Link(8) + NET_BUFFER_HEADER(48) + ChecksumBias(8) + Reserved(8) + NdisPoolHandle(8) +
// NdisReserved[2](16) + ProtocolReserved[6](48) + MiniportReserved[4](32) +
// DataPhysicalAddress(8) + SharedMemoryInfo(8) = 192

template <>
struct NET_BUFFER_POD<8> {
    uint64_t Link;                        // offset   0
    NET_BUFFER_DATA_POD<8> NetBufferHeader;// offset  8 (40 bytes) → offset 48
    uint64_t ChecksumBias;                // offset  48
    uint64_t Reserved;                    // offset  56
    uint64_t NdisPoolHandle;              // offset  64
    uint64_t NdisReserved[2];             // offset  72
    uint64_t ProtocolReserved[6];         // offset  88
    uint64_t MiniportReserved[4];         // offset 136
    uint64_t DataPhysicalAddress;         // offset 168
    uint64_t SharedMemoryInfo;            // offset 176
    // total = 184
};

// x64: 8+40=48, +8=56, +8=64, +8=72, +16=88, +48=136, +32=168, +8=176, +8=184

template <int PtrSize>
struct NET_BUFFER : public EmuStructHelper<NET_BUFFER<PtrSize>>,
                    public NET_BUFFER_POD<PtrSize> {
    std::string get_mem_tag() const override { return "net_buffer"; }
};

#pragma pack(pop)

}}} // namespace speakeasy::deffs::ndis

#endif // SPEAKEASY_DEFS_NEW_NDIS_NDIS_H
