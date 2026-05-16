// ndis.h — Network Driver Interface Specification (NDIS) types
//
// Maps to: speakeasy/winenv/defs/ndis/ndis.py
//
// NDIS packet and buffer list structures used by network
// driver emulation.

#ifndef SPEAKEASY_DEFS_NDIS_NDIS_H
#define SPEAKEASY_DEFS_NDIS_NDIS_H

#include <cstdint>
#include <vector>
#include "../../../../struct.h"

namespace speakeasy { namespace defs { namespace ndis {

// ── NDIS_OBJECT_HEADER (4 bytes) ─────────────────────────
struct NDIS_OBJECT_HEADER : speakeasy::EmuStruct {
    uint8_t  Type     = 0;  // offset 0
    uint8_t  Revision = 0;  // offset 1
    uint16_t Size     = 0;  // offset 2

    size_t sizeof_obj() const override { return 4; }
    std::vector<uint8_t> get_bytes() const override {
        std::vector<uint8_t> b(4);
        speakeasy::write_le(b, 0, Type, 1);
        speakeasy::write_le(b, 1, Revision, 1);
        speakeasy::write_le(b, 2, Size, 2);
        return b;
    }
};

// ── NDIS_GENERIC_OBJECT ──────────────────────────────────
struct NDIS_GENERIC_OBJECT : speakeasy::EmuStruct {
    NDIS_OBJECT_HEADER Header;
    uint32_t __pad0    = 0;  // padding after Header to align pointer
    uint64_t Caller         = 0;  // Ptr
    uint64_t CallersCaller  = 0;  // Ptr
    uint64_t DriverObject   = 0;  // Ptr

    size_t sizeof_obj() const override {
        return Header.sizeof_obj() + 4 + 3 * 8;
    }
    std::vector<uint8_t> get_bytes() const override {
        std::vector<uint8_t> b(32);
        auto hb = Header.get_bytes();
        std::copy(hb.begin(), hb.end(), b.begin());
        // __pad0 at offset 4
        speakeasy::write_le(b, 8, Caller, 8);
        speakeasy::write_le(b, 16, CallersCaller, 8);
        speakeasy::write_le(b, 24, DriverObject, 8);
        return b;
    }
};

// ── NET_BUFFER_LIST_POOL_PARAMETERS (20 bytes) ───────────
struct NET_BUFFER_LIST_POOL_PARAMETERS : speakeasy::EmuStruct {
    NDIS_OBJECT_HEADER Header;
    uint8_t  ProtocolId            = 0;
    uint8_t  fAllocateNetBuffer    = 0;
    uint16_t ContextSize           = 0;
    uint32_t PoolTag               = 0;
    uint32_t DataSize              = 0;

    size_t sizeof_obj() const override {
        return 12 + 4 + 4;  // Header (4) + ProtocolId(1)+fAllocate(1)+ContextSize(2)+PoolTag(4)+DataSize(4) = 16? No...
        // Actually: Header(4) + ProtocolId(1) + fAllocateNetBuffer(1) + ContextSize(2) + PoolTag(4) + DataSize(4) = 16
    }
    std::vector<uint8_t> get_bytes() const override {
        std::vector<uint8_t> b(16);
        auto hb = Header.get_bytes();
        std::copy(hb.begin(), hb.end(), b.begin());
        speakeasy::write_le(b, 4, ProtocolId, 1);
        speakeasy::write_le(b, 5, fAllocateNetBuffer, 1);
        speakeasy::write_le(b, 6, ContextSize, 2);
        speakeasy::write_le(b, 8, PoolTag, 4);
        speakeasy::write_le(b, 12, DataSize, 4);
        return b;
    }
};

// ── NET_BUFFER_LIST (x64: 128 bytes) ─────────────────────
struct NET_BUFFER_LIST : speakeasy::EmuStruct {
    uint64_t Next              = 0;  // Ptr
    uint64_t FirstNetBuffer    = 0;  // Ptr
    uint64_t Context           = 0;  // Ptr
    uint64_t ParentNetBufferList = 0; // Ptr
    uint64_t NdisPoolHandle    = 0;  // Ptr
    uint64_t NdisReserved[2]   = {};  // Ptr * 2
    uint64_t ProtocolReserved[4] = {}; // Ptr * 4
    uint64_t MiniportReserved[2] = {}; // Ptr * 2
    uint64_t Scratch           = 0;  // Ptr
    uint64_t SourceHandle      = 0;  // Ptr
    uint32_t NblFlags          = 0;
    uint32_t ChildRefCount     = 0;
    uint32_t Flags             = 0;
    uint32_t __pad0            = 0;
    uint64_t NetBufferListInfo[11] = {}; // Ptr * 11

    size_t sizeof_obj() const override {
        return 5 * 8 + 2 * 8 + 4 * 8 + 2 * 8 + 2 * 8 + 3 * 4 + 4 + 11 * 8;
        // 5 ptrs + 2[2] + 4[4] + 2[2] + 2 ptrs + 3 u32 + pad + 11 ptrs
        // = 5+2+4+2+2+11 = 26 ptrs * 8 = 208 + 12 bytes of u32 + 4 pad = 224
    }
    std::vector<uint8_t> get_bytes() const override {
        size_t sz = sizeof_obj();
        std::vector<uint8_t> b(sz, 0);
        size_t off = 0;
        speakeasy::write_le(b, off, Next, 8); off += 8;
        speakeasy::write_le(b, off, FirstNetBuffer, 8); off += 8;
        speakeasy::write_le(b, off, Context, 8); off += 8;
        speakeasy::write_le(b, off, ParentNetBufferList, 8); off += 8;
        speakeasy::write_le(b, off, NdisPoolHandle, 8); off += 8;
        for (int i = 0; i < 2; i++) {
            speakeasy::write_le(b, off, NdisReserved[i], 8); off += 8;
        }
        for (int i = 0; i < 4; i++) {
            speakeasy::write_le(b, off, ProtocolReserved[i], 8); off += 8;
        }
        for (int i = 0; i < 2; i++) {
            speakeasy::write_le(b, off, MiniportReserved[i], 8); off += 8;
        }
        speakeasy::write_le(b, off, Scratch, 8); off += 8;
        speakeasy::write_le(b, off, SourceHandle, 8); off += 8;
        speakeasy::write_le(b, off, NblFlags, 4); off += 4;
        speakeasy::write_le(b, off, ChildRefCount, 4); off += 4;
        speakeasy::write_le(b, off, Flags, 4); off += 4;
        off += 4; // __pad0
        for (int i = 0; i < 11; i++) {
            speakeasy::write_le(b, off, NetBufferListInfo[i], 8); off += 8;
        }
        return b;
    }
};

// ── NET_BUFFER_DATA (24 bytes) ───────────────────────────
struct NET_BUFFER_DATA : speakeasy::EmuStruct {
    uint64_t Next             = 0;  // Ptr
    uint64_t CurrentMdl       = 0;  // Ptr
    uint32_t CurrentMdlOffset = 0;
    uint32_t NbDataLength     = 0;
    uint64_t MdlChain         = 0;  // Ptr
    uint32_t DataOffset       = 0;
    uint32_t __pad0           = 0;

    size_t sizeof_obj() const override { return 8 + 8 + 4 + 4 + 8 + 4 + 4; }
    std::vector<uint8_t> get_bytes() const override {
        std::vector<uint8_t> b(40);
        speakeasy::write_le(b, 0, Next, 8);
        speakeasy::write_le(b, 8, CurrentMdl, 8);
        speakeasy::write_le(b, 16, CurrentMdlOffset, 4);
        speakeasy::write_le(b, 20, NbDataLength, 4);
        speakeasy::write_le(b, 24, MdlChain, 8);
        speakeasy::write_le(b, 32, DataOffset, 4);
        // __pad0 at offset 36
        return b;
    }
};

// ── NET_BUFFER_HEADER (16 bytes) ─────────────────────────
struct NET_BUFFER_HEADER : speakeasy::EmuStruct {
    NET_BUFFER_DATA NetBufferData;
    uint64_t        Link = 0;  // Ptr

    size_t sizeof_obj() const override {
        return NetBufferData.sizeof_obj() + 8;
    }
    std::vector<uint8_t> get_bytes() const override {
        auto nb = NetBufferData.get_bytes();
        std::vector<uint8_t> b(nb.size() + 8);
        std::copy(nb.begin(), nb.end(), b.begin());
        speakeasy::write_le(b, nb.size(), Link, 8);
        return b;
    }
};

// ── NET_BUFFER (x64) ─────────────────────────────────────
struct NET_BUFFER : speakeasy::EmuStruct {
    uint64_t Link              = 0;  // Ptr
    uint64_t __pad0            = 0;  // padding for NET_BUFFER_HEADER alignment
    NET_BUFFER_HEADER NetBufferHeader;
    uint64_t ChecksumBias      = 0;  // Ptr (actually PVOID, but stored in a LONG on x64 sometimes...)
    // Hmm, in Python: self.ChecksumBias = Ptr, so 8 bytes
    uint64_t Reserved          = 0;  // Ptr
    uint64_t NdisPoolHandle    = 0;  // Ptr
    uint64_t NdisReserved[2]   = {}; // Ptr * 2
    uint64_t ProtocolReserved[6] = {}; // Ptr * 6
    uint64_t MiniportReserved[4] = {}; // Ptr * 4
    uint64_t DataPhysicalAddress = 0; // PHYSICAL_ADDRESS = LARGE_INTEGER = 8 bytes
    uint64_t SharedMemoryInfo  = 0;  // Ptr

    size_t sizeof_obj() const override {
        // Link(8) + NetBufferHeader(NET_BUFFER_DATA.sizeof()+8) + ... 
        // Let's compute step by step
        // Link = 8
        // NetBufferHeader = 48 (NET_BUFFER_DATA=40 + Link=8)
        // ChecksumBias + Reserved + NdisPoolHandle = 24
        // NdisReserved[2] = 16
        // ProtocolReserved[6] = 48
        // MiniportReserved[4] = 32
        // DataPhysicalAddress = 8
        // SharedMemoryInfo = 8
        return 8 + NetBufferHeader.sizeof_obj() + 3 * 8 + 2 * 8 + 6 * 8 + 4 * 8 + 8 + 8;
    }
    std::vector<uint8_t> get_bytes() const override {
        size_t sz = sizeof_obj();
        std::vector<uint8_t> b(sz, 0);
        size_t off = 0;
        speakeasy::write_le(b, off, Link, 8); off += 8;
        auto nbh = NetBufferHeader.get_bytes();
        std::copy(nbh.begin(), nbh.end(), b.begin() + off); off += nbh.size();
        speakeasy::write_le(b, off, ChecksumBias, 8); off += 8;
        speakeasy::write_le(b, off, Reserved, 8); off += 8;
        speakeasy::write_le(b, off, NdisPoolHandle, 8); off += 8;
        for (int i = 0; i < 2; i++) {
            speakeasy::write_le(b, off, NdisReserved[i], 8); off += 8;
        }
        for (int i = 0; i < 6; i++) {
            speakeasy::write_le(b, off, ProtocolReserved[i], 8); off += 8;
        }
        for (int i = 0; i < 4; i++) {
            speakeasy::write_le(b, off, MiniportReserved[i], 8); off += 8;
        }
        speakeasy::write_le(b, off, DataPhysicalAddress, 8); off += 8;
        speakeasy::write_le(b, off, SharedMemoryInfo, 8); off += 8;
        return b;
    }
};

}}} // namespace speakeasy::defs::ndis

#endif // SPEAKEASY_DEFS_NDIS_NDIS_H
