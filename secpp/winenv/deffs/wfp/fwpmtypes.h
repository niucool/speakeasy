// fwpmtypes.h  Windows Filtering Platform type definitions (new EmuStructHelper CRTP)
//
// Maps to: speakeasy/winenv/defs/wfp/fwpmtypes.py
//
// Uses the new EmuStructHelper CRTP approach for auto serialize/deserialize.
// All structs use #pragma pack(push, 1) with explicit padding fields to match
// the sizeof() that Python ctypes (natural C ABI alignment) would produce.
//
// NOTE: GUID is already defined in secpp/winenv/deffs/windows/windows.h.
// We provide an independent definition here to avoid circular dependencies.

#ifndef SPEAKEASY_DEFS_NEW_WFP_FWPMTYPES_H
#define SPEAKEASY_DEFS_NEW_WFP_FWPMTYPES_H

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include "struct.h"

namespace speakeasy { namespace deffs { namespace wfp {

#pragma pack(push, 1)

// ==========================================================================================================
// GUID: 16 bytes (u32 + u16 + u16 + u8[8])
// ==========================================================================================================
struct GUID_FWP_POD {
    uint32_t Data1     = 0;
    uint16_t Data2     = 0;
    uint16_t Data3     = 0;
    uint8_t  Data4[8]  = {};
    // total = 16
};

struct GUID_FWP : public EmuStructHelper<GUID_FWP>, public GUID_FWP_POD {
    std::string get_mem_tag() const override { return "guid_fwp"; }
};

// ==========================================================================================================
// FWPM_DISPLAY_DATA0: name(Ptr) + description(Ptr)
//   x86: 4+4 = 8
//   x64: 8+8 = 16
// ==========================================================================================================
template <int PtrSize>
struct FWPM_DISPLAY_DATA0_POD;

template <>
struct FWPM_DISPLAY_DATA0_POD<4> {
    uint32_t name;         // offset 0
    uint32_t description;  // offset 4
    // total = 8
};

template <>
struct FWPM_DISPLAY_DATA0_POD<8> {
    uint64_t name;         // offset 0
    uint64_t description;  // offset 8
    // total = 16
};

template <int PtrSize>
struct FWPM_DISPLAY_DATA0 : public EmuStructHelper<FWPM_DISPLAY_DATA0<PtrSize>>,
                            public FWPM_DISPLAY_DATA0_POD<PtrSize> {
    std::string get_mem_tag() const override { return "fwpm_display_data0"; }
};

// ==========================================================================================================
// FWP_VALUE0: type(u32) + data(Ptr)
//   x86: 4+4 = 8
//   x64: 4+pad(4)+8 = 16
// ==========================================================================================================
template <int PtrSize>
struct FWP_VALUE0_POD;

template <>
struct FWP_VALUE0_POD<4> {
    uint32_t type;   // offset 0
    uint32_t data;   // offset 4
    // total = 8
};

template <>
struct FWP_VALUE0_POD<8> {
    uint32_t type;   // offset 0
    uint32_t pad;    // offset 4
    uint64_t data;   // offset 8
    // total = 16
};

template <int PtrSize>
struct FWP_VALUE0 : public EmuStructHelper<FWP_VALUE0<PtrSize>>,
                    public FWP_VALUE0_POD<PtrSize> {
    std::string get_mem_tag() const override { return "fwp_value0"; }
};

// ==========================================================================================================
// FWP_BYTE_BLOB: size(u32) + data(Ptr)
//   x86: 4+4 = 8
//   x64: 4+pad(4)+8 = 16
// ==========================================================================================================
template <int PtrSize>
struct FWP_BYTE_BLOB_POD;

template <>
struct FWP_BYTE_BLOB_POD<4> {
    uint32_t size;   // offset 0
    uint32_t data;   // offset 4
    // total = 8
};

template <>
struct FWP_BYTE_BLOB_POD<8> {
    uint32_t size;   // offset 0
    uint32_t pad;    // offset 4
    uint64_t data;   // offset 8
    // total = 16
};

template <int PtrSize>
struct FWP_BYTE_BLOB : public EmuStructHelper<FWP_BYTE_BLOB<PtrSize>>,
                       public FWP_BYTE_BLOB_POD<PtrSize> {
    std::string get_mem_tag() const override { return "fwp_byte_blob"; }
};

// ==========================================================================================================
// FWPM_SUBLAYER0:
//   subLayerKey(GUID,16)+displayData(FWPM_DISPLAY_DATA0)+flags(u32)+
//   providerKey(GUID,16)+providerData(FWP_BYTE_BLOB)+weight(u16)
//   x86: 16+8+4+16+8+2 = 54
//   x64: 16+16+4+pad(4)+16+16+2+pad(6) = 76
// ==========================================================================================================
template <int PtrSize>
struct FWPM_SUBLAYER0_POD;

template <>
struct FWPM_SUBLAYER0_POD<4> {
    GUID_FWP_POD              subLayerKey;     // offset  0 (16 bytes)
    FWPM_DISPLAY_DATA0_POD<4> displayData;     // offset 16 (8 bytes)
    uint32_t                  flags;           // offset 24
    GUID_FWP_POD              providerKey;     // offset 28 (16 bytes)
    FWP_BYTE_BLOB_POD<4>      providerData;    // offset 44 (8 bytes)
    uint16_t                  weight;          // offset 52
    // total = 54
};

template <>
struct FWPM_SUBLAYER0_POD<8> {
    GUID_FWP_POD              subLayerKey;     // offset  0 (16 bytes)
    FWPM_DISPLAY_DATA0_POD<8> displayData;     // offset 16 (16 bytes)
    uint32_t                  flags;           // offset 32
    uint32_t                  pad1;            // offset 36
    GUID_FWP_POD              providerKey;     // offset 40 (16 bytes)
    FWP_BYTE_BLOB_POD<8>      providerData;    // offset 56 (16 bytes)
    uint16_t                  weight;          // offset 72
    uint8_t                   pad2[6];         // offset 74  align to 8
    // total = 80
};

// Wait: FWPM_DISPLAY_DATA0<8> is 16 bytes (2*Ptr). So:
// subLayerKey(16) @0
// displayData(16) @16
// flags(4) @32
// pad1(4) @36  align providerKey? providerKey is GUID (no pointers), but next is providerData which has a Ptr
// Actually let me just be safe: after flags(4) at 32-35, we have providerKey(GUID, 16 bytes)
// GUID is all uint types, so no alignment needed for it. But FWP_BYTE_BLOB<8> needs 8-byte alignment of its data field.
// Actually, FWP_BYTE_BLOB<8> starts with uint32(4)+pad(4)+Ptr(8). So within the struct, the Ptr is at offset 8.
// The struct itself only needs 4-byte alignment since its first member is uint32.
// So after providerKey(16) at 40-55, providerData starts at 56 (8-byte aligned, good).
// weight(2) at 72-73, pad to 8: 7480 (6 bytes padding).

template <int PtrSize>
struct FWPM_SUBLAYER0 : public EmuStructHelper<FWPM_SUBLAYER0<PtrSize>>,
                         public FWPM_SUBLAYER0_POD<PtrSize> {
    std::string get_mem_tag() const override { return "fwpm_sublayer0"; }
};

// ==========================================================================================================
// FWPS_CALLOUT1:
//   calloutKey(GUID,16)+flags(u32)+classifyFn(Ptr)+notifyFn(Ptr)+flowDeleteFn(Ptr)
//   x86: 16+4+4+4+4 = 32
//   x64: 16+4+pad(4)+8+8+8 = 44... but last 8 rounds to 48 with trailing pad
//   Actually let me be careful: 16+4=20, pad(4)=24, 3*8=48. Total=48.
// ==========================================================================================================
template <int PtrSize>
struct FWPS_CALLOUT1_POD;

template <>
struct FWPS_CALLOUT1_POD<4> {
    GUID_FWP_POD calloutKey;      // offset  0 (16 bytes)
    uint32_t flags;            // offset 16
    uint32_t classifyFn;       // offset 20
    uint32_t notifyFn;         // offset 24
    uint32_t flowDeleteFn;     // offset 28
    // total = 32
};

template <>
struct FWPS_CALLOUT1_POD<8> {
    GUID_FWP_POD calloutKey;      // offset  0 (16 bytes)
    uint32_t flags;            // offset 16
    uint32_t pad1;             // offset 20
    uint64_t classifyFn;       // offset 24
    uint64_t notifyFn;         // offset 32
    uint64_t flowDeleteFn;     // offset 40
    // total = 48
};

template <int PtrSize>
struct FWPS_CALLOUT1 : public EmuStructHelper<FWPS_CALLOUT1<PtrSize>>,
                        public FWPS_CALLOUT1_POD<PtrSize> {
    std::string get_mem_tag() const override { return "fwps_callout1"; }
};

// ==========================================================================================================
// FWPM_CALLOUT0:
//   calloutKey(16)+displayData(FWPM_DISPLAY_DATA0)+flags(u32)+
//   providerKey(16)+providerData(FWP_BYTE_BLOB)+applicableLayer(16)+calloutId(u32)
//   x86: 16+8+4+16+8+16+4 = 72
//   x64: 16+16+4+pad(4)+16+16+16+4+pad(4) = 96
// ==========================================================================================================
template <int PtrSize>
struct FWPM_CALLOUT0_POD;

template <>
struct FWPM_CALLOUT0_POD<4> {
    GUID_FWP_POD              calloutKey;       // offset  0 (16)
    FWPM_DISPLAY_DATA0_POD<4> displayData;      // offset 16 (8)
    uint32_t                  flags;            // offset 24
    GUID_FWP_POD              providerKey;      // offset 28 (16)
    FWP_BYTE_BLOB_POD<4>      providerData;     // offset 44 (8)
    GUID_FWP_POD              applicableLayer;  // offset 52 (16)
    uint32_t                  calloutId;        // offset 68
    // total = 72
};

template <>
struct FWPM_CALLOUT0_POD<8> {
    GUID_FWP_POD              calloutKey;       // offset  0 (16)
    FWPM_DISPLAY_DATA0_POD<8> displayData;      // offset 16 (16)
    uint32_t                  flags;            // offset 32
    uint32_t                  pad1;             // offset 36
    GUID_FWP_POD              providerKey;      // offset 40 (16)
    FWP_BYTE_BLOB_POD<8>      providerData;     // offset 56 (16)
    GUID_FWP_POD              applicableLayer;  // offset 72 (16)
    uint32_t                  calloutId;        // offset 88
    uint32_t                  pad2;             // offset 92  natural alignment to 8
    // total = 96
};

template <int PtrSize>
struct FWPM_CALLOUT0 : public EmuStructHelper<FWPM_CALLOUT0<PtrSize>>,
                        public FWPM_CALLOUT0_POD<PtrSize> {
    std::string get_mem_tag() const override { return "fwpm_callout0"; }
};

// ==========================================================================================================
// FWPM_FILTER_CONDITION0:
//   fieldKey(GUID,16)+matchType(u32)+conditionValue(FWP_VALUE0)
//   x86: 16+4+8 = 28
//   x64: 16+4+pad(4)+16 = 40
// ==========================================================================================================
template <int PtrSize>
struct FWPM_FILTER_CONDITION0_POD;

template <>
struct FWPM_FILTER_CONDITION0_POD<4> {
    GUID_FWP_POD        fieldKey;         // offset  0 (16)
    uint32_t            matchType;        // offset 16
    FWP_VALUE0_POD<4>   conditionValue;   // offset 20 (8)
    // total = 28
};

template <>
struct FWPM_FILTER_CONDITION0_POD<8> {
    GUID_FWP_POD        fieldKey;         // offset  0 (16)
    uint32_t            matchType;        // offset 16
    uint32_t            pad1;             // offset 20
    FWP_VALUE0_POD<8>   conditionValue;   // offset 24 (16)
    // total = 40
};

template <int PtrSize>
struct FWPM_FILTER_CONDITION0 : public EmuStructHelper<FWPM_FILTER_CONDITION0<PtrSize>>,
                                public FWPM_FILTER_CONDITION0_POD<PtrSize> {
    std::string get_mem_tag() const override { return "fwpm_filter_condition0"; }
};

// ==========================================================================================================
// FWPM_ACTION0: type(u32)+filterType(GUID,16)
//   x86: 4+16 = 20
//   x64: 4+pad(4)+16 = 24
// ==========================================================================================================
template <int PtrSize>
struct FWPM_ACTION0_POD;

template <>
struct FWPM_ACTION0_POD<4> {
    uint32_t type;            // offset  0
    GUID_FWP_POD filterType;      // offset  4 (16)
    // total = 20
};

template <>
struct FWPM_ACTION0_POD<8> {
    uint32_t type;            // offset  0
    uint32_t pad1;            // offset  4
    GUID_FWP_POD filterType;      // offset  8 (16)
    // total = 24
};

template <int PtrSize>
struct FWPM_ACTION0 : public EmuStructHelper<FWPM_ACTION0<PtrSize>>,
                      public FWPM_ACTION0_POD<PtrSize> {
    std::string get_mem_tag() const override { return "fwpm_action0"; }
};

// ==========================================================================================================
// FWPM_FILTER0: complex multi-field struct
//   filterKey(16)+displayData+flags(u32)+providerKey(16)+providerData+layerKey(16)+
//   subLayerKey(16)+weight(FWP_VALUE0)+numFilterConditions(u32)+filterCondition(Ptr)+
//   action(FWPM_ACTION0)+providerContextKey(16)+reserved(Ptr)+filterId(u64)+effectiveWeight(FWP_VALUE0)
//
//   x86: 16+8+4+16+8+16+16+8+4+4+20+16+4+8+8 = 152
//   x64: 16+16+4+pad(4)+16+16+16+16+16+4+pad(4)+8+24+16+8+8+16 = ...let me be more careful
// ==========================================================================================================
template <int PtrSize>
struct FWPM_FILTER0_POD;

template <>
struct FWPM_FILTER0_POD<4> {
    GUID_FWP_POD              filterKey;               // offset   0 (16)
    FWPM_DISPLAY_DATA0_POD<4> displayData;             // offset  16 (8)
    uint32_t                  flags;                   // offset  24
    GUID_FWP_POD              providerKey;             // offset  28 (16)
    FWP_BYTE_BLOB_POD<4>      providerData;            // offset  44 (8)
    GUID_FWP_POD              layerKey;                // offset  52 (16)
    GUID_FWP_POD              subLayerKey;             // offset  68 (16)
    FWP_VALUE0_POD<4>         weight;                  // offset  84 (8)
    uint32_t                  numFilterConditions;     // offset  92
    uint32_t                  filterCondition;         // offset  96 (Ptr)
    FWPM_ACTION0_POD<4>       action;                  // offset 100 (20)
    GUID_FWP_POD              providerContextKey;      // offset 120 (16)
    uint32_t                  reserved;                // offset 136 (Ptr)
    uint64_t                  filterId;                // offset 140 (8)
    FWP_VALUE0_POD<4>         effectiveWeight;         // offset 148 (8)
    // total = 156
};

template <>
struct FWPM_FILTER0_POD<8> {
    GUID_FWP_POD              filterKey;               // offset   0 (16)
    FWPM_DISPLAY_DATA0_POD<8> displayData;             // offset  16 (16)
    uint32_t                  flags;                   // offset  32
    uint32_t                  pad1;                    // offset  36
    GUID_FWP_POD              providerKey;             // offset  40 (16)
    FWP_BYTE_BLOB_POD<8>      providerData;            // offset  56 (16)
    GUID_FWP_POD              layerKey;                // offset  72 (16)
    GUID_FWP_POD              subLayerKey;             // offset  88 (16)
    FWP_VALUE0_POD<8>         weight;                  // offset 104 (16)
    uint32_t                  numFilterConditions;     // offset 120
    uint32_t                  pad2;                    // offset 124
    uint64_t                  filterCondition;         // offset 128 (Ptr)
    FWPM_ACTION0_POD<8>       action;                  // offset 136 (24)
    GUID_FWP_POD              providerContextKey;      // offset 160 (16)
    uint64_t                  reserved;                // offset 176 (Ptr)
    uint64_t                  filterId;                // offset 184 (8)
    FWP_VALUE0_POD<8>         effectiveWeight;         // offset 192 (16)
    // total = 208
};

// Let me verify x86: 
// 16+8=24, +4=28, +16=44, +8=52, +16=68, +16=84, +8=92, +4=96, +4=100, +20=120, +16=136, +4=140, +8=148, +8=156
// Total = 156

// Let me verify x64:
// 16+16=32, +4=36, +4=40, +16=56, +16=72, +16=88, +16=104, +16=120, +4=124, +4=128, +8=136, +24=160, +16=176, +8=184, +8=192, +16=208
// Total = 208

template <int PtrSize>
struct FWPM_FILTER0 : public EmuStructHelper<FWPM_FILTER0<PtrSize>>,
                       public FWPM_FILTER0_POD<PtrSize> {
    std::string get_mem_tag() const override { return "fwpm_filter0"; }
};

#pragma pack(pop)

}}} // namespace speakeasy::deffs::wfp

#endif // SPEAKEASY_DEFS_NEW_WFP_FWPMTYPES_H
