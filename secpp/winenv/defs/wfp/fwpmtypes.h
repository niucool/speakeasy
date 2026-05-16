// fwpmtypes.h — Windows Filtering Platform (WFP) type definitions
//
// Maps to: speakeasy/winenv/defs/wfp/fwpmtypes.py
//
// WFP management and callout types used by firewall and
// network filtering emulation.

#ifndef SPEAKEASY_DEFS_WFP_FWPMTYPES_H
#define SPEAKEASY_DEFS_WFP_FWPMTYPES_H

#include <cstdint>
#include <vector>
#include "../../../../struct.h"

namespace speakeasy { namespace defs { namespace wfp {

// ── GUID (16 bytes) ──────────────────────────────────────
struct GUID : speakeasy::EmuStruct {
    uint32_t Data1 = 0;
    uint16_t Data2 = 0;
    uint16_t Data3 = 0;
    uint8_t  Data4[8] = {};

    size_t sizeof_obj() const override { return 16; }
    std::vector<uint8_t> get_bytes() const override {
        std::vector<uint8_t> b(16);
        speakeasy::write_le(b, 0, Data1, 4);
        speakeasy::write_le(b, 4, Data2, 2);
        speakeasy::write_le(b, 6, Data3, 2);
        for (int i = 0; i < 8; i++)
            speakeasy::write_le(b, 8 + i, Data4[i], 1);
        return b;
    }
};

// ── FWPM_DISPLAY_DATA0 (16 bytes) ────────────────────────
struct FWPM_DISPLAY_DATA0 : speakeasy::EmuStruct {
    uint64_t name        = 0;  // PWSTR
    uint64_t description = 0;  // PWSTR

    size_t sizeof_obj() const override { return 16; }
    std::vector<uint8_t> get_bytes() const override {
        std::vector<uint8_t> b(16);
        speakeasy::write_le(b, 0, name, 8);
        speakeasy::write_le(b, 8, description, 8);
        return b;
    }
};

// ── FWP_VALUE0 (16 bytes) ────────────────────────────────
struct FWP_VALUE0 : speakeasy::EmuStruct {
    uint32_t type = 0;    // FWP_DATA_TYPE
    uint32_t __pad0 = 0;
    uint64_t data = 0;    // union (largest member is a pointer)

    size_t sizeof_obj() const override { return 4 + 4 + 8; }
    std::vector<uint8_t> get_bytes() const override {
        std::vector<uint8_t> b(16);
        speakeasy::write_le(b, 0, type, 4);
        // __pad0
        speakeasy::write_le(b, 8, data, 8);
        return b;
    }
};

// ── FWP_BYTE_BLOB (16 bytes) ─────────────────────────────
struct FWP_BYTE_BLOB : speakeasy::EmuStruct {
    uint32_t size = 0;
    uint32_t __pad0 = 0;
    uint64_t data = 0;  // PUINT8

    size_t sizeof_obj() const override { return 4 + 4 + 8; }
    std::vector<uint8_t> get_bytes() const override {
        std::vector<uint8_t> b(16);
        speakeasy::write_le(b, 0, size, 4);
        // __pad0
        speakeasy::write_le(b, 8, data, 8);
        return b;
    }
};

// ── FWPM_SUBLAYER0 (80 bytes) ────────────────────────────
struct FWPM_SUBLAYER0 : speakeasy::EmuStruct {
    GUID      subLayerKey;
    FWPM_DISPLAY_DATA0 displayData;
    uint32_t  flags = 0;
    uint32_t  __pad0 = 0;
    GUID      providerKey;
    FWP_BYTE_BLOB providerData;
    uint16_t  weight = 0;
    uint8_t   __pad1[6] = {};

    size_t sizeof_obj() const override {
        return 16 + 16 + 4 + 4 + 16 + 16 + 2 + 6;
    }
    std::vector<uint8_t> get_bytes() const override {
        size_t sz = sizeof_obj();
        std::vector<uint8_t> b(sz, 0);
        size_t off = 0;
        auto gb = subLayerKey.get_bytes();
        std::copy(gb.begin(), gb.end(), b.begin() + off); off += gb.size();
        auto db = displayData.get_bytes();
        std::copy(db.begin(), db.end(), b.begin() + off); off += db.size();
        speakeasy::write_le(b, off, flags, 4); off += 8; // +4 pad
        gb = providerKey.get_bytes();
        std::copy(gb.begin(), gb.end(), b.begin() + off); off += gb.size();
        auto pb = providerData.get_bytes();
        std::copy(pb.begin(), pb.end(), b.begin() + off); off += pb.size();
        speakeasy::write_le(b, off, weight, 2); off += 8; // +6 pad
        return b;
    }
};

// ── FWPS_CALLOUT1 (40 bytes) ─────────────────────────────
struct FWPS_CALLOUT1 : speakeasy::EmuStruct {
    GUID     calloutKey;
    uint32_t flags = 0;
    uint32_t __pad0 = 0;
    uint64_t classifyFn   = 0;  // Ptr
    uint64_t notifyFn     = 0;  // Ptr
    uint64_t flowDeleteFn = 0;  // Ptr

    size_t sizeof_obj() const override {
        return 16 + 4 + 4 + 3 * 8;
    }
    std::vector<uint8_t> get_bytes() const override {
        std::vector<uint8_t> b(40);
        auto gb = calloutKey.get_bytes();
        std::copy(gb.begin(), gb.end(), b.begin());
        speakeasy::write_le(b, 16, flags, 4);
        // __pad0
        speakeasy::write_le(b, 24, classifyFn, 8);
        speakeasy::write_le(b, 32, notifyFn, 8);
        speakeasy::write_le(b, 40, flowDeleteFn, 8);
        return b;
    }
};

// ── FWPM_CALLOUT0 (88 bytes) ─────────────────────────────
struct FWPM_CALLOUT0 : speakeasy::EmuStruct {
    GUID      calloutKey;
    FWPM_DISPLAY_DATA0 displayData;
    uint32_t  flags = 0;
    uint32_t  __pad0 = 0;
    GUID      providerKey;
    FWP_BYTE_BLOB providerData;
    GUID      applicableLayer;
    uint32_t  calloutId = 0;
    uint32_t  __pad1 = 0;

    size_t sizeof_obj() const override {
        return 16 + 16 + 4 + 4 + 16 + 16 + 16 + 4 + 4;
    }
    std::vector<uint8_t> get_bytes() const override {
        size_t sz = sizeof_obj();
        std::vector<uint8_t> b(sz, 0);
        size_t off = 0;
        auto gb = calloutKey.get_bytes();
        std::copy(gb.begin(), gb.end(), b.begin() + off); off += gb.size();
        auto db = displayData.get_bytes();
        std::copy(db.begin(), db.end(), b.begin() + off); off += db.size();
        speakeasy::write_le(b, off, flags, 4); off += 8; // +4 pad
        gb = providerKey.get_bytes();
        std::copy(gb.begin(), gb.end(), b.begin() + off); off += gb.size();
        auto pb = providerData.get_bytes();
        std::copy(pb.begin(), pb.end(), b.begin() + off); off += pb.size();
        gb = applicableLayer.get_bytes();
        std::copy(gb.begin(), gb.end(), b.begin() + off); off += gb.size();
        speakeasy::write_le(b, off, calloutId, 4); off += 8; // +4 pad
        return b;
    }
};

// ── FWPM_FILTER_CONDITION0 (32 bytes) ────────────────────
struct FWPM_FILTER_CONDITION0 : speakeasy::EmuStruct {
    GUID       fieldKey;
    uint32_t   matchType = 0;
    uint32_t   __pad0 = 0;
    FWP_VALUE0 conditionValue;

    size_t sizeof_obj() const override {
        return 16 + 4 + 4 + 16;
    }
    std::vector<uint8_t> get_bytes() const override {
        std::vector<uint8_t> b(40);
        auto gb = fieldKey.get_bytes();
        std::copy(gb.begin(), gb.end(), b.begin());
        speakeasy::write_le(b, 16, matchType, 4);
        // __pad0
        auto cv = conditionValue.get_bytes();
        std::copy(cv.begin(), cv.end(), b.begin() + 24);
        return b;
    }
};

// ── FWPM_ACTION0 (20 bytes) ──────────────────────────────
struct FWPM_ACTION0 : speakeasy::EmuStruct {
    uint32_t type = 0;
    uint32_t __pad0 = 0;
    GUID     filterType;

    size_t sizeof_obj() const override {
        return 4 + 4 + 16;
    }
    std::vector<uint8_t> get_bytes() const override {
        std::vector<uint8_t> b(24);
        speakeasy::write_le(b, 0, type, 4);
        // __pad0
        auto gb = filterType.get_bytes();
        std::copy(gb.begin(), gb.end(), b.begin() + 8);
        return b;
    }
};

// ── FWPM_FILTER0 (152 bytes) ─────────────────────────────
struct FWPM_FILTER0 : speakeasy::EmuStruct {
    GUID      filterKey;
    FWPM_DISPLAY_DATA0 displayData;
    uint32_t  flags = 0;
    uint32_t  __pad0 = 0;
    GUID      providerKey;
    FWP_BYTE_BLOB providerData;
    GUID      layerKey;
    GUID      subLayerKey;
    FWP_VALUE0 weight;
    uint32_t  numFilterConditions = 0;
    uint32_t  __pad1 = 0;
    uint64_t  filterCondition    = 0;  // Ptr to FWPM_FILTER_CONDITION0[]
    FWPM_ACTION0 action;
    GUID      providerContextKey;
    uint64_t  reserved = 0;  // Ptr
    uint64_t  filterId = 0;
    FWP_VALUE0 effectiveWeight;

    // Note: On x64 this struct is:
    // filterKey (16) + displayData (16) + flags(4)+pad(4) + providerKey(16)
    // + providerData(16) + layerKey(16) + subLayerKey(16) + weight(16)
    // + numFilterConditions(4)+pad(4) + filterCondition(8) + action(24)
    // + providerContextKey(16) + reserved(8) + filterId(8) + effectiveWeight(16)

    size_t sizeof_obj() const override {
        return 16 + 16 + 8 + 16 + 16 + 16 + 16 + 16 + 8 + 8 + 24 + 16 + 8 + 8 + 16;
    }
    std::vector<uint8_t> get_bytes() const override {
        size_t sz = sizeof_obj();
        std::vector<uint8_t> b(sz, 0);
        size_t off = 0;
        auto gb = filterKey.get_bytes();
        std::copy(gb.begin(), gb.end(), b.begin() + off); off += gb.size();
        auto dd = displayData.get_bytes();
        std::copy(dd.begin(), dd.end(), b.begin() + off); off += dd.size();
        speakeasy::write_le(b, off, flags, 4); off += 8; // +4 pad
        gb = providerKey.get_bytes();
        std::copy(gb.begin(), gb.end(), b.begin() + off); off += gb.size();
        auto pd = providerData.get_bytes();
        std::copy(pd.begin(), pd.end(), b.begin() + off); off += pd.size();
        gb = layerKey.get_bytes();
        std::copy(gb.begin(), gb.end(), b.begin() + off); off += gb.size();
        gb = subLayerKey.get_bytes();
        std::copy(gb.begin(), gb.end(), b.begin() + off); off += gb.size();
        auto wb = weight.get_bytes();
        std::copy(wb.begin(), wb.end(), b.begin() + off); off += wb.size();
        speakeasy::write_le(b, off, numFilterConditions, 4); off += 8; // +4 pad
        speakeasy::write_le(b, off, filterCondition, 8); off += 8;
        auto ab = action.get_bytes();
        std::copy(ab.begin(), ab.end(), b.begin() + off); off += ab.size();
        gb = providerContextKey.get_bytes();
        std::copy(gb.begin(), gb.end(), b.begin() + off); off += gb.size();
        speakeasy::write_le(b, off, reserved, 8); off += 8;
        speakeasy::write_le(b, off, filterId, 8); off += 8;
        auto ew = effectiveWeight.get_bytes();
        std::copy(ew.begin(), ew.end(), b.begin() + off); off += ew.size();
        return b;
    }
};

}}} // namespace speakeasy::defs::wfp

#endif // SPEAKEASY_DEFS_WFP_FWPMTYPES_H
