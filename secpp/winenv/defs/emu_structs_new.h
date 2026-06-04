#ifndef SPEAKEASY_EMU_STRUCTS_NEW_H
#define SPEAKEASY_EMU_STRUCTS_NEW_H

#include <cstdint>
#include <vector>
#include <string>
#include <type_traits>
#include <cstring>
#include "struct.h"

namespace speakeasy { namespace defs { namespace new_structs {

#pragma pack(push, 1)

// Helper to choose pointer types dynamically based on pointer size (4 or 8)
template <int PtrSize>
struct PointerType {
    using Type = typename std::conditional<PtrSize == 8, uint64_t, uint32_t>::type;
};

// ── 1. LIST_ENTRY ───────────────────────────────────────────────────────────
template <int PtrSize>
struct LIST_ENTRY_POD {
    typename PointerType<PtrSize>::Type Flink = 0;
    typename PointerType<PtrSize>::Type Blink = 0;
};

template <int PtrSize>
struct LIST_ENTRY : public EmuStructHelper<LIST_ENTRY<PtrSize>>, public LIST_ENTRY_POD<PtrSize> {
    std::string get_mem_tag() const override { return "list_entry"; }
};

// ── 2. KSYSTEM_TIME ──────────────────────────────────────────────────────────
struct KSYSTEM_TIME : public EmuStructHelper<KSYSTEM_TIME> {
    uint32_t LowPart    = 0;
    uint32_t High1Time  = 0;
    uint32_t High2Time  = 0;
    std::string get_mem_tag() const override { return "ksystem_time"; }
};

// ── 3. UNICODE_STRING ────────────────────────────────────────────────────────
template <int PtrSize>
struct UNICODE_STRING_POD;

template <>
struct UNICODE_STRING_POD<4> {
    uint16_t Length = 0;
    uint16_t MaximumLength = 0;
    uint32_t Buffer = 0;
};

template <>
struct UNICODE_STRING_POD<8> {
    uint16_t Length = 0;
    uint16_t MaximumLength = 0;
    uint32_t padding = 0;
    uint64_t Buffer = 0;
};

template <int PtrSize>
struct UNICODE_STRING : public EmuStructHelper<UNICODE_STRING<PtrSize>>, public UNICODE_STRING_POD<PtrSize> {
    std::string get_mem_tag() const override { return "unicode_string"; }
};

// ── 4. STRING ────────────────────────────────────────────────────────────────
template <int PtrSize>
struct STRING_POD : public UNICODE_STRING_POD<PtrSize> {};

template <int PtrSize>
struct STRING : public EmuStructHelper<STRING<PtrSize>>, public STRING_POD<PtrSize> {
    std::string get_mem_tag() const override { return "string"; }
};

// ── 5. OBJECT_ATTRIBUTES ─────────────────────────────────────────────────────
template <int PtrSize>
struct OBJECT_ATTRIBUTES_POD;

template <>
struct OBJECT_ATTRIBUTES_POD<4> {
    uint32_t Length = 0;
    uint32_t RootDirectory = 0;
    uint32_t ObjectName = 0;
    uint32_t Attributes = 0;
    uint32_t SecurityDescriptor = 0;
    uint32_t SecurityQoS = 0;
};

template <>
struct OBJECT_ATTRIBUTES_POD<8> {
    uint32_t Length = 0;
    uint32_t padding1 = 0;
    uint64_t RootDirectory = 0;
    uint64_t ObjectName = 0;
    uint32_t Attributes = 0;
    uint32_t padding2 = 0;
    uint64_t SecurityDescriptor = 0;
    uint64_t SecurityQoS = 0;
};

template <int PtrSize>
struct OBJECT_ATTRIBUTES : public EmuStructHelper<OBJECT_ATTRIBUTES<PtrSize>>, public OBJECT_ATTRIBUTES_POD<PtrSize> {
    std::string get_mem_tag() const override { return "object_attributes"; }
};

// ── 6. IO_STATUS_BLOCK ───────────────────────────────────────────────────────
template <int PtrSize>
struct IO_STATUS_BLOCK_POD {
    typename PointerType<PtrSize>::Type Status = 0;
    typename PointerType<PtrSize>::Type Information = 0;
};

template <int PtrSize>
struct IO_STATUS_BLOCK : public EmuStructHelper<IO_STATUS_BLOCK<PtrSize>>, public IO_STATUS_BLOCK_POD<PtrSize> {
    std::string get_mem_tag() const override { return "io_status_block"; }
};

// ── 7. LARGE_INTEGER ─────────────────────────────────────────────────────────
struct LARGE_INTEGER : public EmuStructHelper<LARGE_INTEGER> {
    uint64_t QuadPart = 0;
    std::string get_mem_tag() const override { return "large_integer"; }
};

// ── 8. SYSTEM_TIMEOFDAY_INFORMATION ──────────────────────────────────────────
struct SYSTEM_TIMEOFDAY_INFORMATION : public EmuStructHelper<SYSTEM_TIMEOFDAY_INFORMATION> {
    uint64_t BootTime       = 0;
    uint64_t CurrentTime    = 0;
    uint64_t TimeZoneBias   = 0;
    uint32_t TimeZoneId     = 0;
    uint32_t Reserved       = 0;
    uint64_t BootTimeBias   = 0;
    uint64_t SleepTimeBias  = 0;
    std::string get_mem_tag() const override { return "system_timeofday_info"; }
};

// ── 9. DISK_EXTENT ───────────────────────────────────────────────────────────
struct DISK_EXTENT_POD {
    uint32_t DiskNumber = 0;
    uint8_t  padding[4] = {};
    uint64_t StartingOffset = 0;
    uint64_t ExtentLength = 0;
};

struct DISK_EXTENT : public EmuStructHelper<DISK_EXTENT>, public DISK_EXTENT_POD {
    std::string get_mem_tag() const override { return "disk_extent"; }
};

// ── 10. VOLUME_DISK_EXTENTS ──────────────────────────────────────────────────
struct VOLUME_DISK_EXTENTS : public EmuStructHelper<VOLUME_DISK_EXTENTS> {
    uint32_t NumberOfDiskExtents = 0;
    uint8_t  padding[4] = {};
    DISK_EXTENT_POD Extents[1];
    std::string get_mem_tag() const override { return "volume_disk_extents"; }
};

// ── 11. NDIS_OBJECT_HEADER ───────────────────────────────────────────────────
struct NDIS_OBJECT_HEADER : public EmuStructHelper<NDIS_OBJECT_HEADER> {
    uint8_t  Type = 0;
    uint8_t  Revision = 0;
    uint16_t Size = 0;
    std::string get_mem_tag() const override { return "ndis_object_header"; }
};

// ── 12. USB_DEVICE_DESCRIPTOR ────────────────────────────────────────────────
struct USB_DEVICE_DESCRIPTOR : public EmuStructHelper<USB_DEVICE_DESCRIPTOR> {
    uint8_t  bLength = 0;
    uint8_t  bDescriptorType = 0;
    uint16_t bcdUSB = 0;
    uint8_t  bDeviceClass = 0;
    uint8_t  bDeviceSubClass = 0;
    uint8_t  bDeviceProtocol = 0;
    uint8_t  bMaxPacketSize0 = 0;
    uint16_t idVendor = 0;
    uint16_t idProduct = 0;
    uint16_t bcdDevice = 0;
    uint8_t  iManufacturer = 0;
    uint8_t  iProduct = 0;
    uint8_t  iSerialNumber = 0;
    uint8_t  bNumConfigurations = 0;
    std::string get_mem_tag() const override { return "usb_device_descriptor"; }
};

// ── 13. KEY_VALUE_PARTIAL_INFORMATION ────────────────────────────────────────
struct KEY_VALUE_PARTIAL_INFORMATION : public EmuStructHelper<KEY_VALUE_PARTIAL_INFORMATION> {
    uint32_t TitleIndex = 0;
    uint32_t Type = 0;
    uint32_t DataLength = 0;
    uint8_t  Data[1] = {};
    std::string get_mem_tag() const override { return "key_value_partial_info"; }
};

// ── 14. WDF_VERSION ──────────────────────────────────────────────────────────
struct WDF_VERSION : public EmuStructHelper<WDF_VERSION> {
    uint32_t Major = 0;
    uint32_t Minor = 0;
    uint32_t Build = 0;
    std::string get_mem_tag() const override { return "wdf_version"; }
};

#pragma pack(pop)

}}} // namespace speakeasy::defs::new_structs

#endif // SPEAKEASY_EMU_STRUCTS_NEW_H
