// wdf.h  WDF (Windows Driver Framework) type definitions (new EmuStructHelper CRTP)
//
// Maps to: speakeasy/winenv/defs/wdf.py
//
// Uses the new EmuStructHelper CRTP approach for auto serialize/deserialize.
// All structs use #pragma pack(push, 1) with explicit padding fields to match
// the sizeof() that Python ctypes (natural C ABI alignment) would produce.
//
// NOTE: WDF_VERSION is defined below.

#ifndef SPEAKEASY_DEFS_NEW_WDF_H
#define SPEAKEASY_DEFS_NEW_WDF_H

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include "struct.h"
#include "usb.h"

namespace speakeasy { namespace deffs {

#pragma pack(push, 1)

// ==========================================================================================================
// Enum constants from Python
// ==========================================================================================================
enum class WdfUsbTargetDeviceSelectConfigType : int {
    Invalid              = 0,
    Deconfig             = 1,
    SingleInterface      = 2,
    MultiInterface       = 3,
    InterfacesPairs      = 4,
    InterfacesDescriptor = 5,
    Urb                  = 6,
};

enum class WdfUsbTargetDeviceSelectSettingType : int {
    Descriptor = 0x10,
    Setting    = 0x11,
    Urb        = 0x12,
};

enum class WdfUsbPipeType : int {
    Invalid      = 0,
    Control      = 1,
    Isochronous  = 2,
    Bulk         = 3,
    Interrupt    = 4,
};

constexpr uint32_t kWdfUsbDeviceTraitSelfPowered        = 1;
constexpr uint32_t kWdfUsbDeviceTraitRemoteWakeCapable  = 2;
constexpr uint32_t kWdfUsbDeviceTraitAtHighSpeed        = 4;

// ==========================================================================================================
// WDF_VERSION: u32+u32+u32 = 12 bytes
// ==========================================================================================================
struct WDF_VERSION : public EmuStructHelper<WDF_VERSION> {
    uint32_t Major = 0;
    uint32_t Minor = 0;
    uint32_t Build = 0;
    std::string get_mem_tag() const override { return "wdf_version"; }
};

// ==========================================================================================================
// WDF_BIND_INFO: Size(u32)+Component(Ptr)+Version(WDF_VERSION)+FuncCount(u32)+FuncTable(Ptr)+Module(Ptr)
//   x86: 4+4+12+4+4+4 = 32
//   x64: 4+pad(4)+8+12+4+pad(4)+8+8 = 48
// ==========================================================================================================
template <int PtrSize>
struct WDF_BIND_INFO_POD;

template <>
struct WDF_BIND_INFO_POD<4> {
    uint32_t    Size;              // offset  0
    uint32_t    Component;         // offset  4
    WDF_VERSION Version;           // offset  8 (12 bytes)
    uint32_t    FuncCount;         // offset 20
    uint32_t    FuncTable;         // offset 24
    uint32_t    Module;            // offset 28
    // total = 32
};

template <>
struct WDF_BIND_INFO_POD<8> {
    uint32_t    Size;              // offset  0
    uint32_t    pad1;              // offset  4
    uint64_t    Component;         // offset  8
    WDF_VERSION Version;           // offset 16 (12 bytes)
    uint32_t    FuncCount;         // offset 28
    uint64_t    FuncTable;         // offset 32
    uint64_t    Module;            // offset 40
    // total = 48
};

template <int PtrSize>
struct WDF_BIND_INFO : public EmuStructHelper<WDF_BIND_INFO<PtrSize>>,
                        public WDF_BIND_INFO_POD<PtrSize> {
    std::string get_mem_tag() const override { return "wdf_bind_info"; }
};

// ==========================================================================================================
// WDF_USB_DEVICE_INFORMATION: Size(u32)+UsbdVersionInformation(USBD_VERSION_INFORMATION)+
//                             HcdPortCapabilities(u32)+Traits(u32)
//   Fixed layout: 4+8+4+4 = 20
// ==========================================================================================================
struct WDF_USB_DEVICE_INFORMATION_POD {
    uint32_t                  Size;                    // offset  0
    USBD_VERSION_INFORMATION  UsbdVersionInformation;  // offset  4 (8 bytes)
    uint32_t                  HcdPortCapabilities;     // offset 12
    uint32_t                  Traits;                  // offset 16
    // total = 20
};

struct WDF_USB_DEVICE_INFORMATION
    : public EmuStructHelper<WDF_USB_DEVICE_INFORMATION>,
      public WDF_USB_DEVICE_INFORMATION_POD {
    std::string get_mem_tag() const override { return "wdf_usb_device_information"; }
};

// ==========================================================================================================
// WDF_DRIVER_CONFIG: Size(u32)+EvtDriverDeviceAdd(Ptr)+EvtDriverUnload(Ptr)+
//                    DriverInitFlags(u32)+DriverPoolTag(u32)
//   x86: 4+4+4+4+4 = 20
//   x64: 4+pad(4)+8+8+4+4 = 32
// ==========================================================================================================
template <int PtrSize>
struct WDF_DRIVER_CONFIG_POD;

template <>
struct WDF_DRIVER_CONFIG_POD<4> {
    uint32_t Size;                  // offset  0
    uint32_t EvtDriverDeviceAdd;    // offset  4
    uint32_t EvtDriverUnload;       // offset  8
    uint32_t DriverInitFlags;       // offset 12
    uint32_t DriverPoolTag;         // offset 16
    // total = 20
};

template <>
struct WDF_DRIVER_CONFIG_POD<8> {
    uint32_t Size;                  // offset  0
    uint32_t pad;                   // offset  4
    uint64_t EvtDriverDeviceAdd;    // offset  8
    uint64_t EvtDriverUnload;       // offset 16
    uint32_t DriverInitFlags;       // offset 24
    uint32_t DriverPoolTag;         // offset 28
    // total = 32
};

template <int PtrSize>
struct WDF_DRIVER_CONFIG : public EmuStructHelper<WDF_DRIVER_CONFIG<PtrSize>>,
                            public WDF_DRIVER_CONFIG_POD<PtrSize> {
    std::string get_mem_tag() const override { return "wdf_driver_config"; }
};

// ==========================================================================================================
// WDF_COMPONENT_GLOBALS: u8[0x100] = 256 (fixed)
// ==========================================================================================================
struct WDF_COMPONENT_GLOBALS_POD {
    uint8_t Data[0x100] = {};  // offset 0, 256 bytes
};

struct WDF_COMPONENT_GLOBALS
    : public EmuStructHelper<WDF_COMPONENT_GLOBALS>,
      public WDF_COMPONENT_GLOBALS_POD {
    std::string get_mem_tag() const override { return "wdf_component_globals"; }
};

// ==========================================================================================================
// WDF_TYPED_CONTEXT_WORKER: u8[0x100] = 256 (fixed)
// ==========================================================================================================
struct WDF_TYPED_CONTEXT_WORKER_POD {
    uint8_t Data[0x100] = {};  // offset 0, 256 bytes
};

struct WDF_TYPED_CONTEXT_WORKER
    : public EmuStructHelper<WDF_TYPED_CONTEXT_WORKER>,
      public WDF_TYPED_CONTEXT_WORKER_POD {
    std::string get_mem_tag() const override { return "wdf_typed_context_worker"; }
};

// ==========================================================================================================
// WDF_USB_PIPE_INFORMATION: Size(u32)+MaxPacketSize(u32)+EndpointAddress(u8)+Interval(u8)+
//                           SettingIndex(u8)+PipeType(u32)+MaxTransferSize(u32)
//   Natural alignment: 4+4+1+1+1+pad(1)+4+4 = 20
// ==========================================================================================================
struct WDF_USB_PIPE_INFORMATION_POD {
    uint32_t Size;                // offset  0
    uint32_t MaximumPacketSize;   // offset  4
    uint8_t  EndpointAddress;     // offset  8
    uint8_t  Interval;            // offset  9
    uint8_t  SettingIndex;        // offset 10
    uint8_t  pad;                 // offset 11 → align PipeType to 4
    uint32_t PipeType;            // offset 12
    uint32_t MaximumTransferSize; // offset 16
    // total = 20
};

struct WDF_USB_PIPE_INFORMATION
    : public EmuStructHelper<WDF_USB_PIPE_INFORMATION>,
      public WDF_USB_PIPE_INFORMATION_POD {
    std::string get_mem_tag() const override { return "wdf_usb_pipe_information"; }
};

// ==========================================================================================================
// WDF_PNPPOWER_EVENT_CALLBACKS: Size(u32) + 16*Ptr
//   x86: 4 + 16*4 = 68
//   x64: 4+pad(4) + 16*8 = 136
// ==========================================================================================================
template <int PtrSize>
struct WDF_PNPPOWER_EVENT_CALLBACKS_POD;

template <>
struct WDF_PNPPOWER_EVENT_CALLBACKS_POD<4> {
    uint32_t Size;                                    // offset   0
    uint32_t EvtDeviceD0Entry;                        // offset   4
    uint32_t EvtDeviceD0EntryPostInterruptsEnabled;   // offset   8
    uint32_t EvtDeviceD0Exit;                         // offset  12
    uint32_t EvtDeviceD0ExitPreInterruptsDisabled;    // offset  16
    uint32_t EvtDevicePrepareHardware;                // offset  20
    uint32_t EvtDeviceReleaseHardware;                // offset  24
    uint32_t EvtDeviceSelfManagedIoCleanup;           // offset  28
    uint32_t EvtDeviceSelfManagedIoFlush;             // offset  32
    uint32_t EvtDeviceSelfManagedIoInit;              // offset  36
    uint32_t EvtDeviceSelfManagedIoSuspend;           // offset  40
    uint32_t EvtDeviceSelfManagedIoRestart;           // offset  44
    uint32_t EvtDeviceSurpriseRemoval;                // offset  48
    uint32_t EvtDeviceQueryRemove;                    // offset  52
    uint32_t EvtDeviceQueryStop;                      // offset  56
    uint32_t EvtDeviceUsageNotification;              // offset  60
    uint32_t EvtDeviceRelationsQuery;                 // offset  64
    uint32_t EvtDeviceUsageNotificationEx;            // offset  68
    // total = 72
};

template <>
struct WDF_PNPPOWER_EVENT_CALLBACKS_POD<8> {
    uint32_t Size;                                    // offset   0
    uint32_t pad;                                     // offset   4
    uint64_t EvtDeviceD0Entry;                        // offset   8
    uint64_t EvtDeviceD0EntryPostInterruptsEnabled;   // offset  16
    uint64_t EvtDeviceD0Exit;                         // offset  24
    uint64_t EvtDeviceD0ExitPreInterruptsDisabled;    // offset  32
    uint64_t EvtDevicePrepareHardware;                // offset  40
    uint64_t EvtDeviceReleaseHardware;                // offset  48
    uint64_t EvtDeviceSelfManagedIoCleanup;           // offset  56
    uint64_t EvtDeviceSelfManagedIoFlush;             // offset  64
    uint64_t EvtDeviceSelfManagedIoInit;              // offset  72
    uint64_t EvtDeviceSelfManagedIoSuspend;           // offset  80
    uint64_t EvtDeviceSelfManagedIoRestart;           // offset  88
    uint64_t EvtDeviceSurpriseRemoval;                // offset  96
    uint64_t EvtDeviceQueryRemove;                    // offset 104
    uint64_t EvtDeviceQueryStop;                      // offset 112
    uint64_t EvtDeviceUsageNotification;              // offset 120
    uint64_t EvtDeviceRelationsQuery;                 // offset 128
    uint64_t EvtDeviceUsageNotificationEx;            // offset 136
    // total = 144
};

template <int PtrSize>
struct WDF_PNPPOWER_EVENT_CALLBACKS
    : public EmuStructHelper<WDF_PNPPOWER_EVENT_CALLBACKS<PtrSize>>,
      public WDF_PNPPOWER_EVENT_CALLBACKS_POD<PtrSize> {
    std::string get_mem_tag() const override { return "wdf_pnppower_event_callbacks"; }
};

// ==========================================================================================================
// Helper structs for WDF_USB_INTERFACE_SELECT_SETTING_PARAMS union
// ==========================================================================================================
template <int PtrSize>
struct _InterfaceDescriptor_POD;

template <>
struct _InterfaceDescriptor_POD<4> {
    uint32_t InterfaceDescriptor;  // Ptr, offset 0
};

template <>
struct _InterfaceDescriptor_POD<8> {
    uint64_t InterfaceDescriptor;  // Ptr, offset 0
};

template <int PtrSize>
struct _InterfaceDescriptor
    : public EmuStructHelper<_InterfaceDescriptor<PtrSize>>,
      public _InterfaceDescriptor_POD<PtrSize> {
    std::string get_mem_tag() const override { return "interface_descriptor"; }
};

template <int PtrSize>
struct Interface_POD;

template <>
struct Interface_POD<4> {
    uint8_t SettingIndex;  // offset 0
    // total = 1
};

template <>
struct Interface_POD<8> {
    uint8_t SettingIndex;  // offset 0
    // total = 1
};

template <int PtrSize>
struct Interface
    : public EmuStructHelper<Interface<PtrSize>>,
      public Interface_POD<PtrSize> {
    std::string get_mem_tag() const override { return "wdf_interface"; }
};

template <int PtrSize>
struct InterfaceUrb_POD;

template <>
struct InterfaceUrb_POD<4> {
    uint32_t Urb;  // Ptr, offset 0
};

template <>
struct InterfaceUrb_POD<8> {
    uint64_t Urb;  // Ptr, offset 0
};

template <int PtrSize>
struct InterfaceUrb
    : public EmuStructHelper<InterfaceUrb<PtrSize>>,
      public InterfaceUrb_POD<PtrSize> {
    std::string get_mem_tag() const override { return "interface_urb"; }
};

// Union InterfaceTypes: max(sizeof of members)
// x86: max(4, 1, 4) = 4
// x64: max(8, 1, 8) = 8
template <int PtrSize>
struct InterfaceTypes_POD;

template <>
struct InterfaceTypes_POD<4> {
    union {
        _InterfaceDescriptor_POD<4> Descriptor;
        Interface_POD<4>            Interface;
        InterfaceUrb_POD<4>         Urb;
    };
};

template <>
struct InterfaceTypes_POD<8> {
    union {
        _InterfaceDescriptor_POD<8> Descriptor;
        Interface_POD<8>            Interface;
        InterfaceUrb_POD<8>         Urb;
    };
};

// ==========================================================================================================
// WDF_USB_INTERFACE_SELECT_SETTING_PARAMS:
//   Size(u32)+Type(u32)+Types(InterfaceTypes union)
//   x86: 4+4+4 = 12
//   x64: 4+4+8 = 16
// ==========================================================================================================
template <int PtrSize>
struct WDF_USB_INTERFACE_SELECT_SETTING_PARAMS_POD;

template <>
struct WDF_USB_INTERFACE_SELECT_SETTING_PARAMS_POD<4> {
    uint32_t               Size;    // offset 0
    uint32_t               Type;    // offset 4
    InterfaceTypes_POD<4>  Types;   // offset 8 (4 bytes)
    // total = 12
};

template <>
struct WDF_USB_INTERFACE_SELECT_SETTING_PARAMS_POD<8> {
    uint32_t               Size;    // offset 0
    uint32_t               Type;    // offset 4
    InterfaceTypes_POD<8>  Types;   // offset 8 (8 bytes)
    // total = 16
};

template <int PtrSize>
struct WDF_USB_INTERFACE_SELECT_SETTING_PARAMS
    : public EmuStructHelper<WDF_USB_INTERFACE_SELECT_SETTING_PARAMS<PtrSize>>,
      public WDF_USB_INTERFACE_SELECT_SETTING_PARAMS_POD<PtrSize> {
    std::string get_mem_tag() const override { return "wdf_usb_interface_select_setting_params"; }
};

// ==========================================================================================================
// Helper structs for WDF_USB_DEVICE_SELECT_CONFIG_PARAMS union (Types)
// ==========================================================================================================
template <int PtrSize>
struct Descriptor_POD;

template <>
struct Descriptor_POD<4> {
    uint32_t ConfigurationDescriptor;  // offset 0 (Ptr)
    uint32_t InterfaceDescriptors;     // offset 4 (Ptr)
    uint32_t NumInterfaceDescriptors;  // offset 8 (u32)
    // total = 12
};

template <>
struct Descriptor_POD<8> {
    uint64_t ConfigurationDescriptor;  // offset 0 (Ptr)
    uint64_t InterfaceDescriptors;     // offset 8 (Ptr)
    uint32_t NumInterfaceDescriptors;  // offset 16 (u32)
    uint32_t pad;                      // offset 20
    // total = 24
};

template <int PtrSize>
struct Descriptor
    : public EmuStructHelper<Descriptor<PtrSize>>,
      public Descriptor_POD<PtrSize> {
    std::string get_mem_tag() const override { return "descriptor"; }
};

template <int PtrSize>
struct UrbConfig_POD;

template <>
struct UrbConfig_POD<4> {
    uint32_t Urb;  // offset 0 (Ptr)
    // total = 4
};

template <>
struct UrbConfig_POD<8> {
    uint64_t Urb;  // offset 0 (Ptr)
    // total = 8
};

template <int PtrSize>
struct Urb
    : public EmuStructHelper<Urb<PtrSize>>,
      public UrbConfig_POD<PtrSize> {
    std::string get_mem_tag() const override { return "urb"; }
};

template <int PtrSize>
struct SingleInterface_POD;

template <>
struct SingleInterface_POD<4> {
    uint8_t  NumberConfiguredPipes;  // offset 0
    uint8_t  pad[3];                 // offset 1 → align Ptr
    uint32_t ConfiguredUsbInterface; // offset 4 (Ptr)
    // total = 8
};

template <>
struct SingleInterface_POD<8> {
    uint8_t  NumberConfiguredPipes;  // offset 0
    uint8_t  pad[7];                 // offset 1 → align Ptr
    uint64_t ConfiguredUsbInterface; // offset 8 (Ptr)
    // total = 16
};

template <int PtrSize>
struct SingleInterface
    : public EmuStructHelper<SingleInterface<PtrSize>>,
      public SingleInterface_POD<PtrSize> {
    std::string get_mem_tag() const override { return "single_interface"; }
};

template <int PtrSize>
struct MultiInterface_POD;

template <>
struct MultiInterface_POD<4> {
    uint8_t  NumberInterfaces;               // offset 0
    uint8_t  pad[3];                         // offset 1 → align Ptr
    uint32_t Pairs;                          // offset 4 (Ptr)
    uint8_t  NumberOfConfiguredInterfaces;   // offset 8
    uint8_t  pad2[3];                        // offset 9 → natural alignment
    // total = 12
};

template <>
struct MultiInterface_POD<8> {
    uint8_t  NumberInterfaces;               // offset 0
    uint8_t  pad[7];                         // offset 1 → align Ptr
    uint64_t Pairs;                          // offset 8 (Ptr)
    uint8_t  NumberOfConfiguredInterfaces;   // offset 16
    uint8_t  pad2[7];                        // offset 17 → natural alignment to 8
    // total = 24
};

template <int PtrSize>
struct MultiInterface
    : public EmuStructHelper<MultiInterface<PtrSize>>,
      public MultiInterface_POD<PtrSize> {
    std::string get_mem_tag() const override { return "multi_interface"; }
};

// Union Types: max(sizeof)
// x86: max(12, 4, 8, 12) = 12
// x64: max(24, 8, 16, 24) = 24
template <int PtrSize>
struct Types_POD;

template <>
struct Types_POD<4> {
    union {
        Descriptor_POD<4>      Descriptor;
        UrbConfig_POD<4>       Urb;
        SingleInterface_POD<4> SingleInterface;
        MultiInterface_POD<4>  MultiInterface;
    };
};

template <>
struct Types_POD<8> {
    union {
        Descriptor_POD<8>      Descriptor;
        UrbConfig_POD<8>       Urb;
        SingleInterface_POD<8> SingleInterface;
        MultiInterface_POD<8>  MultiInterface;
    };
};

// ==========================================================================================================
// WDF_USB_DEVICE_SELECT_CONFIG_PARAMS:
//   Size(u32)+Type(u32)+Types(union)
//   x86: 4+4+12 = 20
//   x64: 4+4+24 = 32
// ==========================================================================================================
template <int PtrSize>
struct WDF_USB_DEVICE_SELECT_CONFIG_PARAMS_POD;

template <>
struct WDF_USB_DEVICE_SELECT_CONFIG_PARAMS_POD<4> {
    uint32_t          Size;    // offset 0
    uint32_t          Type;    // offset 4
    Types_POD<4>      Types;   // offset 8 (12 bytes)
    // total = 20
};

template <>
struct WDF_USB_DEVICE_SELECT_CONFIG_PARAMS_POD<8> {
    uint32_t          Size;    // offset 0
    uint32_t          Type;    // offset 4
    Types_POD<8>      Types;   // offset 8 (24 bytes)
    // total = 32
};

template <int PtrSize>
struct WDF_USB_DEVICE_SELECT_CONFIG_PARAMS
    : public EmuStructHelper<WDF_USB_DEVICE_SELECT_CONFIG_PARAMS<PtrSize>>,
      public WDF_USB_DEVICE_SELECT_CONFIG_PARAMS_POD<PtrSize> {
    std::string get_mem_tag() const override { return "wdf_usb_device_select_config_params"; }
};

// ==========================================================================================================
// WDF_IO_QUEUE_CONFIG:
//   Size(u32)+DispatchType(Ptr)+PowerManaged(Ptr)+AllowZeroLengthRequests(u8)+DefaultQueue(u8)+
//   7*Ptr+NumberOfPresentedRequests(u32)+Driver(Ptr)
//   x86: 4+4+4+1+1+pad(2)+7*4(28)+4+4 = 52
//   x64: 4+pad(4)+8+8+1+1+pad(6)+7*8(56)+4+pad(4)+8 = 104
// ==========================================================================================================
template <int PtrSize>
struct WDF_IO_QUEUE_CONFIG_POD;

template <>
struct WDF_IO_QUEUE_CONFIG_POD<4> {
    uint32_t Size;                           // offset  0
    uint32_t DispatchType;                   // offset  4
    uint32_t PowerManaged;                   // offset  8
    uint8_t  AllowZeroLengthRequests;        // offset 12
    uint8_t  DefaultQueue;                   // offset 13
    uint8_t  pad1[2];                        // offset 14
    uint32_t EvtIoDefault;                   // offset 16
    uint32_t EvtIoRead;                      // offset 20
    uint32_t EvtIoWrite;                     // offset 24
    uint32_t EvtIoDeviceControl;             // offset 28
    uint32_t EvtIoInternalDeviceControl;     // offset 32
    uint32_t EvtIoStop;                      // offset 36
    uint32_t EvtIoResume;                    // offset 40
    uint32_t EvtIoCanceledOnQueue;           // offset 44
    uint32_t NumberOfPresentedRequests;      // offset 48
    uint32_t Driver;                         // offset 52
    // total = 56
};

template <>
struct WDF_IO_QUEUE_CONFIG_POD<8> {
    uint32_t Size;                           // offset   0
    uint32_t pad1;                           // offset   4
    uint64_t DispatchType;                   // offset   8
    uint64_t PowerManaged;                   // offset  16
    uint8_t  AllowZeroLengthRequests;        // offset  24
    uint8_t  DefaultQueue;                   // offset  25
    uint8_t  pad2[6];                        // offset  26
    uint64_t EvtIoDefault;                   // offset  32
    uint64_t EvtIoRead;                      // offset  40
    uint64_t EvtIoWrite;                     // offset  48
    uint64_t EvtIoDeviceControl;             // offset  56
    uint64_t EvtIoInternalDeviceControl;     // offset  64
    uint64_t EvtIoStop;                      // offset  72
    uint64_t EvtIoResume;                    // offset  80
    uint64_t EvtIoCanceledOnQueue;           // offset  88
    uint32_t NumberOfPresentedRequests;      // offset  96
    uint32_t pad3;                           // offset 100
    uint64_t Driver;                         // offset 104
    // total = 112
};

template <int PtrSize>
struct WDF_IO_QUEUE_CONFIG : public EmuStructHelper<WDF_IO_QUEUE_CONFIG<PtrSize>>,
                              public WDF_IO_QUEUE_CONFIG_POD<PtrSize> {
    std::string get_mem_tag() const override { return "wdf_io_queue_config"; }
};

// ==========================================================================================================
// WDFFUNCTIONS: Large function pointer table (vtable-like)
//   Total of 422 function pointer slots
//   x86: 422*4 = 1688 bytes
//   x64: 422*8 = 3376 bytes
// ==========================================================================================================
template <int PtrSize>
struct WDFFUNCTIONS_POD;

template <>
struct WDFFUNCTIONS_POD<4> {
    uint32_t pfnWdfChildListCreate = 0;   // offset 0
    uint32_t pfnWdfChildListGetDevice = 0;   // offset 4
    uint32_t pfnWdfChildListRetrievePdo = 0;   // offset 8
    uint32_t pfnWdfChildListRetrieveAddressDescription = 0;   // offset 12
    uint32_t pfnWdfChildListBeginScan = 0;   // offset 16
    uint32_t pfnWdfChildListEndScan = 0;   // offset 20
    uint32_t pfnWdfChildListBeginIteration = 0;   // offset 24
    uint32_t pfnWdfChildListRetrieveNextDevice = 0;   // offset 28
    uint32_t pfnWdfChildListEndIteration = 0;   // offset 32
    uint32_t pfnWdfChildListAddOrUpdateChildDescriptionAsPresent = 0;   // offset 36
    uint32_t pfnWdfChildListUpdateChildDescriptionAsMissing = 0;   // offset 40
    uint32_t pfnWdfChildListUpdateAllChildDescriptionsAsPresent = 0;   // offset 44
    uint32_t pfnWdfChildListRequestChildEject = 0;   // offset 48
    uint32_t pfnWdfCollectionCreate = 0;   // offset 52
    uint32_t pfnWdfCollectionGetCount = 0;   // offset 56
    uint32_t pfnWdfCollectionAdd = 0;   // offset 60
    uint32_t pfnWdfCollectionRemove = 0;   // offset 64
    uint32_t pfnWdfCollectionRemoveItem = 0;   // offset 68
    uint32_t pfnWdfCollectionGetItem = 0;   // offset 72
    uint32_t pfnWdfCollectionGetFirstItem = 0;   // offset 76
    uint32_t pfnWdfCollectionGetLastItem = 0;   // offset 80
    uint32_t pfnWdfCommonBufferCreate = 0;   // offset 84
    uint32_t pfnWdfCommonBufferGetAlignedVirtualAddress = 0;   // offset 88
    uint32_t pfnWdfCommonBufferGetAlignedLogicalAddress = 0;   // offset 92
    uint32_t pfnWdfCommonBufferGetLength = 0;   // offset 96
    uint32_t pfnWdfControlDeviceInitAllocate = 0;   // offset 100
    uint32_t pfnWdfControlDeviceInitSetShutdownNotification = 0;   // offset 104
    uint32_t pfnWdfControlFinishInitializing = 0;   // offset 108
    uint32_t pfnWdfDeviceGetDeviceState = 0;   // offset 112
    uint32_t pfnWdfDeviceSetDeviceState = 0;   // offset 116
    uint32_t pfnWdfWdmDeviceGetWdfDeviceHandle = 0;   // offset 120
    uint32_t pfnWdfDeviceWdmGetDeviceObject = 0;   // offset 124
    uint32_t pfnWdfDeviceWdmGetAttachedDevice = 0;   // offset 128
    uint32_t pfnWdfDeviceWdmGetPhysicalDevice = 0;   // offset 132
    uint32_t pfnWdfDeviceWdmDispatchPreprocessedIrp = 0;   // offset 136
    uint32_t pfnWdfDeviceAddDependentUsageDeviceObject = 0;   // offset 140
    uint32_t pfnWdfDeviceAddRemovalRelationsPhysicalDevice = 0;   // offset 144
    uint32_t pfnWdfDeviceRemoveRemovalRelationsPhysicalDevice = 0;   // offset 148
    uint32_t pfnWdfDeviceClearRemovalRelationsDevices = 0;   // offset 152
    uint32_t pfnWdfDeviceGetDriver = 0;   // offset 156
    uint32_t pfnWdfDeviceRetrieveDeviceName = 0;   // offset 160
    uint32_t pfnWdfDeviceAssignMofResourceName = 0;   // offset 164
    uint32_t pfnWdfDeviceGetIoTarget = 0;   // offset 168
    uint32_t pfnWdfDeviceGetDevicePnpState = 0;   // offset 172
    uint32_t pfnWdfDeviceGetDevicePowerState = 0;   // offset 176
    uint32_t pfnWdfDeviceGetDevicePowerPolicyState = 0;   // offset 180
    uint32_t pfnWdfDeviceAssignS0IdleSettings = 0;   // offset 184
    uint32_t pfnWdfDeviceAssignSxWakeSettings = 0;   // offset 188
    uint32_t pfnWdfDeviceOpenRegistryKey = 0;   // offset 192
    uint32_t pfnWdfDeviceSetSpecialFileSupport = 0;   // offset 196
    uint32_t pfnWdfDeviceSetCharacteristics = 0;   // offset 200
    uint32_t pfnWdfDeviceGetCharacteristics = 0;   // offset 204
    uint32_t pfnWdfDeviceGetAlignmentRequirement = 0;   // offset 208
    uint32_t pfnWdfDeviceSetAlignmentRequirement = 0;   // offset 212
    uint32_t pfnWdfDeviceInitFree = 0;   // offset 216
    uint32_t pfnWdfDeviceInitSetPnpPowerEventCallbacks = 0;   // offset 220
    uint32_t pfnWdfDeviceInitSetPowerPolicyEventCallbacks = 0;   // offset 224
    uint32_t pfnWdfDeviceInitSetPowerPolicyOwnership = 0;   // offset 228
    uint32_t pfnWdfDeviceInitRegisterPnpStateChangeCallback = 0;   // offset 232
    uint32_t pfnWdfDeviceInitRegisterPowerStateChangeCallback = 0;   // offset 236
    uint32_t pfnWdfDeviceInitRegisterPowerPolicyStateChangeCallback = 0;   // offset 240
    uint32_t pfnWdfDeviceInitSetIoType = 0;   // offset 244
    uint32_t pfnWdfDeviceInitSetExclusive = 0;   // offset 248
    uint32_t pfnWdfDeviceInitSetPowerNotPageable = 0;   // offset 252
    uint32_t pfnWdfDeviceInitSetPowerPageable = 0;   // offset 256
    uint32_t pfnWdfDeviceInitSetPowerInrush = 0;   // offset 260
    uint32_t pfnWdfDeviceInitSetDeviceType = 0;   // offset 264
    uint32_t pfnWdfDeviceInitAssignName = 0;   // offset 268
    uint32_t pfnWdfDeviceInitAssignSDDLString = 0;   // offset 272
    uint32_t pfnWdfDeviceInitSetDeviceClass = 0;   // offset 276
    uint32_t pfnWdfDeviceInitSetCharacteristics = 0;   // offset 280
    uint32_t pfnWdfDeviceInitSetFileObjectConfig = 0;   // offset 284
    uint32_t pfnWdfDeviceInitSetRequestAttributes = 0;   // offset 288
    uint32_t pfnWdfDeviceInitAssignWdmIrpPreprocessCallback = 0;   // offset 292
    uint32_t pfnWdfDeviceInitSetIoInCallerContextCallback = 0;   // offset 296
    uint32_t pfnWdfDeviceCreate = 0;   // offset 300
    uint32_t pfnWdfDeviceSetStaticStopRemove = 0;   // offset 304
    uint32_t pfnWdfDeviceCreateDeviceInterface = 0;   // offset 308
    uint32_t pfnWdfDeviceSetDeviceInterfaceState = 0;   // offset 312
    uint32_t pfnWdfDeviceRetrieveDeviceInterfaceString = 0;   // offset 316
    uint32_t pfnWdfDeviceCreateSymbolicLink = 0;   // offset 320
    uint32_t pfnWdfDeviceQueryProperty = 0;   // offset 324
    uint32_t pfnWdfDeviceAllocAndQueryProperty = 0;   // offset 328
    uint32_t pfnWdfDeviceSetPnpCapabilities = 0;   // offset 332
    uint32_t pfnWdfDeviceSetPowerCapabilities = 0;   // offset 336
    uint32_t pfnWdfDeviceSetBusInformationForChildren = 0;   // offset 340
    uint32_t pfnWdfDeviceIndicateWakeStatus = 0;   // offset 344
    uint32_t pfnWdfDeviceSetFailed = 0;   // offset 348
    uint32_t pfnWdfDeviceStopIdleNoTrack = 0;   // offset 352
    uint32_t pfnWdfDeviceResumeIdleNoTrack = 0;   // offset 356
    uint32_t pfnWdfDeviceGetFileObject = 0;   // offset 360
    uint32_t pfnWdfDeviceEnqueueRequest = 0;   // offset 364
    uint32_t pfnWdfDeviceGetDefaultQueue = 0;   // offset 368
    uint32_t pfnWdfDeviceConfigureRequestDispatching = 0;   // offset 372
    uint32_t pfnWdfDmaEnablerCreate = 0;   // offset 376
    uint32_t pfnWdfDmaEnablerGetMaximumLength = 0;   // offset 380
    uint32_t pfnWdfDmaEnablerGetMaximumScatterGatherElements = 0;   // offset 384
    uint32_t pfnWdfDmaEnablerSetMaximumScatterGatherElements = 0;   // offset 388
    uint32_t pfnWdfDmaTransactionCreate = 0;   // offset 392
    uint32_t pfnWdfDmaTransactionInitialize = 0;   // offset 396
    uint32_t pfnWdfDmaTransactionInitializeUsingRequest = 0;   // offset 400
    uint32_t pfnWdfDmaTransactionExecute = 0;   // offset 404
    uint32_t pfnWdfDmaTransactionRelease = 0;   // offset 408
    uint32_t pfnWdfDmaTransactionDmaCompleted = 0;   // offset 412
    uint32_t pfnWdfDmaTransactionDmaCompletedWithLength = 0;   // offset 416
    uint32_t pfnWdfDmaTransactionDmaCompletedFinal = 0;   // offset 420
    uint32_t pfnWdfDmaTransactionGetBytesTransferred = 0;   // offset 424
    uint32_t pfnWdfDmaTransactionSetMaximumLength = 0;   // offset 428
    uint32_t pfnWdfDmaTransactionGetRequest = 0;   // offset 432
    uint32_t pfnWdfDmaTransactionGetCurrentDmaTransferLength = 0;   // offset 436
    uint32_t pfnWdfDmaTransactionGetDevice = 0;   // offset 440
    uint32_t pfnWdfDpcCreate = 0;   // offset 444
    uint32_t pfnWdfDpcEnqueue = 0;   // offset 448
    uint32_t pfnWdfDpcCancel = 0;   // offset 452
    uint32_t pfnWdfDpcGetParentObject = 0;   // offset 456
    uint32_t pfnWdfDpcWdmGetDpc = 0;   // offset 460
    uint32_t pfnWdfDriverCreate = 0;   // offset 464
    uint32_t pfnWdfDriverGetRegistryPath = 0;   // offset 468
    uint32_t pfnWdfDriverWdmGetDriverObject = 0;   // offset 472
    uint32_t pfnWdfDriverOpenParametersRegistryKey = 0;   // offset 476
    uint32_t pfnWdfWdmDriverGetWdfDriverHandle = 0;   // offset 480
    uint32_t pfnWdfDriverRegisterTraceInfo = 0;   // offset 484
    uint32_t pfnWdfDriverRetrieveVersionString = 0;   // offset 488
    uint32_t pfnWdfDriverIsVersionAvailable = 0;   // offset 492
    uint32_t pfnWdfFdoInitWdmGetPhysicalDevice = 0;   // offset 496
    uint32_t pfnWdfFdoInitOpenRegistryKey = 0;   // offset 500
    uint32_t pfnWdfFdoInitQueryProperty = 0;   // offset 504
    uint32_t pfnWdfFdoInitAllocAndQueryProperty = 0;   // offset 508
    uint32_t pfnWdfFdoInitSetEventCallbacks = 0;   // offset 512
    uint32_t pfnWdfFdoInitSetFilter = 0;   // offset 516
    uint32_t pfnWdfFdoInitSetDefaultChildListConfig = 0;   // offset 520
    uint32_t pfnWdfFdoQueryForInterface = 0;   // offset 524
    uint32_t pfnWdfFdoGetDefaultChildList = 0;   // offset 528
    uint32_t pfnWdfFdoAddStaticChild = 0;   // offset 532
    uint32_t pfnWdfFdoLockStaticChildListForIteration = 0;   // offset 536
    uint32_t pfnWdfFdoRetrieveNextStaticChild = 0;   // offset 540
    uint32_t pfnWdfFdoUnlockStaticChildListFromIteration = 0;   // offset 544
    uint32_t pfnWdfFileObjectGetFileName = 0;   // offset 548
    uint32_t pfnWdfFileObjectGetFlags = 0;   // offset 552
    uint32_t pfnWdfFileObjectGetDevice = 0;   // offset 556
    uint32_t pfnWdfFileObjectWdmGetFileObject = 0;   // offset 560
    uint32_t pfnWdfInterruptCreate = 0;   // offset 564
    uint32_t pfnWdfInterruptQueueDpcForIsr = 0;   // offset 568
    uint32_t pfnWdfInterruptSynchronize = 0;   // offset 572
    uint32_t pfnWdfInterruptAcquireLock = 0;   // offset 576
    uint32_t pfnWdfInterruptReleaseLock = 0;   // offset 580
    uint32_t pfnWdfInterruptEnable = 0;   // offset 584
    uint32_t pfnWdfInterruptDisable = 0;   // offset 588
    uint32_t pfnWdfInterruptWdmGetInterrupt = 0;   // offset 592
    uint32_t pfnWdfInterruptGetInfo = 0;   // offset 596
    uint32_t pfnWdfInterruptSetPolicy = 0;   // offset 600
    uint32_t pfnWdfInterruptGetDevice = 0;   // offset 604
    uint32_t pfnWdfIoQueueCreate = 0;   // offset 608
    uint32_t pfnWdfIoQueueGetState = 0;   // offset 612
    uint32_t pfnWdfIoQueueStart = 0;   // offset 616
    uint32_t pfnWdfIoQueueStop = 0;   // offset 620
    uint32_t pfnWdfIoQueueStopSynchronously = 0;   // offset 624
    uint32_t pfnWdfIoQueueGetDevice = 0;   // offset 628
    uint32_t pfnWdfIoQueueRetrieveNextRequest = 0;   // offset 632
    uint32_t pfnWdfIoQueueRetrieveRequestByFileObject = 0;   // offset 636
    uint32_t pfnWdfIoQueueFindRequest = 0;   // offset 640
    uint32_t pfnWdfIoQueueRetrieveFoundRequest = 0;   // offset 644
    uint32_t pfnWdfIoQueueDrainSynchronously = 0;   // offset 648
    uint32_t pfnWdfIoQueueDrain = 0;   // offset 652
    uint32_t pfnWdfIoQueuePurgeSynchronously = 0;   // offset 656
    uint32_t pfnWdfIoQueuePurge = 0;   // offset 660
    uint32_t pfnWdfIoQueueReadyNotify = 0;   // offset 664
    uint32_t pfnWdfIoTargetCreate = 0;   // offset 668
    uint32_t pfnWdfIoTargetOpen = 0;   // offset 672
    uint32_t pfnWdfIoTargetCloseForQueryRemove = 0;   // offset 676
    uint32_t pfnWdfIoTargetClose = 0;   // offset 680
    uint32_t pfnWdfIoTargetStart = 0;   // offset 684
    uint32_t pfnWdfIoTargetStop = 0;   // offset 688
    uint32_t pfnWdfIoTargetGetState = 0;   // offset 692
    uint32_t pfnWdfIoTargetGetDevice = 0;   // offset 696
    uint32_t pfnWdfIoTargetQueryTargetProperty = 0;   // offset 700
    uint32_t pfnWdfIoTargetAllocAndQueryTargetProperty = 0;   // offset 704
    uint32_t pfnWdfIoTargetQueryForInterface = 0;   // offset 708
    uint32_t pfnWdfIoTargetWdmGetTargetDeviceObject = 0;   // offset 712
    uint32_t pfnWdfIoTargetWdmGetTargetPhysicalDevice = 0;   // offset 716
    uint32_t pfnWdfIoTargetWdmGetTargetFileObject = 0;   // offset 720
    uint32_t pfnWdfIoTargetWdmGetTargetFileHandle = 0;   // offset 724
    uint32_t pfnWdfIoTargetSendReadSynchronously = 0;   // offset 728
    uint32_t pfnWdfIoTargetFormatRequestForRead = 0;   // offset 732
    uint32_t pfnWdfIoTargetSendWriteSynchronously = 0;   // offset 736
    uint32_t pfnWdfIoTargetFormatRequestForWrite = 0;   // offset 740
    uint32_t pfnWdfIoTargetSendIoctlSynchronously = 0;   // offset 744
    uint32_t pfnWdfIoTargetFormatRequestForIoctl = 0;   // offset 748
    uint32_t pfnWdfIoTargetSendInternalIoctlSynchronously = 0;   // offset 752
    uint32_t pfnWdfIoTargetFormatRequestForInternalIoctl = 0;   // offset 756
    uint32_t pfnWdfIoTargetSendInternalIoctlOthersSynchronously = 0;   // offset 760
    uint32_t pfnWdfIoTargetFormatRequestForInternalIoctlOthers = 0;   // offset 764
    uint32_t pfnWdfMemoryCreate = 0;   // offset 768
    uint32_t pfnWdfMemoryCreatePreallocated = 0;   // offset 772
    uint32_t pfnWdfMemoryGetBuffer = 0;   // offset 776
    uint32_t pfnWdfMemoryAssignBuffer = 0;   // offset 780
    uint32_t pfnWdfMemoryCopyToBuffer = 0;   // offset 784
    uint32_t pfnWdfMemoryCopyFromBuffer = 0;   // offset 788
    uint32_t pfnWdfLookasideListCreate = 0;   // offset 792
    uint32_t pfnWdfMemoryCreateFromLookaside = 0;   // offset 796
    uint32_t pfnWdfDeviceMiniportCreate = 0;   // offset 800
    uint32_t pfnWdfDriverMiniportUnload = 0;   // offset 804
    uint32_t pfnWdfObjectGetTypedContextWorker = 0;   // offset 808
    uint32_t pfnWdfObjectAllocateContext = 0;   // offset 812
    uint32_t pfnWdfObjectContextGetObject = 0;   // offset 816
    uint32_t pfnWdfObjectReferenceActual = 0;   // offset 820
    uint32_t pfnWdfObjectDereferenceActual = 0;   // offset 824
    uint32_t pfnWdfObjectCreate = 0;   // offset 828
    uint32_t pfnWdfObjectDelete = 0;   // offset 832
    uint32_t pfnWdfObjectQuery = 0;   // offset 836
    uint32_t pfnWdfPdoInitAllocate = 0;   // offset 840
    uint32_t pfnWdfPdoInitSetEventCallbacks = 0;   // offset 844
    uint32_t pfnWdfPdoInitAssignDeviceID = 0;   // offset 848
    uint32_t pfnWdfPdoInitAssignInstanceID = 0;   // offset 852
    uint32_t pfnWdfPdoInitAddHardwareID = 0;   // offset 856
    uint32_t pfnWdfPdoInitAddCompatibleID = 0;   // offset 860
    uint32_t pfnWdfPdoInitAddDeviceText = 0;   // offset 864
    uint32_t pfnWdfPdoInitSetDefaultLocale = 0;   // offset 868
    uint32_t pfnWdfPdoInitAssignRawDevice = 0;   // offset 872
    uint32_t pfnWdfPdoMarkMissing = 0;   // offset 876
    uint32_t pfnWdfPdoRequestEject = 0;   // offset 880
    uint32_t pfnWdfPdoGetParent = 0;   // offset 884
    uint32_t pfnWdfPdoRetrieveIdentificationDescription = 0;   // offset 888
    uint32_t pfnWdfPdoRetrieveAddressDescription = 0;   // offset 892
    uint32_t pfnWdfPdoUpdateAddressDescription = 0;   // offset 896
    uint32_t pfnWdfPdoAddEjectionRelationsPhysicalDevice = 0;   // offset 900
    uint32_t pfnWdfPdoRemoveEjectionRelationsPhysicalDevice = 0;   // offset 904
    uint32_t pfnWdfPdoClearEjectionRelationsDevices = 0;   // offset 908
    uint32_t pfnWdfDeviceAddQueryInterface = 0;   // offset 912
    uint32_t pfnWdfRegistryOpenKey = 0;   // offset 916
    uint32_t pfnWdfRegistryCreateKey = 0;   // offset 920
    uint32_t pfnWdfRegistryClose = 0;   // offset 924
    uint32_t pfnWdfRegistryWdmGetHandle = 0;   // offset 928
    uint32_t pfnWdfRegistryRemoveKey = 0;   // offset 932
    uint32_t pfnWdfRegistryRemoveValue = 0;   // offset 936
    uint32_t pfnWdfRegistryQueryValue = 0;   // offset 940
    uint32_t pfnWdfRegistryQueryMemory = 0;   // offset 944
    uint32_t pfnWdfRegistryQueryMultiString = 0;   // offset 948
    uint32_t pfnWdfRegistryQueryUnicodeString = 0;   // offset 952
    uint32_t pfnWdfRegistryQueryString = 0;   // offset 956
    uint32_t pfnWdfRegistryQueryULong = 0;   // offset 960
    uint32_t pfnWdfRegistryAssignValue = 0;   // offset 964
    uint32_t pfnWdfRegistryAssignMemory = 0;   // offset 968
    uint32_t pfnWdfRegistryAssignMultiString = 0;   // offset 972
    uint32_t pfnWdfRegistryAssignUnicodeString = 0;   // offset 976
    uint32_t pfnWdfRegistryAssignString = 0;   // offset 980
    uint32_t pfnWdfRegistryAssignULong = 0;   // offset 984
    uint32_t pfnWdfRequestCreate = 0;   // offset 988
    uint32_t pfnWdfRequestCreateFromIrp = 0;   // offset 992
    uint32_t pfnWdfRequestReuse = 0;   // offset 996
    uint32_t pfnWdfRequestChangeTarget = 0;   // offset 1000
    uint32_t pfnWdfRequestFormatRequestUsingCurrentType = 0;   // offset 1004
    uint32_t pfnWdfRequestWdmFormatUsingStackLocation = 0;   // offset 1008
    uint32_t pfnWdfRequestSend = 0;   // offset 1012
    uint32_t pfnWdfRequestGetStatus = 0;   // offset 1016
    uint32_t pfnWdfRequestMarkCancelable = 0;   // offset 1020
    uint32_t pfnWdfRequestUnmarkCancelable = 0;   // offset 1024
    uint32_t pfnWdfRequestIsCanceled = 0;   // offset 1028
    uint32_t pfnWdfRequestCancelSentRequest = 0;   // offset 1032
    uint32_t pfnWdfRequestIsFrom32BitProcess = 0;   // offset 1036
    uint32_t pfnWdfRequestSetCompletionRoutine = 0;   // offset 1040
    uint32_t pfnWdfRequestGetCompletionParams = 0;   // offset 1044
    uint32_t pfnWdfRequestAllocateTimer = 0;   // offset 1048
    uint32_t pfnWdfRequestComplete = 0;   // offset 1052
    uint32_t pfnWdfRequestCompleteWithPriorityBoost = 0;   // offset 1056
    uint32_t pfnWdfRequestCompleteWithInformation = 0;   // offset 1060
    uint32_t pfnWdfRequestGetParameters = 0;   // offset 1064
    uint32_t pfnWdfRequestRetrieveInputMemory = 0;   // offset 1068
    uint32_t pfnWdfRequestRetrieveOutputMemory = 0;   // offset 1072
    uint32_t pfnWdfRequestRetrieveInputBuffer = 0;   // offset 1076
    uint32_t pfnWdfRequestRetrieveOutputBuffer = 0;   // offset 1080
    uint32_t pfnWdfRequestRetrieveInputWdmMdl = 0;   // offset 1084
    uint32_t pfnWdfRequestRetrieveOutputWdmMdl = 0;   // offset 1088
    uint32_t pfnWdfRequestRetrieveUnsafeUserInputBuffer = 0;   // offset 1092
    uint32_t pfnWdfRequestRetrieveUnsafeUserOutputBuffer = 0;   // offset 1096
    uint32_t pfnWdfRequestSetInformation = 0;   // offset 1100
    uint32_t pfnWdfRequestGetInformation = 0;   // offset 1104
    uint32_t pfnWdfRequestGetFileObject = 0;   // offset 1108
    uint32_t pfnWdfRequestProbeAndLockUserBufferForRead = 0;   // offset 1112
    uint32_t pfnWdfRequestProbeAndLockUserBufferForWrite = 0;   // offset 1116
    uint32_t pfnWdfRequestGetRequestorMode = 0;   // offset 1120
    uint32_t pfnWdfRequestForwardToIoQueue = 0;   // offset 1124
    uint32_t pfnWdfRequestGetIoQueue = 0;   // offset 1128
    uint32_t pfnWdfRequestRequeue = 0;   // offset 1132
    uint32_t pfnWdfRequestStopAcknowledge = 0;   // offset 1136
    uint32_t pfnWdfRequestWdmGetIrp = 0;   // offset 1140
    uint32_t pfnWdfIoResourceRequirementsListSetSlotNumber = 0;   // offset 1144
    uint32_t pfnWdfIoResourceRequirementsListSetInterfaceType = 0;   // offset 1148
    uint32_t pfnWdfIoResourceRequirementsListAppendIoResList = 0;   // offset 1152
    uint32_t pfnWdfIoResourceRequirementsListInsertIoResList = 0;   // offset 1156
    uint32_t pfnWdfIoResourceRequirementsListGetCount = 0;   // offset 1160
    uint32_t pfnWdfIoResourceRequirementsListGetIoResList = 0;   // offset 1164
    uint32_t pfnWdfIoResourceRequirementsListRemove = 0;   // offset 1168
    uint32_t pfnWdfIoResourceRequirementsListRemoveByIoResList = 0;   // offset 1172
    uint32_t pfnWdfIoResourceListCreate = 0;   // offset 1176
    uint32_t pfnWdfIoResourceListAppendDescriptor = 0;   // offset 1180
    uint32_t pfnWdfIoResourceListInsertDescriptor = 0;   // offset 1184
    uint32_t pfnWdfIoResourceListUpdateDescriptor = 0;   // offset 1188
    uint32_t pfnWdfIoResourceListGetCount = 0;   // offset 1192
    uint32_t pfnWdfIoResourceListGetDescriptor = 0;   // offset 1196
    uint32_t pfnWdfIoResourceListRemove = 0;   // offset 1200
    uint32_t pfnWdfIoResourceListRemoveByDescriptor = 0;   // offset 1204
    uint32_t pfnWdfCmResourceListAppendDescriptor = 0;   // offset 1208
    uint32_t pfnWdfCmResourceListInsertDescriptor = 0;   // offset 1212
    uint32_t pfnWdfCmResourceListGetCount = 0;   // offset 1216
    uint32_t pfnWdfCmResourceListGetDescriptor = 0;   // offset 1220
    uint32_t pfnWdfCmResourceListRemove = 0;   // offset 1224
    uint32_t pfnWdfCmResourceListRemoveByDescriptor = 0;   // offset 1228
    uint32_t pfnWdfStringCreate = 0;   // offset 1232
    uint32_t pfnWdfStringGetUnicodeString = 0;   // offset 1236
    uint32_t pfnWdfObjectAcquireLock = 0;   // offset 1240
    uint32_t pfnWdfObjectReleaseLock = 0;   // offset 1244
    uint32_t pfnWdfWaitLockCreate = 0;   // offset 1248
    uint32_t pfnWdfWaitLockAcquire = 0;   // offset 1252
    uint32_t pfnWdfWaitLockRelease = 0;   // offset 1256
    uint32_t pfnWdfSpinLockCreate = 0;   // offset 1260
    uint32_t pfnWdfSpinLockAcquire = 0;   // offset 1264
    uint32_t pfnWdfSpinLockRelease = 0;   // offset 1268
    uint32_t pfnWdfTimerCreate = 0;   // offset 1272
    uint32_t pfnWdfTimerStart = 0;   // offset 1276
    uint32_t pfnWdfTimerStop = 0;   // offset 1280
    uint32_t pfnWdfTimerGetParentObject = 0;   // offset 1284
    uint32_t pfnWdfUsbTargetDeviceCreate = 0;   // offset 1288
    uint32_t pfnWdfUsbTargetDeviceRetrieveInformation = 0;   // offset 1292
    uint32_t pfnWdfUsbTargetDeviceGetDeviceDescriptor = 0;   // offset 1296
    uint32_t pfnWdfUsbTargetDeviceRetrieveConfigDescriptor = 0;   // offset 1300
    uint32_t pfnWdfUsbTargetDeviceQueryString = 0;   // offset 1304
    uint32_t pfnWdfUsbTargetDeviceAllocAndQueryString = 0;   // offset 1308
    uint32_t pfnWdfUsbTargetDeviceFormatRequestForString = 0;   // offset 1312
    uint32_t pfnWdfUsbTargetDeviceGetNumInterfaces = 0;   // offset 1316
    uint32_t pfnWdfUsbTargetDeviceSelectConfig = 0;   // offset 1320
    uint32_t pfnWdfUsbTargetDeviceWdmGetConfigurationHandle = 0;   // offset 1324
    uint32_t pfnWdfUsbTargetDeviceRetrieveCurrentFrameNumber = 0;   // offset 1328
    uint32_t pfnWdfUsbTargetDeviceSendControlTransferSynchronously = 0;   // offset 1332
    uint32_t pfnWdfUsbTargetDeviceFormatRequestForControlTransfer = 0;   // offset 1336
    uint32_t pfnWdfUsbTargetDeviceIsConnectedSynchronous = 0;   // offset 1340
    uint32_t pfnWdfUsbTargetDeviceResetPortSynchronously = 0;   // offset 1344
    uint32_t pfnWdfUsbTargetDeviceCyclePortSynchronously = 0;   // offset 1348
    uint32_t pfnWdfUsbTargetDeviceFormatRequestForCyclePort = 0;   // offset 1352
    uint32_t pfnWdfUsbTargetDeviceSendUrbSynchronously = 0;   // offset 1356
    uint32_t pfnWdfUsbTargetDeviceFormatRequestForUrb = 0;   // offset 1360
    uint32_t pfnWdfUsbTargetPipeGetInformation = 0;   // offset 1364
    uint32_t pfnWdfUsbTargetPipeIsInEndpoint = 0;   // offset 1368
    uint32_t pfnWdfUsbTargetPipeIsOutEndpoint = 0;   // offset 1372
    uint32_t pfnWdfUsbTargetPipeGetType = 0;   // offset 1376
    uint32_t pfnWdfUsbTargetPipeSetNoMaximumPacketSizeCheck = 0;   // offset 1380
    uint32_t pfnWdfUsbTargetPipeWriteSynchronously = 0;   // offset 1384
    uint32_t pfnWdfUsbTargetPipeFormatRequestForWrite = 0;   // offset 1388
    uint32_t pfnWdfUsbTargetPipeReadSynchronously = 0;   // offset 1392
    uint32_t pfnWdfUsbTargetPipeFormatRequestForRead = 0;   // offset 1396
    uint32_t pfnWdfUsbTargetPipeConfigContinuousReader = 0;   // offset 1400
    uint32_t pfnWdfUsbTargetPipeAbortSynchronously = 0;   // offset 1404
    uint32_t pfnWdfUsbTargetPipeFormatRequestForAbort = 0;   // offset 1408
    uint32_t pfnWdfUsbTargetPipeResetSynchronously = 0;   // offset 1412
    uint32_t pfnWdfUsbTargetPipeFormatRequestForReset = 0;   // offset 1416
    uint32_t pfnWdfUsbTargetPipeSendUrbSynchronously = 0;   // offset 1420
    uint32_t pfnWdfUsbTargetPipeFormatRequestForUrb = 0;   // offset 1424
    uint32_t pfnWdfUsbInterfaceGetInterfaceNumber = 0;   // offset 1428
    uint32_t pfnWdfUsbInterfaceGetNumEndpoints = 0;   // offset 1432
    uint32_t pfnWdfUsbInterfaceGetDescriptor = 0;   // offset 1436
    uint32_t pfnWdfUsbInterfaceSelectSetting = 0;   // offset 1440
    uint32_t pfnWdfUsbInterfaceGetEndpointInformation = 0;   // offset 1444
    uint32_t pfnWdfUsbTargetDeviceGetInterface = 0;   // offset 1448
    uint32_t pfnWdfUsbInterfaceGetConfiguredSettingIndex = 0;   // offset 1452
    uint32_t pfnWdfUsbInterfaceGetNumConfiguredPipes = 0;   // offset 1456
    uint32_t pfnWdfUsbInterfaceGetConfiguredPipe = 0;   // offset 1460
    uint32_t pfnWdfUsbTargetPipeWdmGetPipeHandle = 0;   // offset 1464
    uint32_t pfnWdfVerifierDbgBreakPoint = 0;   // offset 1468
    uint32_t pfnWdfVerifierKeBugCheck = 0;   // offset 1472
    uint32_t pfnWdfWmiProviderCreate = 0;   // offset 1476
    uint32_t pfnWdfWmiProviderGetDevice = 0;   // offset 1480
    uint32_t pfnWdfWmiProviderIsEnabled = 0;   // offset 1484
    uint32_t pfnWdfWmiProviderGetTracingHandle = 0;   // offset 1488
    uint32_t unknown0[13] = {};   // offset 1492
    uint32_t pfnWdfUsbInterfaceGetNumSettings = 0;   // offset 1544
    uint32_t unknown1[34] = {};   // offset 1548
    uint32_t pfnWdfUsbTargetDeviceCreateWithParameters = 0;   // offset 1684
    // total = 1688
};

template <>
struct WDFFUNCTIONS_POD<8> {
    uint64_t pfnWdfChildListCreate = 0;   // offset 0
    uint64_t pfnWdfChildListGetDevice = 0;   // offset 8
    uint64_t pfnWdfChildListRetrievePdo = 0;   // offset 16
    uint64_t pfnWdfChildListRetrieveAddressDescription = 0;   // offset 24
    uint64_t pfnWdfChildListBeginScan = 0;   // offset 32
    uint64_t pfnWdfChildListEndScan = 0;   // offset 40
    uint64_t pfnWdfChildListBeginIteration = 0;   // offset 48
    uint64_t pfnWdfChildListRetrieveNextDevice = 0;   // offset 56
    uint64_t pfnWdfChildListEndIteration = 0;   // offset 64
    uint64_t pfnWdfChildListAddOrUpdateChildDescriptionAsPresent = 0;   // offset 72
    uint64_t pfnWdfChildListUpdateChildDescriptionAsMissing = 0;   // offset 80
    uint64_t pfnWdfChildListUpdateAllChildDescriptionsAsPresent = 0;   // offset 88
    uint64_t pfnWdfChildListRequestChildEject = 0;   // offset 96
    uint64_t pfnWdfCollectionCreate = 0;   // offset 104
    uint64_t pfnWdfCollectionGetCount = 0;   // offset 112
    uint64_t pfnWdfCollectionAdd = 0;   // offset 120
    uint64_t pfnWdfCollectionRemove = 0;   // offset 128
    uint64_t pfnWdfCollectionRemoveItem = 0;   // offset 136
    uint64_t pfnWdfCollectionGetItem = 0;   // offset 144
    uint64_t pfnWdfCollectionGetFirstItem = 0;   // offset 152
    uint64_t pfnWdfCollectionGetLastItem = 0;   // offset 160
    uint64_t pfnWdfCommonBufferCreate = 0;   // offset 168
    uint64_t pfnWdfCommonBufferGetAlignedVirtualAddress = 0;   // offset 176
    uint64_t pfnWdfCommonBufferGetAlignedLogicalAddress = 0;   // offset 184
    uint64_t pfnWdfCommonBufferGetLength = 0;   // offset 192
    uint64_t pfnWdfControlDeviceInitAllocate = 0;   // offset 200
    uint64_t pfnWdfControlDeviceInitSetShutdownNotification = 0;   // offset 208
    uint64_t pfnWdfControlFinishInitializing = 0;   // offset 216
    uint64_t pfnWdfDeviceGetDeviceState = 0;   // offset 224
    uint64_t pfnWdfDeviceSetDeviceState = 0;   // offset 232
    uint64_t pfnWdfWdmDeviceGetWdfDeviceHandle = 0;   // offset 240
    uint64_t pfnWdfDeviceWdmGetDeviceObject = 0;   // offset 248
    uint64_t pfnWdfDeviceWdmGetAttachedDevice = 0;   // offset 256
    uint64_t pfnWdfDeviceWdmGetPhysicalDevice = 0;   // offset 264
    uint64_t pfnWdfDeviceWdmDispatchPreprocessedIrp = 0;   // offset 272
    uint64_t pfnWdfDeviceAddDependentUsageDeviceObject = 0;   // offset 280
    uint64_t pfnWdfDeviceAddRemovalRelationsPhysicalDevice = 0;   // offset 288
    uint64_t pfnWdfDeviceRemoveRemovalRelationsPhysicalDevice = 0;   // offset 296
    uint64_t pfnWdfDeviceClearRemovalRelationsDevices = 0;   // offset 304
    uint64_t pfnWdfDeviceGetDriver = 0;   // offset 312
    uint64_t pfnWdfDeviceRetrieveDeviceName = 0;   // offset 320
    uint64_t pfnWdfDeviceAssignMofResourceName = 0;   // offset 328
    uint64_t pfnWdfDeviceGetIoTarget = 0;   // offset 336
    uint64_t pfnWdfDeviceGetDevicePnpState = 0;   // offset 344
    uint64_t pfnWdfDeviceGetDevicePowerState = 0;   // offset 352
    uint64_t pfnWdfDeviceGetDevicePowerPolicyState = 0;   // offset 360
    uint64_t pfnWdfDeviceAssignS0IdleSettings = 0;   // offset 368
    uint64_t pfnWdfDeviceAssignSxWakeSettings = 0;   // offset 376
    uint64_t pfnWdfDeviceOpenRegistryKey = 0;   // offset 384
    uint64_t pfnWdfDeviceSetSpecialFileSupport = 0;   // offset 392
    uint64_t pfnWdfDeviceSetCharacteristics = 0;   // offset 400
    uint64_t pfnWdfDeviceGetCharacteristics = 0;   // offset 408
    uint64_t pfnWdfDeviceGetAlignmentRequirement = 0;   // offset 416
    uint64_t pfnWdfDeviceSetAlignmentRequirement = 0;   // offset 424
    uint64_t pfnWdfDeviceInitFree = 0;   // offset 432
    uint64_t pfnWdfDeviceInitSetPnpPowerEventCallbacks = 0;   // offset 440
    uint64_t pfnWdfDeviceInitSetPowerPolicyEventCallbacks = 0;   // offset 448
    uint64_t pfnWdfDeviceInitSetPowerPolicyOwnership = 0;   // offset 456
    uint64_t pfnWdfDeviceInitRegisterPnpStateChangeCallback = 0;   // offset 464
    uint64_t pfnWdfDeviceInitRegisterPowerStateChangeCallback = 0;   // offset 472
    uint64_t pfnWdfDeviceInitRegisterPowerPolicyStateChangeCallback = 0;   // offset 480
    uint64_t pfnWdfDeviceInitSetIoType = 0;   // offset 488
    uint64_t pfnWdfDeviceInitSetExclusive = 0;   // offset 496
    uint64_t pfnWdfDeviceInitSetPowerNotPageable = 0;   // offset 504
    uint64_t pfnWdfDeviceInitSetPowerPageable = 0;   // offset 512
    uint64_t pfnWdfDeviceInitSetPowerInrush = 0;   // offset 520
    uint64_t pfnWdfDeviceInitSetDeviceType = 0;   // offset 528
    uint64_t pfnWdfDeviceInitAssignName = 0;   // offset 536
    uint64_t pfnWdfDeviceInitAssignSDDLString = 0;   // offset 544
    uint64_t pfnWdfDeviceInitSetDeviceClass = 0;   // offset 552
    uint64_t pfnWdfDeviceInitSetCharacteristics = 0;   // offset 560
    uint64_t pfnWdfDeviceInitSetFileObjectConfig = 0;   // offset 568
    uint64_t pfnWdfDeviceInitSetRequestAttributes = 0;   // offset 576
    uint64_t pfnWdfDeviceInitAssignWdmIrpPreprocessCallback = 0;   // offset 584
    uint64_t pfnWdfDeviceInitSetIoInCallerContextCallback = 0;   // offset 592
    uint64_t pfnWdfDeviceCreate = 0;   // offset 600
    uint64_t pfnWdfDeviceSetStaticStopRemove = 0;   // offset 608
    uint64_t pfnWdfDeviceCreateDeviceInterface = 0;   // offset 616
    uint64_t pfnWdfDeviceSetDeviceInterfaceState = 0;   // offset 624
    uint64_t pfnWdfDeviceRetrieveDeviceInterfaceString = 0;   // offset 632
    uint64_t pfnWdfDeviceCreateSymbolicLink = 0;   // offset 640
    uint64_t pfnWdfDeviceQueryProperty = 0;   // offset 648
    uint64_t pfnWdfDeviceAllocAndQueryProperty = 0;   // offset 656
    uint64_t pfnWdfDeviceSetPnpCapabilities = 0;   // offset 664
    uint64_t pfnWdfDeviceSetPowerCapabilities = 0;   // offset 672
    uint64_t pfnWdfDeviceSetBusInformationForChildren = 0;   // offset 680
    uint64_t pfnWdfDeviceIndicateWakeStatus = 0;   // offset 688
    uint64_t pfnWdfDeviceSetFailed = 0;   // offset 696
    uint64_t pfnWdfDeviceStopIdleNoTrack = 0;   // offset 704
    uint64_t pfnWdfDeviceResumeIdleNoTrack = 0;   // offset 712
    uint64_t pfnWdfDeviceGetFileObject = 0;   // offset 720
    uint64_t pfnWdfDeviceEnqueueRequest = 0;   // offset 728
    uint64_t pfnWdfDeviceGetDefaultQueue = 0;   // offset 736
    uint64_t pfnWdfDeviceConfigureRequestDispatching = 0;   // offset 744
    uint64_t pfnWdfDmaEnablerCreate = 0;   // offset 752
    uint64_t pfnWdfDmaEnablerGetMaximumLength = 0;   // offset 760
    uint64_t pfnWdfDmaEnablerGetMaximumScatterGatherElements = 0;   // offset 768
    uint64_t pfnWdfDmaEnablerSetMaximumScatterGatherElements = 0;   // offset 776
    uint64_t pfnWdfDmaTransactionCreate = 0;   // offset 784
    uint64_t pfnWdfDmaTransactionInitialize = 0;   // offset 792
    uint64_t pfnWdfDmaTransactionInitializeUsingRequest = 0;   // offset 800
    uint64_t pfnWdfDmaTransactionExecute = 0;   // offset 808
    uint64_t pfnWdfDmaTransactionRelease = 0;   // offset 816
    uint64_t pfnWdfDmaTransactionDmaCompleted = 0;   // offset 824
    uint64_t pfnWdfDmaTransactionDmaCompletedWithLength = 0;   // offset 832
    uint64_t pfnWdfDmaTransactionDmaCompletedFinal = 0;   // offset 840
    uint64_t pfnWdfDmaTransactionGetBytesTransferred = 0;   // offset 848
    uint64_t pfnWdfDmaTransactionSetMaximumLength = 0;   // offset 856
    uint64_t pfnWdfDmaTransactionGetRequest = 0;   // offset 864
    uint64_t pfnWdfDmaTransactionGetCurrentDmaTransferLength = 0;   // offset 872
    uint64_t pfnWdfDmaTransactionGetDevice = 0;   // offset 880
    uint64_t pfnWdfDpcCreate = 0;   // offset 888
    uint64_t pfnWdfDpcEnqueue = 0;   // offset 896
    uint64_t pfnWdfDpcCancel = 0;   // offset 904
    uint64_t pfnWdfDpcGetParentObject = 0;   // offset 912
    uint64_t pfnWdfDpcWdmGetDpc = 0;   // offset 920
    uint64_t pfnWdfDriverCreate = 0;   // offset 928
    uint64_t pfnWdfDriverGetRegistryPath = 0;   // offset 936
    uint64_t pfnWdfDriverWdmGetDriverObject = 0;   // offset 944
    uint64_t pfnWdfDriverOpenParametersRegistryKey = 0;   // offset 952
    uint64_t pfnWdfWdmDriverGetWdfDriverHandle = 0;   // offset 960
    uint64_t pfnWdfDriverRegisterTraceInfo = 0;   // offset 968
    uint64_t pfnWdfDriverRetrieveVersionString = 0;   // offset 976
    uint64_t pfnWdfDriverIsVersionAvailable = 0;   // offset 984
    uint64_t pfnWdfFdoInitWdmGetPhysicalDevice = 0;   // offset 992
    uint64_t pfnWdfFdoInitOpenRegistryKey = 0;   // offset 1000
    uint64_t pfnWdfFdoInitQueryProperty = 0;   // offset 1008
    uint64_t pfnWdfFdoInitAllocAndQueryProperty = 0;   // offset 1016
    uint64_t pfnWdfFdoInitSetEventCallbacks = 0;   // offset 1024
    uint64_t pfnWdfFdoInitSetFilter = 0;   // offset 1032
    uint64_t pfnWdfFdoInitSetDefaultChildListConfig = 0;   // offset 1040
    uint64_t pfnWdfFdoQueryForInterface = 0;   // offset 1048
    uint64_t pfnWdfFdoGetDefaultChildList = 0;   // offset 1056
    uint64_t pfnWdfFdoAddStaticChild = 0;   // offset 1064
    uint64_t pfnWdfFdoLockStaticChildListForIteration = 0;   // offset 1072
    uint64_t pfnWdfFdoRetrieveNextStaticChild = 0;   // offset 1080
    uint64_t pfnWdfFdoUnlockStaticChildListFromIteration = 0;   // offset 1088
    uint64_t pfnWdfFileObjectGetFileName = 0;   // offset 1096
    uint64_t pfnWdfFileObjectGetFlags = 0;   // offset 1104
    uint64_t pfnWdfFileObjectGetDevice = 0;   // offset 1112
    uint64_t pfnWdfFileObjectWdmGetFileObject = 0;   // offset 1120
    uint64_t pfnWdfInterruptCreate = 0;   // offset 1128
    uint64_t pfnWdfInterruptQueueDpcForIsr = 0;   // offset 1136
    uint64_t pfnWdfInterruptSynchronize = 0;   // offset 1144
    uint64_t pfnWdfInterruptAcquireLock = 0;   // offset 1152
    uint64_t pfnWdfInterruptReleaseLock = 0;   // offset 1160
    uint64_t pfnWdfInterruptEnable = 0;   // offset 1168
    uint64_t pfnWdfInterruptDisable = 0;   // offset 1176
    uint64_t pfnWdfInterruptWdmGetInterrupt = 0;   // offset 1184
    uint64_t pfnWdfInterruptGetInfo = 0;   // offset 1192
    uint64_t pfnWdfInterruptSetPolicy = 0;   // offset 1200
    uint64_t pfnWdfInterruptGetDevice = 0;   // offset 1208
    uint64_t pfnWdfIoQueueCreate = 0;   // offset 1216
    uint64_t pfnWdfIoQueueGetState = 0;   // offset 1224
    uint64_t pfnWdfIoQueueStart = 0;   // offset 1232
    uint64_t pfnWdfIoQueueStop = 0;   // offset 1240
    uint64_t pfnWdfIoQueueStopSynchronously = 0;   // offset 1248
    uint64_t pfnWdfIoQueueGetDevice = 0;   // offset 1256
    uint64_t pfnWdfIoQueueRetrieveNextRequest = 0;   // offset 1264
    uint64_t pfnWdfIoQueueRetrieveRequestByFileObject = 0;   // offset 1272
    uint64_t pfnWdfIoQueueFindRequest = 0;   // offset 1280
    uint64_t pfnWdfIoQueueRetrieveFoundRequest = 0;   // offset 1288
    uint64_t pfnWdfIoQueueDrainSynchronously = 0;   // offset 1296
    uint64_t pfnWdfIoQueueDrain = 0;   // offset 1304
    uint64_t pfnWdfIoQueuePurgeSynchronously = 0;   // offset 1312
    uint64_t pfnWdfIoQueuePurge = 0;   // offset 1320
    uint64_t pfnWdfIoQueueReadyNotify = 0;   // offset 1328
    uint64_t pfnWdfIoTargetCreate = 0;   // offset 1336
    uint64_t pfnWdfIoTargetOpen = 0;   // offset 1344
    uint64_t pfnWdfIoTargetCloseForQueryRemove = 0;   // offset 1352
    uint64_t pfnWdfIoTargetClose = 0;   // offset 1360
    uint64_t pfnWdfIoTargetStart = 0;   // offset 1368
    uint64_t pfnWdfIoTargetStop = 0;   // offset 1376
    uint64_t pfnWdfIoTargetGetState = 0;   // offset 1384
    uint64_t pfnWdfIoTargetGetDevice = 0;   // offset 1392
    uint64_t pfnWdfIoTargetQueryTargetProperty = 0;   // offset 1400
    uint64_t pfnWdfIoTargetAllocAndQueryTargetProperty = 0;   // offset 1408
    uint64_t pfnWdfIoTargetQueryForInterface = 0;   // offset 1416
    uint64_t pfnWdfIoTargetWdmGetTargetDeviceObject = 0;   // offset 1424
    uint64_t pfnWdfIoTargetWdmGetTargetPhysicalDevice = 0;   // offset 1432
    uint64_t pfnWdfIoTargetWdmGetTargetFileObject = 0;   // offset 1440
    uint64_t pfnWdfIoTargetWdmGetTargetFileHandle = 0;   // offset 1448
    uint64_t pfnWdfIoTargetSendReadSynchronously = 0;   // offset 1456
    uint64_t pfnWdfIoTargetFormatRequestForRead = 0;   // offset 1464
    uint64_t pfnWdfIoTargetSendWriteSynchronously = 0;   // offset 1472
    uint64_t pfnWdfIoTargetFormatRequestForWrite = 0;   // offset 1480
    uint64_t pfnWdfIoTargetSendIoctlSynchronously = 0;   // offset 1488
    uint64_t pfnWdfIoTargetFormatRequestForIoctl = 0;   // offset 1496
    uint64_t pfnWdfIoTargetSendInternalIoctlSynchronously = 0;   // offset 1504
    uint64_t pfnWdfIoTargetFormatRequestForInternalIoctl = 0;   // offset 1512
    uint64_t pfnWdfIoTargetSendInternalIoctlOthersSynchronously = 0;   // offset 1520
    uint64_t pfnWdfIoTargetFormatRequestForInternalIoctlOthers = 0;   // offset 1528
    uint64_t pfnWdfMemoryCreate = 0;   // offset 1536
    uint64_t pfnWdfMemoryCreatePreallocated = 0;   // offset 1544
    uint64_t pfnWdfMemoryGetBuffer = 0;   // offset 1552
    uint64_t pfnWdfMemoryAssignBuffer = 0;   // offset 1560
    uint64_t pfnWdfMemoryCopyToBuffer = 0;   // offset 1568
    uint64_t pfnWdfMemoryCopyFromBuffer = 0;   // offset 1576
    uint64_t pfnWdfLookasideListCreate = 0;   // offset 1584
    uint64_t pfnWdfMemoryCreateFromLookaside = 0;   // offset 1592
    uint64_t pfnWdfDeviceMiniportCreate = 0;   // offset 1600
    uint64_t pfnWdfDriverMiniportUnload = 0;   // offset 1608
    uint64_t pfnWdfObjectGetTypedContextWorker = 0;   // offset 1616
    uint64_t pfnWdfObjectAllocateContext = 0;   // offset 1624
    uint64_t pfnWdfObjectContextGetObject = 0;   // offset 1632
    uint64_t pfnWdfObjectReferenceActual = 0;   // offset 1640
    uint64_t pfnWdfObjectDereferenceActual = 0;   // offset 1648
    uint64_t pfnWdfObjectCreate = 0;   // offset 1656
    uint64_t pfnWdfObjectDelete = 0;   // offset 1664
    uint64_t pfnWdfObjectQuery = 0;   // offset 1672
    uint64_t pfnWdfPdoInitAllocate = 0;   // offset 1680
    uint64_t pfnWdfPdoInitSetEventCallbacks = 0;   // offset 1688
    uint64_t pfnWdfPdoInitAssignDeviceID = 0;   // offset 1696
    uint64_t pfnWdfPdoInitAssignInstanceID = 0;   // offset 1704
    uint64_t pfnWdfPdoInitAddHardwareID = 0;   // offset 1712
    uint64_t pfnWdfPdoInitAddCompatibleID = 0;   // offset 1720
    uint64_t pfnWdfPdoInitAddDeviceText = 0;   // offset 1728
    uint64_t pfnWdfPdoInitSetDefaultLocale = 0;   // offset 1736
    uint64_t pfnWdfPdoInitAssignRawDevice = 0;   // offset 1744
    uint64_t pfnWdfPdoMarkMissing = 0;   // offset 1752
    uint64_t pfnWdfPdoRequestEject = 0;   // offset 1760
    uint64_t pfnWdfPdoGetParent = 0;   // offset 1768
    uint64_t pfnWdfPdoRetrieveIdentificationDescription = 0;   // offset 1776
    uint64_t pfnWdfPdoRetrieveAddressDescription = 0;   // offset 1784
    uint64_t pfnWdfPdoUpdateAddressDescription = 0;   // offset 1792
    uint64_t pfnWdfPdoAddEjectionRelationsPhysicalDevice = 0;   // offset 1800
    uint64_t pfnWdfPdoRemoveEjectionRelationsPhysicalDevice = 0;   // offset 1808
    uint64_t pfnWdfPdoClearEjectionRelationsDevices = 0;   // offset 1816
    uint64_t pfnWdfDeviceAddQueryInterface = 0;   // offset 1824
    uint64_t pfnWdfRegistryOpenKey = 0;   // offset 1832
    uint64_t pfnWdfRegistryCreateKey = 0;   // offset 1840
    uint64_t pfnWdfRegistryClose = 0;   // offset 1848
    uint64_t pfnWdfRegistryWdmGetHandle = 0;   // offset 1856
    uint64_t pfnWdfRegistryRemoveKey = 0;   // offset 1864
    uint64_t pfnWdfRegistryRemoveValue = 0;   // offset 1872
    uint64_t pfnWdfRegistryQueryValue = 0;   // offset 1880
    uint64_t pfnWdfRegistryQueryMemory = 0;   // offset 1888
    uint64_t pfnWdfRegistryQueryMultiString = 0;   // offset 1896
    uint64_t pfnWdfRegistryQueryUnicodeString = 0;   // offset 1904
    uint64_t pfnWdfRegistryQueryString = 0;   // offset 1912
    uint64_t pfnWdfRegistryQueryULong = 0;   // offset 1920
    uint64_t pfnWdfRegistryAssignValue = 0;   // offset 1928
    uint64_t pfnWdfRegistryAssignMemory = 0;   // offset 1936
    uint64_t pfnWdfRegistryAssignMultiString = 0;   // offset 1944
    uint64_t pfnWdfRegistryAssignUnicodeString = 0;   // offset 1952
    uint64_t pfnWdfRegistryAssignString = 0;   // offset 1960
    uint64_t pfnWdfRegistryAssignULong = 0;   // offset 1968
    uint64_t pfnWdfRequestCreate = 0;   // offset 1976
    uint64_t pfnWdfRequestCreateFromIrp = 0;   // offset 1984
    uint64_t pfnWdfRequestReuse = 0;   // offset 1992
    uint64_t pfnWdfRequestChangeTarget = 0;   // offset 2000
    uint64_t pfnWdfRequestFormatRequestUsingCurrentType = 0;   // offset 2008
    uint64_t pfnWdfRequestWdmFormatUsingStackLocation = 0;   // offset 2016
    uint64_t pfnWdfRequestSend = 0;   // offset 2024
    uint64_t pfnWdfRequestGetStatus = 0;   // offset 2032
    uint64_t pfnWdfRequestMarkCancelable = 0;   // offset 2040
    uint64_t pfnWdfRequestUnmarkCancelable = 0;   // offset 2048
    uint64_t pfnWdfRequestIsCanceled = 0;   // offset 2056
    uint64_t pfnWdfRequestCancelSentRequest = 0;   // offset 2064
    uint64_t pfnWdfRequestIsFrom32BitProcess = 0;   // offset 2072
    uint64_t pfnWdfRequestSetCompletionRoutine = 0;   // offset 2080
    uint64_t pfnWdfRequestGetCompletionParams = 0;   // offset 2088
    uint64_t pfnWdfRequestAllocateTimer = 0;   // offset 2096
    uint64_t pfnWdfRequestComplete = 0;   // offset 2104
    uint64_t pfnWdfRequestCompleteWithPriorityBoost = 0;   // offset 2112
    uint64_t pfnWdfRequestCompleteWithInformation = 0;   // offset 2120
    uint64_t pfnWdfRequestGetParameters = 0;   // offset 2128
    uint64_t pfnWdfRequestRetrieveInputMemory = 0;   // offset 2136
    uint64_t pfnWdfRequestRetrieveOutputMemory = 0;   // offset 2144
    uint64_t pfnWdfRequestRetrieveInputBuffer = 0;   // offset 2152
    uint64_t pfnWdfRequestRetrieveOutputBuffer = 0;   // offset 2160
    uint64_t pfnWdfRequestRetrieveInputWdmMdl = 0;   // offset 2168
    uint64_t pfnWdfRequestRetrieveOutputWdmMdl = 0;   // offset 2176
    uint64_t pfnWdfRequestRetrieveUnsafeUserInputBuffer = 0;   // offset 2184
    uint64_t pfnWdfRequestRetrieveUnsafeUserOutputBuffer = 0;   // offset 2192
    uint64_t pfnWdfRequestSetInformation = 0;   // offset 2200
    uint64_t pfnWdfRequestGetInformation = 0;   // offset 2208
    uint64_t pfnWdfRequestGetFileObject = 0;   // offset 2216
    uint64_t pfnWdfRequestProbeAndLockUserBufferForRead = 0;   // offset 2224
    uint64_t pfnWdfRequestProbeAndLockUserBufferForWrite = 0;   // offset 2232
    uint64_t pfnWdfRequestGetRequestorMode = 0;   // offset 2240
    uint64_t pfnWdfRequestForwardToIoQueue = 0;   // offset 2248
    uint64_t pfnWdfRequestGetIoQueue = 0;   // offset 2256
    uint64_t pfnWdfRequestRequeue = 0;   // offset 2264
    uint64_t pfnWdfRequestStopAcknowledge = 0;   // offset 2272
    uint64_t pfnWdfRequestWdmGetIrp = 0;   // offset 2280
    uint64_t pfnWdfIoResourceRequirementsListSetSlotNumber = 0;   // offset 2288
    uint64_t pfnWdfIoResourceRequirementsListSetInterfaceType = 0;   // offset 2296
    uint64_t pfnWdfIoResourceRequirementsListAppendIoResList = 0;   // offset 2304
    uint64_t pfnWdfIoResourceRequirementsListInsertIoResList = 0;   // offset 2312
    uint64_t pfnWdfIoResourceRequirementsListGetCount = 0;   // offset 2320
    uint64_t pfnWdfIoResourceRequirementsListGetIoResList = 0;   // offset 2328
    uint64_t pfnWdfIoResourceRequirementsListRemove = 0;   // offset 2336
    uint64_t pfnWdfIoResourceRequirementsListRemoveByIoResList = 0;   // offset 2344
    uint64_t pfnWdfIoResourceListCreate = 0;   // offset 2352
    uint64_t pfnWdfIoResourceListAppendDescriptor = 0;   // offset 2360
    uint64_t pfnWdfIoResourceListInsertDescriptor = 0;   // offset 2368
    uint64_t pfnWdfIoResourceListUpdateDescriptor = 0;   // offset 2376
    uint64_t pfnWdfIoResourceListGetCount = 0;   // offset 2384
    uint64_t pfnWdfIoResourceListGetDescriptor = 0;   // offset 2392
    uint64_t pfnWdfIoResourceListRemove = 0;   // offset 2400
    uint64_t pfnWdfIoResourceListRemoveByDescriptor = 0;   // offset 2408
    uint64_t pfnWdfCmResourceListAppendDescriptor = 0;   // offset 2416
    uint64_t pfnWdfCmResourceListInsertDescriptor = 0;   // offset 2424
    uint64_t pfnWdfCmResourceListGetCount = 0;   // offset 2432
    uint64_t pfnWdfCmResourceListGetDescriptor = 0;   // offset 2440
    uint64_t pfnWdfCmResourceListRemove = 0;   // offset 2448
    uint64_t pfnWdfCmResourceListRemoveByDescriptor = 0;   // offset 2456
    uint64_t pfnWdfStringCreate = 0;   // offset 2464
    uint64_t pfnWdfStringGetUnicodeString = 0;   // offset 2472
    uint64_t pfnWdfObjectAcquireLock = 0;   // offset 2480
    uint64_t pfnWdfObjectReleaseLock = 0;   // offset 2488
    uint64_t pfnWdfWaitLockCreate = 0;   // offset 2496
    uint64_t pfnWdfWaitLockAcquire = 0;   // offset 2504
    uint64_t pfnWdfWaitLockRelease = 0;   // offset 2512
    uint64_t pfnWdfSpinLockCreate = 0;   // offset 2520
    uint64_t pfnWdfSpinLockAcquire = 0;   // offset 2528
    uint64_t pfnWdfSpinLockRelease = 0;   // offset 2536
    uint64_t pfnWdfTimerCreate = 0;   // offset 2544
    uint64_t pfnWdfTimerStart = 0;   // offset 2552
    uint64_t pfnWdfTimerStop = 0;   // offset 2560
    uint64_t pfnWdfTimerGetParentObject = 0;   // offset 2568
    uint64_t pfnWdfUsbTargetDeviceCreate = 0;   // offset 2576
    uint64_t pfnWdfUsbTargetDeviceRetrieveInformation = 0;   // offset 2584
    uint64_t pfnWdfUsbTargetDeviceGetDeviceDescriptor = 0;   // offset 2592
    uint64_t pfnWdfUsbTargetDeviceRetrieveConfigDescriptor = 0;   // offset 2600
    uint64_t pfnWdfUsbTargetDeviceQueryString = 0;   // offset 2608
    uint64_t pfnWdfUsbTargetDeviceAllocAndQueryString = 0;   // offset 2616
    uint64_t pfnWdfUsbTargetDeviceFormatRequestForString = 0;   // offset 2624
    uint64_t pfnWdfUsbTargetDeviceGetNumInterfaces = 0;   // offset 2632
    uint64_t pfnWdfUsbTargetDeviceSelectConfig = 0;   // offset 2640
    uint64_t pfnWdfUsbTargetDeviceWdmGetConfigurationHandle = 0;   // offset 2648
    uint64_t pfnWdfUsbTargetDeviceRetrieveCurrentFrameNumber = 0;   // offset 2656
    uint64_t pfnWdfUsbTargetDeviceSendControlTransferSynchronously = 0;   // offset 2664
    uint64_t pfnWdfUsbTargetDeviceFormatRequestForControlTransfer = 0;   // offset 2672
    uint64_t pfnWdfUsbTargetDeviceIsConnectedSynchronous = 0;   // offset 2680
    uint64_t pfnWdfUsbTargetDeviceResetPortSynchronously = 0;   // offset 2688
    uint64_t pfnWdfUsbTargetDeviceCyclePortSynchronously = 0;   // offset 2696
    uint64_t pfnWdfUsbTargetDeviceFormatRequestForCyclePort = 0;   // offset 2704
    uint64_t pfnWdfUsbTargetDeviceSendUrbSynchronously = 0;   // offset 2712
    uint64_t pfnWdfUsbTargetDeviceFormatRequestForUrb = 0;   // offset 2720
    uint64_t pfnWdfUsbTargetPipeGetInformation = 0;   // offset 2728
    uint64_t pfnWdfUsbTargetPipeIsInEndpoint = 0;   // offset 2736
    uint64_t pfnWdfUsbTargetPipeIsOutEndpoint = 0;   // offset 2744
    uint64_t pfnWdfUsbTargetPipeGetType = 0;   // offset 2752
    uint64_t pfnWdfUsbTargetPipeSetNoMaximumPacketSizeCheck = 0;   // offset 2760
    uint64_t pfnWdfUsbTargetPipeWriteSynchronously = 0;   // offset 2768
    uint64_t pfnWdfUsbTargetPipeFormatRequestForWrite = 0;   // offset 2776
    uint64_t pfnWdfUsbTargetPipeReadSynchronously = 0;   // offset 2784
    uint64_t pfnWdfUsbTargetPipeFormatRequestForRead = 0;   // offset 2792
    uint64_t pfnWdfUsbTargetPipeConfigContinuousReader = 0;   // offset 2800
    uint64_t pfnWdfUsbTargetPipeAbortSynchronously = 0;   // offset 2808
    uint64_t pfnWdfUsbTargetPipeFormatRequestForAbort = 0;   // offset 2816
    uint64_t pfnWdfUsbTargetPipeResetSynchronously = 0;   // offset 2824
    uint64_t pfnWdfUsbTargetPipeFormatRequestForReset = 0;   // offset 2832
    uint64_t pfnWdfUsbTargetPipeSendUrbSynchronously = 0;   // offset 2840
    uint64_t pfnWdfUsbTargetPipeFormatRequestForUrb = 0;   // offset 2848
    uint64_t pfnWdfUsbInterfaceGetInterfaceNumber = 0;   // offset 2856
    uint64_t pfnWdfUsbInterfaceGetNumEndpoints = 0;   // offset 2864
    uint64_t pfnWdfUsbInterfaceGetDescriptor = 0;   // offset 2872
    uint64_t pfnWdfUsbInterfaceSelectSetting = 0;   // offset 2880
    uint64_t pfnWdfUsbInterfaceGetEndpointInformation = 0;   // offset 2888
    uint64_t pfnWdfUsbTargetDeviceGetInterface = 0;   // offset 2896
    uint64_t pfnWdfUsbInterfaceGetConfiguredSettingIndex = 0;   // offset 2904
    uint64_t pfnWdfUsbInterfaceGetNumConfiguredPipes = 0;   // offset 2912
    uint64_t pfnWdfUsbInterfaceGetConfiguredPipe = 0;   // offset 2920
    uint64_t pfnWdfUsbTargetPipeWdmGetPipeHandle = 0;   // offset 2928
    uint64_t pfnWdfVerifierDbgBreakPoint = 0;   // offset 2936
    uint64_t pfnWdfVerifierKeBugCheck = 0;   // offset 2944
    uint64_t pfnWdfWmiProviderCreate = 0;   // offset 2952
    uint64_t pfnWdfWmiProviderGetDevice = 0;   // offset 2960
    uint64_t pfnWdfWmiProviderIsEnabled = 0;   // offset 2968
    uint64_t pfnWdfWmiProviderGetTracingHandle = 0;   // offset 2976
    uint64_t unknown0[13] = {};   // offset 2984
    uint64_t pfnWdfUsbInterfaceGetNumSettings = 0;   // offset 3088
    uint64_t unknown1[34] = {};   // offset 3096
    uint64_t pfnWdfUsbTargetDeviceCreateWithParameters = 0;   // offset 3368
    // total = 3376
};

template <int PtrSize>
struct WDFFUNCTIONS
    : public EmuStructHelper<WDFFUNCTIONS<PtrSize>>,
      public WDFFUNCTIONS_POD<PtrSize> {
    std::string get_mem_tag() const override { return "wdffunctions"; }
};

#pragma pack(pop)

} // namespace deffs
} // namespace speakeasy

#endif // SPEAKEASY_DEFS_NEW_WDF_H
