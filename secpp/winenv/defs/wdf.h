// wdf.h  Windows Driver Framework (WDF) type definitions
//
// Maps to: speakeasy/winenv/defs/wdf.py
//
// KMDF structures and enums used by WDF API emulation,
// including USB target, I/O queue, interrupt, and DMA types.

#ifndef SPEAKEASY_DEFS_WDF_H
#define SPEAKEASY_DEFS_WDF_H

#include <cstdint>
#include <vector>
#include "../../struct.h"
#include "usb.h"

namespace speakeasy { namespace defs {

//  WDF USB target select config type enums 
constexpr uint32_t WdfUsbTargetDeviceSelectConfigTypeInvalid             = 0;
constexpr uint32_t WdfUsbTargetDeviceSelectConfigTypeDeconfig           = 1;
constexpr uint32_t WdfUsbTargetDeviceSelectConfigTypeSingleInterface    = 2;
constexpr uint32_t WdfUsbTargetDeviceSelectConfigTypeMultiInterface     = 3;
constexpr uint32_t WdfUsbTargetDeviceSelectConfigTypeInterfacesPairs    = 4;
constexpr uint32_t WdfUsbTargetDeviceSelectConfigTypeInterfacesDescriptor = 5;
constexpr uint32_t WdfUsbTargetDeviceSelectConfigTypeUrb                = 6;

constexpr uint32_t WdfUsbInterfaceSelectSettingTypeDescriptor = 0x10;
constexpr uint32_t WdfUsbInterfaceSelectSettingTypeSetting    = 0x11;
constexpr uint32_t WdfUsbInterfaceSelectSettingTypeUrb        = 0x12;

//  WDF USB pipe type enums 
constexpr uint32_t WdfUsbPipeTypeInvalid      = 0;
constexpr uint32_t WdfUsbPipeTypeControl      = 1;
constexpr uint32_t WdfUsbPipeTypeIsochronous  = 2;
constexpr uint32_t WdfUsbPipeTypeBulk         = 3;
constexpr uint32_t WdfUsbPipeTypeInterrupt    = 4;

//  WDF USB device trait flags 
constexpr uint32_t WDF_USB_DEVICE_TRAIT_SELF_POWERED          = 1;
constexpr uint32_t WDF_USB_DEVICE_TRAIT_REMOTE_WAKE_CAPABLE   = 2;
constexpr uint32_t WDF_USB_DEVICE_TRAIT_AT_HIGH_SPEED         = 4;

//  WDF_VERSION (12 bytes) 
struct WDF_VERSION : speakeasy::EmuStruct {
    uint32_t Major = 0;
    uint32_t Minor = 0;
    uint32_t Build = 0;

    size_t sizeof_obj() const override { return 12; }
    std::vector<uint8_t> get_bytes() const override {
        std::vector<uint8_t> b(12);
        speakeasy::write_le(b, 0, Major, 4);
        speakeasy::write_le(b, 4, Minor, 4);
        speakeasy::write_le(b, 8, Build, 4);
        return b;
    }
};

//  WDF_BIND_INFO 
struct WDF_BIND_INFO : speakeasy::EmuStruct {
    uint32_t Size       = 0;
    uint32_t __pad0     = 0;
    uint64_t Component  = 0;  // Ptr
    WDF_VERSION Version;
    uint32_t FuncCount  = 0;
    uint32_t __pad1     = 0;
    uint64_t FuncTable  = 0;  // Ptr
    uint64_t Module     = 0;  // Ptr

    size_t sizeof_obj() const override {
        return 4 + 4 + 8 + Version.sizeof_obj() + 4 + 4 + 8 + 8;
    }
    std::vector<uint8_t> get_bytes() const override {
        size_t sz = sizeof_obj();
        std::vector<uint8_t> b(sz, 0);
        size_t off = 0;
        speakeasy::write_le(b, off, Size, 4); off += 8; // +4 pad
        speakeasy::write_le(b, off, Component, 8); off += 8;
        auto vb = Version.get_bytes();
        std::copy(vb.begin(), vb.end(), b.begin() + off); off += vb.size();
        speakeasy::write_le(b, off, FuncCount, 4); off += 8; // +4 pad
        speakeasy::write_le(b, off, FuncTable, 8); off += 8;
        speakeasy::write_le(b, off, Module, 8); off += 8;
        return b;
    }
};

//  WDF_USB_DEVICE_INFORMATION 
struct WDF_USB_DEVICE_INFORMATION : speakeasy::EmuStruct {
    uint32_t Size                  = 0;
    uint32_t __pad0                = 0;
    USBD_VERSION_INFORMATION UsbdVersionInformation;
    uint32_t HcdPortCapabilities   = 0;
    uint32_t Traits                = 0;

    size_t sizeof_obj() const override {
        return 4 + 4 + UsbdVersionInformation.sizeof_obj() + 4 + 4;
    }
    std::vector<uint8_t> get_bytes() const override {
        size_t sz = sizeof_obj();
        std::vector<uint8_t> b(sz, 0);
        size_t off = 0;
        speakeasy::write_le(b, off, Size, 4); off += 8; // +4 pad
        auto uvb = UsbdVersionInformation.get_bytes();
        std::copy(uvb.begin(), uvb.end(), b.begin() + off); off += uvb.size();
        speakeasy::write_le(b, off, HcdPortCapabilities, 4); off += 4;
        speakeasy::write_le(b, off, Traits, 4); off += 4;
        return b;
    }
};

//  WDF_DRIVER_CONFIG 
struct WDF_DRIVER_CONFIG : speakeasy::EmuStruct {
    uint32_t Size            = 0;
    uint32_t __pad0          = 0;
    uint64_t EvtDriverDeviceAdd = 0;  // Ptr
    uint64_t EvtDriverUnload = 0;     // Ptr
    uint32_t DriverInitFlags = 0;
    uint32_t DriverPoolTag   = 0;

    size_t sizeof_obj() const override { return 4 + 4 + 8 + 8 + 4 + 4; }
    std::vector<uint8_t> get_bytes() const override {
        size_t sz = sizeof_obj();
        std::vector<uint8_t> b(sz, 0);
        speakeasy::write_le(b, 0, Size, 4);
        // __pad0
        speakeasy::write_le(b, 8, EvtDriverDeviceAdd, 8);
        speakeasy::write_le(b, 16, EvtDriverUnload, 8);
        speakeasy::write_le(b, 24, DriverInitFlags, 4);
        speakeasy::write_le(b, 28, DriverPoolTag, 4);
        return b;
    }
};

//  WDF_COMPONENT_GLOBALS (0x100 opaque bytes) 
struct WDF_COMPONENT_GLOBALS : speakeasy::EmuStruct {
    uint8_t Data[0x100] = {};

    size_t sizeof_obj() const override { return 0x100; }
    std::vector<uint8_t> get_bytes() const override {
        return std::vector<uint8_t>(Data, Data + 0x100);
    }
};

//  WDF_TYPED_CONTEXT_WORKER (0x100 opaque bytes) 
struct WDF_TYPED_CONTEXT_WORKER : speakeasy::EmuStruct {
    uint8_t Data[0x100] = {};

    size_t sizeof_obj() const override { return 0x100; }
    std::vector<uint8_t> get_bytes() const override {
        return std::vector<uint8_t>(Data, Data + 0x100);
    }
};

//  WDF_USB_PIPE_INFORMATION 
struct WDF_USB_PIPE_INFORMATION : speakeasy::EmuStruct {
    uint32_t Size               = 0;
    uint32_t MaximumPacketSize  = 0;
    uint8_t  EndpointAddress    = 0;
    uint8_t  Interval           = 0;
    uint8_t  SettingIndex       = 0;
    uint8_t  __pad0             = 0;
    uint32_t PipeType           = 0;
    uint32_t MaximumTransferSize = 0;

    size_t sizeof_obj() const override { return 4 + 4 + 1 + 1 + 1 + 1 + 4 + 4; }
    std::vector<uint8_t> get_bytes() const override {
        std::vector<uint8_t> b(20);
        speakeasy::write_le(b, 0, Size, 4);
        speakeasy::write_le(b, 4, MaximumPacketSize, 4);
        speakeasy::write_le(b, 8, EndpointAddress, 1);
        speakeasy::write_le(b, 9, Interval, 1);
        speakeasy::write_le(b, 10, SettingIndex, 1);
        // __pad0 at offset 11
        speakeasy::write_le(b, 12, PipeType, 4);
        speakeasy::write_le(b, 16, MaximumTransferSize, 4);
        return b;
    }
};

//  WDF_PNPPOWER_EVENT_CALLBACKS 
struct WDF_PNPPOWER_EVENT_CALLBACKS : speakeasy::EmuStruct {
    uint32_t Size                                  = 0;
    uint32_t __pad0                                = 0;
    uint64_t EvtDeviceD0Entry                      = 0;
    uint64_t EvtDeviceD0EntryPostInterruptsEnabled = 0;
    uint64_t EvtDeviceD0Exit                       = 0;
    uint64_t EvtDeviceD0ExitPreInterruptsDisabled  = 0;
    uint64_t EvtDevicePrepareHardware              = 0;
    uint64_t EvtDeviceReleaseHardware              = 0;
    uint64_t EvtDeviceSelfManagedIoCleanup         = 0;
    uint64_t EvtDeviceSelfManagedIoFlush           = 0;
    uint64_t EvtDeviceSelfManagedIoInit            = 0;
    uint64_t EvtDeviceSelfManagedIoSuspend         = 0;
    uint64_t EvtDeviceSelfManagedIoRestart         = 0;
    uint64_t EvtDeviceSurpriseRemoval              = 0;
    uint64_t EvtDeviceQueryRemove                  = 0;
    uint64_t EvtDeviceQueryStop                    = 0;
    uint64_t EvtDeviceUsageNotification            = 0;
    uint64_t EvtDeviceRelationsQuery               = 0;
    uint64_t EvtDeviceUsageNotificationEx          = 0;

    size_t sizeof_obj() const override {
        return 4 + 4 + 16 * 8;  // Size + pad + 16 pointers
    }
    std::vector<uint8_t> get_bytes() const override {
        size_t sz = sizeof_obj();
        std::vector<uint8_t> b(sz, 0);
        size_t off = 0;
        speakeasy::write_le(b, off, Size, 4); off += 8; // +4 pad
        speakeasy::write_le(b, off, EvtDeviceD0Entry, 8); off += 8;
        speakeasy::write_le(b, off, EvtDeviceD0EntryPostInterruptsEnabled, 8); off += 8;
        speakeasy::write_le(b, off, EvtDeviceD0Exit, 8); off += 8;
        speakeasy::write_le(b, off, EvtDeviceD0ExitPreInterruptsDisabled, 8); off += 8;
        speakeasy::write_le(b, off, EvtDevicePrepareHardware, 8); off += 8;
        speakeasy::write_le(b, off, EvtDeviceReleaseHardware, 8); off += 8;
        speakeasy::write_le(b, off, EvtDeviceSelfManagedIoCleanup, 8); off += 8;
        speakeasy::write_le(b, off, EvtDeviceSelfManagedIoFlush, 8); off += 8;
        speakeasy::write_le(b, off, EvtDeviceSelfManagedIoInit, 8); off += 8;
        speakeasy::write_le(b, off, EvtDeviceSelfManagedIoSuspend, 8); off += 8;
        speakeasy::write_le(b, off, EvtDeviceSelfManagedIoRestart, 8); off += 8;
        speakeasy::write_le(b, off, EvtDeviceSurpriseRemoval, 8); off += 8;
        speakeasy::write_le(b, off, EvtDeviceQueryRemove, 8); off += 8;
        speakeasy::write_le(b, off, EvtDeviceQueryStop, 8); off += 8;
        speakeasy::write_le(b, off, EvtDeviceUsageNotification, 8); off += 8;
        speakeasy::write_le(b, off, EvtDeviceRelationsQuery, 8); off += 8;
        speakeasy::write_le(b, off, EvtDeviceUsageNotificationEx, 8); off += 8;
        return b;
    }
};

//  WDF_USB_INTERFACE_SELECT_SETTING_PARAMS 
struct _WDF_USB_INTERFACE_SELECT_SETTING_PARAMS_Descriptor : speakeasy::EmuStruct {
    uint64_t InterfaceDescriptor = 0;  // Ptr
    size_t sizeof_obj() const override { return 8; }
    std::vector<uint8_t> get_bytes() const override {
        std::vector<uint8_t> b(8);
        speakeasy::write_le(b, 0, InterfaceDescriptor, 8);
        return b;
    }
};

struct _WDF_USB_INTERFACE_SELECT_SETTING_PARAMS_Interface : speakeasy::EmuStruct {
    uint8_t SettingIndex = 0;
    uint8_t __pad0[7]    = {};
    size_t sizeof_obj() const override { return 8; }
    std::vector<uint8_t> get_bytes() const override {
        std::vector<uint8_t> b(8, 0);
        speakeasy::write_le(b, 0, SettingIndex, 1);
        return b;
    }
};

struct _WDF_USB_INTERFACE_SELECT_SETTING_PARAMS_Urb : speakeasy::EmuStruct {
    uint64_t Urb = 0;  // Ptr
    size_t sizeof_obj() const override { return 8; }
    std::vector<uint8_t> get_bytes() const override {
        std::vector<uint8_t> b(8);
        speakeasy::write_le(b, 0, Urb, 8);
        return b;
    }
};

struct WDF_USB_INTERFACE_SELECT_SETTING_PARAMS : speakeasy::EmuStruct {
    uint32_t Size = 0;
    uint32_t Type = 0;
    // Union Types is 8 bytes max (all members are 8 bytes)
    uint64_t Types_InterfaceDescriptor = 0;
    uint64_t Types_SettingIndex        = 0;
    uint64_t Types_Urb                 = 0;

    size_t sizeof_obj() const override { return 4 + 4 + 8; }
    std::vector<uint8_t> get_bytes() const override {
        size_t sz = sizeof_obj();
        std::vector<uint8_t> b(sz, 0);
        speakeasy::write_le(b, 0, Size, 4);
        speakeasy::write_le(b, 4, Type, 4);
        // Union: write the largest variant (8 bytes)
        speakeasy::write_le(b, 8, Types_InterfaceDescriptor, 8);
        return b;
    }
};

//  WDF_USB_DEVICE_SELECT_CONFIG_PARAMS 
struct _WDF_USB_DEVICE_SELECT_CONFIG_PARAMS_Descriptor : speakeasy::EmuStruct {
    uint64_t ConfigurationDescriptor = 0;  // Ptr
    uint64_t InterfaceDescriptors    = 0;  // Ptr
    uint32_t NumInterfaceDescriptors = 0;
    uint32_t __pad0                  = 0;

    size_t sizeof_obj() const override { return 8 + 8 + 4 + 4; }
    std::vector<uint8_t> get_bytes() const override {
        std::vector<uint8_t> b(24);
        speakeasy::write_le(b, 0, ConfigurationDescriptor, 8);
        speakeasy::write_le(b, 8, InterfaceDescriptors, 8);
        speakeasy::write_le(b, 16, NumInterfaceDescriptors, 4);
        // __pad0
        return b;
    }
};

struct _WDF_USB_DEVICE_SELECT_CONFIG_PARAMS_Urb : speakeasy::EmuStruct {
    uint64_t Urb = 0;  // Ptr
    size_t sizeof_obj() const override { return 8; }
    std::vector<uint8_t> get_bytes() const override {
        std::vector<uint8_t> b(8);
        speakeasy::write_le(b, 0, Urb, 8);
        return b;
    }
};

struct _WDF_USB_DEVICE_SELECT_CONFIG_PARAMS_SingleInterface : speakeasy::EmuStruct {
    uint8_t  NumberConfiguredPipes = 0;
    uint8_t  __pad0[7]            = {};
    uint64_t ConfiguredUsbInterface = 0;

    size_t sizeof_obj() const override { return 16; }
    std::vector<uint8_t> get_bytes() const override {
        std::vector<uint8_t> b(16, 0);
        speakeasy::write_le(b, 0, NumberConfiguredPipes, 1);
        speakeasy::write_le(b, 8, ConfiguredUsbInterface, 8);
        return b;
    }
};

struct _WDF_USB_DEVICE_SELECT_CONFIG_PARAMS_MultiInterface : speakeasy::EmuStruct {
    uint8_t  NumberInterfaces                = 0;
    uint8_t  __pad0[7]                      = {};
    uint64_t Pairs                           = 0;
    uint8_t  NumberOfConfiguredInterfaces    = 0;
    uint8_t  __pad1[7]                      = {};

    size_t sizeof_obj() const override { return 24; }
    std::vector<uint8_t> get_bytes() const override {
        std::vector<uint8_t> b(24, 0);
        speakeasy::write_le(b, 0, NumberInterfaces, 1);
        speakeasy::write_le(b, 8, Pairs, 8);
        speakeasy::write_le(b, 16, NumberOfConfiguredInterfaces, 1);
        return b;
    }
};

struct WDF_USB_DEVICE_SELECT_CONFIG_PARAMS : speakeasy::EmuStruct {
    uint32_t Size = 0;
    uint32_t Type = 0;
    // Union Types, largest member is Descriptor (24 bytes)
    uint64_t Types_Descriptor_conf_desc  = 0;
    uint64_t Types_Descriptor_intf_desc  = 0;
    uint32_t Types_Descriptor_num_intf   = 0;
    uint32_t __pad0                      = 0;

    size_t sizeof_obj() const override { return 4 + 4 + 24; }
    std::vector<uint8_t> get_bytes() const override {
        size_t sz = sizeof_obj();
        std::vector<uint8_t> b(sz, 0);
        speakeasy::write_le(b, 0, Size, 4);
        speakeasy::write_le(b, 4, Type, 4);
        speakeasy::write_le(b, 8, Types_Descriptor_conf_desc, 8);
        speakeasy::write_le(b, 16, Types_Descriptor_intf_desc, 8);
        speakeasy::write_le(b, 24, Types_Descriptor_num_intf, 4);
        return b;
    }
};

//  WDF_IO_QUEUE_CONFIG 
struct WDF_IO_QUEUE_CONFIG : speakeasy::EmuStruct {
    uint32_t Size                    = 0;
    uint32_t __pad0                  = 0;
    uint64_t DispatchType            = 0;  // Ptr
    uint64_t PowerManaged            = 0;  // Ptr
    uint8_t  AllowZeroLengthRequests = 0;
    uint8_t  DefaultQueue            = 0;
    uint8_t  __pad1[6]              = {};
    uint64_t EvtIoDefault            = 0;
    uint64_t EvtIoRead               = 0;
    uint64_t EvtIoWrite              = 0;
    uint64_t EvtIoDeviceControl      = 0;
    uint64_t EvtIoInternalDeviceControl = 0;
    uint64_t EvtIoStop               = 0;
    uint64_t EvtIoResume             = 0;
    uint64_t EvtIoCanceledOnQueue    = 0;
    uint32_t NumberOfPresentedRequests = 0;
    uint32_t __pad2                  = 0;
    uint64_t Driver                  = 0;

    size_t sizeof_obj() const override {
        return 4 + 4 + 8 + 8 + 1 + 1 + 6 + 8 + 8 + 8 + 8 + 8 + 8 + 8 + 8 + 4 + 4 + 8;
    }
    std::vector<uint8_t> get_bytes() const override {
        size_t sz = sizeof_obj();
        std::vector<uint8_t> b(sz, 0);
        size_t off = 0;
        speakeasy::write_le(b, off, Size, 4); off += 8;
        speakeasy::write_le(b, off, DispatchType, 8); off += 8;
        speakeasy::write_le(b, off, PowerManaged, 8); off += 8;
        speakeasy::write_le(b, off, AllowZeroLengthRequests, 1); off += 1;
        speakeasy::write_le(b, off, DefaultQueue, 1); off += 7; // +6 pad
        speakeasy::write_le(b, off, EvtIoDefault, 8); off += 8;
        speakeasy::write_le(b, off, EvtIoRead, 8); off += 8;
        speakeasy::write_le(b, off, EvtIoWrite, 8); off += 8;
        speakeasy::write_le(b, off, EvtIoDeviceControl, 8); off += 8;
        speakeasy::write_le(b, off, EvtIoInternalDeviceControl, 8); off += 8;
        speakeasy::write_le(b, off, EvtIoStop, 8); off += 8;
        speakeasy::write_le(b, off, EvtIoResume, 8); off += 8;
        speakeasy::write_le(b, off, EvtIoCanceledOnQueue, 8); off += 8;
        speakeasy::write_le(b, off, NumberOfPresentedRequests, 4); off += 8;
        speakeasy::write_le(b, off, Driver, 8); off += 8;
        return b;
    }
};

//  WDFFUNCTIONS (function table) 
//
// WDF function dispatch table. All entries are 8-byte pointers.
// Total field count: 422 = 422 pointers  8 bytes = 3376 bytes.
//
struct WDFFUNCTIONS : speakeasy::EmuStruct {
    enum : size_t { FIELD_COUNT = 422 };

    uint64_t fields[FIELD_COUNT] = {};

    // Named index constants for the function table
    enum Idx : size_t {
        kPfnWdfChildListCreate = 0,
        kPfnWdfChildListGetDevice,
        kPfnWdfChildListRetrievePdo,
        kPfnWdfChildListRetrieveAddressDescription,
        kPfnWdfChildListBeginScan,
        kPfnWdfChildListEndScan,
        kPfnWdfChildListBeginIteration,
        kPfnWdfChildListRetrieveNextDevice,
        kPfnWdfChildListEndIteration,
        kPfnWdfChildListAddOrUpdateChildDescriptionAsPresent,
        kPfnWdfChildListUpdateChildDescriptionAsMissing,
        kPfnWdfChildListUpdateAllChildDescriptionsAsPresent,
        kPfnWdfChildListRequestChildEject,
        kPfnWdfCollectionCreate,
        kPfnWdfCollectionGetCount,
        kPfnWdfCollectionAdd,
        kPfnWdfCollectionRemove,
        kPfnWdfCollectionRemoveItem,
        kPfnWdfCollectionGetItem,
        kPfnWdfCollectionGetFirstItem,
        kPfnWdfCollectionGetLastItem,
        kPfnWdfCommonBufferCreate,
        kPfnWdfCommonBufferGetAlignedVirtualAddress,
        kPfnWdfCommonBufferGetAlignedLogicalAddress,
        kPfnWdfCommonBufferGetLength,
        kPfnWdfControlDeviceInitAllocate,
        kPfnWdfControlDeviceInitSetShutdownNotification,
        kPfnWdfControlFinishInitializing,
        kPfnWdfDeviceGetDeviceState,
        kPfnWdfDeviceSetDeviceState,
        kPfnWdfWdmDeviceGetWdfDeviceHandle,
        kPfnWdfDeviceWdmGetDeviceObject,
        kPfnWdfDeviceWdmGetAttachedDevice,
        kPfnWdfDeviceWdmGetPhysicalDevice,
        kPfnWdfDeviceWdmDispatchPreprocessedIrp,
        kPfnWdfDeviceAddDependentUsageDeviceObject,
        kPfnWdfDeviceAddRemovalRelationsPhysicalDevice,
        kPfnWdfDeviceRemoveRemovalRelationsPhysicalDevice,
        kPfnWdfDeviceClearRemovalRelationsDevices,
        kPfnWdfDeviceGetDriver,
        kPfnWdfDeviceRetrieveDeviceName,
        kPfnWdfDeviceAssignMofResourceName,
        kPfnWdfDeviceGetIoTarget,
        kPfnWdfDeviceGetDevicePnpState,
        kPfnWdfDeviceGetDevicePowerState,
        kPfnWdfDeviceGetDevicePowerPolicyState,
        kPfnWdfDeviceAssignS0IdleSettings,
        kPfnWdfDeviceAssignSxWakeSettings,
        kPfnWdfDeviceOpenRegistryKey,
        kPfnWdfDeviceSetSpecialFileSupport,
        kPfnWdfDeviceSetCharacteristics,
        kPfnWdfDeviceGetCharacteristics,
        kPfnWdfDeviceGetAlignmentRequirement,
        kPfnWdfDeviceSetAlignmentRequirement,
        kPfnWdfDeviceInitFree,
        kPfnWdfDeviceInitSetPnpPowerEventCallbacks,
        kPfnWdfDeviceInitSetPowerPolicyEventCallbacks,
        kPfnWdfDeviceInitSetPowerPolicyOwnership,
        kPfnWdfDeviceInitRegisterPnpStateChangeCallback,
        kPfnWdfDeviceInitRegisterPowerStateChangeCallback,
        kPfnWdfDeviceInitRegisterPowerPolicyStateChangeCallback,
        kPfnWdfDeviceInitSetIoType,
        kPfnWdfDeviceInitSetExclusive,
        kPfnWdfDeviceInitSetPowerNotPageable,
        kPfnWdfDeviceInitSetPowerPageable,
        kPfnWdfDeviceInitSetPowerInrush,
        kPfnWdfDeviceInitSetDeviceType,
        kPfnWdfDeviceInitAssignName,
        kPfnWdfDeviceInitAssignSDDLString,
        kPfnWdfDeviceInitSetDeviceClass,
        kPfnWdfDeviceInitSetCharacteristics,
        kPfnWdfDeviceInitSetFileObjectConfig,
        kPfnWdfDeviceInitSetRequestAttributes,
        kPfnWdfDeviceInitAssignWdmIrpPreprocessCallback,
        kPfnWdfDeviceInitSetIoInCallerContextCallback,
        kPfnWdfDeviceCreate,
        kPfnWdfDeviceSetStaticStopRemove,
        kPfnWdfDeviceCreateDeviceInterface,
        kPfnWdfDeviceSetDeviceInterfaceState,
        kPfnWdfDeviceRetrieveDeviceInterfaceString,
        kPfnWdfDeviceCreateSymbolicLink,
        kPfnWdfDeviceQueryProperty,
        kPfnWdfDeviceAllocAndQueryProperty,
        kPfnWdfDeviceSetPnpCapabilities,
        kPfnWdfDeviceSetPowerCapabilities,
        kPfnWdfDeviceSetBusInformationForChildren,
        kPfnWdfDeviceIndicateWakeStatus,
        kPfnWdfDeviceSetFailed,
        kPfnWdfDeviceStopIdleNoTrack,
        kPfnWdfDeviceResumeIdleNoTrack,
        kPfnWdfDeviceGetFileObject,
        kPfnWdfDeviceEnqueueRequest,
        kPfnWdfDeviceGetDefaultQueue,
        kPfnWdfDeviceConfigureRequestDispatching,
        kPfnWdfDmaEnablerCreate,
        kPfnWdfDmaEnablerGetMaximumLength,
        kPfnWdfDmaEnablerGetMaximumScatterGatherElements,
        kPfnWdfDmaEnablerSetMaximumScatterGatherElements,
        kPfnWdfDmaTransactionCreate,
        kPfnWdfDmaTransactionInitialize,
        kPfnWdfDmaTransactionInitializeUsingRequest,
        kPfnWdfDmaTransactionExecute,
        kPfnWdfDmaTransactionRelease,
        kPfnWdfDmaTransactionDmaCompleted,
        kPfnWdfDmaTransactionDmaCompletedWithLength,
        kPfnWdfDmaTransactionDmaCompletedFinal,
        kPfnWdfDmaTransactionGetBytesTransferred,
        kPfnWdfDmaTransactionSetMaximumLength,
        kPfnWdfDmaTransactionGetRequest,
        kPfnWdfDmaTransactionGetCurrentDmaTransferLength,
        kPfnWdfDmaTransactionGetDevice,
        kPfnWdfDpcCreate,
        kPfnWdfDpcEnqueue,
        kPfnWdfDpcCancel,
        kPfnWdfDpcGetParentObject,
        kPfnWdfDpcWdmGetDpc,
        kPfnWdfDriverCreate,
        kPfnWdfDriverGetRegistryPath,
        kPfnWdfDriverWdmGetDriverObject,
        kPfnWdfDriverOpenParametersRegistryKey,
        kPfnWdfWdmDriverGetWdfDriverHandle,
        kPfnWdfDriverRegisterTraceInfo,
        kPfnWdfDriverRetrieveVersionString,
        kPfnWdfDriverIsVersionAvailable,
        kPfnWdfFdoInitWdmGetPhysicalDevice,
        kPfnWdfFdoInitOpenRegistryKey,
        kPfnWdfFdoInitQueryProperty,
        kPfnWdfFdoInitAllocAndQueryProperty,
        kPfnWdfFdoInitSetEventCallbacks,
        kPfnWdfFdoInitSetFilter,
        kPfnWdfFdoInitSetDefaultChildListConfig,
        kPfnWdfFdoQueryForInterface,
        kPfnWdfFdoGetDefaultChildList,
        kPfnWdfFdoAddStaticChild,
        kPfnWdfFdoLockStaticChildListForIteration,
        kPfnWdfFdoRetrieveNextStaticChild,
        kPfnWdfFdoUnlockStaticChildListFromIteration,
        kPfnWdfFileObjectGetFileName,
        kPfnWdfFileObjectGetFlags,
        kPfnWdfFileObjectGetDevice,
        kPfnWdfFileObjectWdmGetFileObject,
        kPfnWdfInterruptCreate,
        kPfnWdfInterruptQueueDpcForIsr,
        kPfnWdfInterruptSynchronize,
        kPfnWdfInterruptAcquireLock,
        kPfnWdfInterruptReleaseLock,
        kPfnWdfInterruptEnable,
        kPfnWdfInterruptDisable,
        kPfnWdfInterruptWdmGetInterrupt,
        kPfnWdfInterruptGetInfo,
        kPfnWdfInterruptSetPolicy,
        kPfnWdfInterruptGetDevice,
        kPfnWdfIoQueueCreate,
        kPfnWdfIoQueueGetState,
        kPfnWdfIoQueueStart,
        kPfnWdfIoQueueStop,
        kPfnWdfIoQueueStopSynchronously,
        kPfnWdfIoQueueGetDevice,
        kPfnWdfIoQueueRetrieveNextRequest,
        kPfnWdfIoQueueRetrieveRequestByFileObject,
        kPfnWdfIoQueueFindRequest,
        kPfnWdfIoQueueRetrieveFoundRequest,
        kPfnWdfIoQueueDrainSynchronously,
        kPfnWdfIoQueueDrain,
        kPfnWdfIoQueuePurgeSynchronously,
        kPfnWdfIoQueuePurge,
        kPfnWdfIoQueueReadyNotify,
        kPfnWdfIoTargetCreate,
        kPfnWdfIoTargetOpen,
        kPfnWdfIoTargetCloseForQueryRemove,
        kPfnWdfIoTargetClose,
        kPfnWdfIoTargetStart,
        kPfnWdfIoTargetStop,
        kPfnWdfIoTargetGetState,
        kPfnWdfIoTargetGetDevice,
        kPfnWdfIoTargetQueryTargetProperty,
        kPfnWdfIoTargetAllocAndQueryTargetProperty,
        kPfnWdfIoTargetQueryForInterface,
        kPfnWdfIoTargetWdmGetTargetDeviceObject,
        kPfnWdfIoTargetWdmGetTargetPhysicalDevice,
        kPfnWdfIoTargetWdmGetTargetFileObject,
        kPfnWdfIoTargetWdmGetTargetFileHandle,
        kPfnWdfIoTargetSendReadSynchronously,
        kPfnWdfIoTargetFormatRequestForRead,
        kPfnWdfIoTargetSendWriteSynchronously,
        kPfnWdfIoTargetFormatRequestForWrite,
        kPfnWdfIoTargetSendIoctlSynchronously,
        kPfnWdfIoTargetFormatRequestForIoctl,
        kPfnWdfIoTargetSendInternalIoctlSynchronously,
        kPfnWdfIoTargetFormatRequestForInternalIoctl,
        kPfnWdfIoTargetSendInternalIoctlOthersSynchronously,
        kPfnWdfIoTargetFormatRequestForInternalIoctlOthers,
        kPfnWdfMemoryCreate,
        kPfnWdfMemoryCreatePreallocated,
        kPfnWdfMemoryGetBuffer,
        kPfnWdfMemoryAssignBuffer,
        kPfnWdfMemoryCopyToBuffer,
        kPfnWdfMemoryCopyFromBuffer,
        kPfnWdfLookasideListCreate,
        kPfnWdfMemoryCreateFromLookaside,
        kPfnWdfDeviceMiniportCreate,
        kPfnWdfDriverMiniportUnload,
        kPfnWdfObjectGetTypedContextWorker,
        kPfnWdfObjectAllocateContext,
        kPfnWdfObjectContextGetObject,
        kPfnWdfObjectReferenceActual,
        kPfnWdfObjectDereferenceActual,
        kPfnWdfObjectCreate,
        kPfnWdfObjectDelete,
        kPfnWdfObjectQuery,
        kPfnWdfPdoInitAllocate,
        kPfnWdfPdoInitSetEventCallbacks,
        kPfnWdfPdoInitAssignDeviceID,
        kPfnWdfPdoInitAssignInstanceID,
        kPfnWdfPdoInitAddHardwareID,
        kPfnWdfPdoInitAddCompatibleID,
        kPfnWdfPdoInitAddDeviceText,
        kPfnWdfPdoInitSetDefaultLocale,
        kPfnWdfPdoInitAssignRawDevice,
        kPfnWdfPdoMarkMissing,
        kPfnWdfPdoRequestEject,
        kPfnWdfPdoGetParent,
        kPfnWdfPdoRetrieveIdentificationDescription,
        kPfnWdfPdoRetrieveAddressDescription,
        kPfnWdfPdoUpdateAddressDescription,
        kPfnWdfPdoAddEjectionRelationsPhysicalDevice,
        kPfnWdfPdoRemoveEjectionRelationsPhysicalDevice,
        kPfnWdfPdoClearEjectionRelationsDevices,
        kPfnWdfDeviceAddQueryInterface,
        kPfnWdfRegistryOpenKey,
        kPfnWdfRegistryCreateKey,
        kPfnWdfRegistryClose,
        kPfnWdfRegistryWdmGetHandle,
        kPfnWdfRegistryRemoveKey,
        kPfnWdfRegistryRemoveValue,
        kPfnWdfRegistryQueryValue,
        kPfnWdfRegistryQueryMemory,
        kPfnWdfRegistryQueryMultiString,
        kPfnWdfRegistryQueryUnicodeString,
        kPfnWdfRegistryQueryString,
        kPfnWdfRegistryQueryULong,
        kPfnWdfRegistryAssignValue,
        kPfnWdfRegistryAssignMemory,
        kPfnWdfRegistryAssignMultiString,
        kPfnWdfRegistryAssignUnicodeString,
        kPfnWdfRegistryAssignString,
        kPfnWdfRegistryAssignULong,
        kPfnWdfRequestCreate,
        kPfnWdfRequestCreateFromIrp,
        kPfnWdfRequestReuse,
        kPfnWdfRequestChangeTarget,
        kPfnWdfRequestFormatRequestUsingCurrentType,
        kPfnWdfRequestWdmFormatUsingStackLocation,
        kPfnWdfRequestSend,
        kPfnWdfRequestGetStatus,
        kPfnWdfRequestMarkCancelable,
        kPfnWdfRequestUnmarkCancelable,
        kPfnWdfRequestIsCanceled,
        kPfnWdfRequestCancelSentRequest,
        kPfnWdfRequestIsFrom32BitProcess,
        kPfnWdfRequestSetCompletionRoutine,
        kPfnWdfRequestGetCompletionParams,
        kPfnWdfRequestAllocateTimer,
        kPfnWdfRequestComplete,
        kPfnWdfRequestCompleteWithPriorityBoost,
        kPfnWdfRequestCompleteWithInformation,
        kPfnWdfRequestGetParameters,
        kPfnWdfRequestRetrieveInputMemory,
        kPfnWdfRequestRetrieveOutputMemory,
        kPfnWdfRequestRetrieveInputBuffer,
        kPfnWdfRequestRetrieveOutputBuffer,
        kPfnWdfRequestRetrieveInputWdmMdl,
        kPfnWdfRequestRetrieveOutputWdmMdl,
        kPfnWdfRequestRetrieveUnsafeUserInputBuffer,
        kPfnWdfRequestRetrieveUnsafeUserOutputBuffer,
        kPfnWdfRequestSetInformation,
        kPfnWdfRequestGetInformation,
        kPfnWdfRequestGetFileObject,
        kPfnWdfRequestProbeAndLockUserBufferForRead,
        kPfnWdfRequestProbeAndLockUserBufferForWrite,
        kPfnWdfRequestGetRequestorMode,
        kPfnWdfRequestForwardToIoQueue,
        kPfnWdfRequestGetIoQueue,
        kPfnWdfRequestRequeue,
        kPfnWdfRequestStopAcknowledge,
        kPfnWdfRequestWdmGetIrp,
        kPfnWdfIoResourceRequirementsListSetSlotNumber,
        kPfnWdfIoResourceRequirementsListSetInterfaceType,
        kPfnWdfIoResourceRequirementsListAppendIoResList,
        kPfnWdfIoResourceRequirementsListInsertIoResList,
        kPfnWdfIoResourceRequirementsListGetCount,
        kPfnWdfIoResourceRequirementsListGetIoResList,
        kPfnWdfIoResourceRequirementsListRemove,
        kPfnWdfIoResourceRequirementsListRemoveByIoResList,
        kPfnWdfIoResourceListCreate,
        kPfnWdfIoResourceListAppendDescriptor,
        kPfnWdfIoResourceListInsertDescriptor,
        kPfnWdfIoResourceListUpdateDescriptor,
        kPfnWdfIoResourceListGetCount,
        kPfnWdfIoResourceListGetDescriptor,
        kPfnWdfIoResourceListRemove,
        kPfnWdfIoResourceListRemoveByDescriptor,
        kPfnWdfCmResourceListAppendDescriptor,
        kPfnWdfCmResourceListInsertDescriptor,
        kPfnWdfCmResourceListGetCount,
        kPfnWdfCmResourceListGetDescriptor,
        kPfnWdfCmResourceListRemove,
        kPfnWdfCmResourceListRemoveByDescriptor,
        kPfnWdfStringCreate,
        kPfnWdfStringGetUnicodeString,
        kPfnWdfObjectAcquireLock,
        kPfnWdfObjectReleaseLock,
        kPfnWdfWaitLockCreate,
        kPfnWdfWaitLockAcquire,
        kPfnWdfWaitLockRelease,
        kPfnWdfSpinLockCreate,
        kPfnWdfSpinLockAcquire,
        kPfnWdfSpinLockRelease,
        kPfnWdfTimerCreate,
        kPfnWdfTimerStart,
        kPfnWdfTimerStop,
        kPfnWdfTimerGetParentObject,
        kPfnWdfUsbTargetDeviceCreate,
        kPfnWdfUsbTargetDeviceRetrieveInformation,
        kPfnWdfUsbTargetDeviceGetDeviceDescriptor,
        kPfnWdfUsbTargetDeviceRetrieveConfigDescriptor,
        kPfnWdfUsbTargetDeviceQueryString,
        kPfnWdfUsbTargetDeviceAllocAndQueryString,
        kPfnWdfUsbTargetDeviceFormatRequestForString,
        kPfnWdfUsbTargetDeviceGetNumInterfaces,
        kPfnWdfUsbTargetDeviceSelectConfig,
        kPfnWdfUsbTargetDeviceWdmGetConfigurationHandle,
        kPfnWdfUsbTargetDeviceRetrieveCurrentFrameNumber,
        kPfnWdfUsbTargetDeviceSendControlTransferSynchronously,
        kPfnWdfUsbTargetDeviceFormatRequestForControlTransfer,
        kPfnWdfUsbTargetDeviceIsConnectedSynchronous,
        kPfnWdfUsbTargetDeviceResetPortSynchronously,
        kPfnWdfUsbTargetDeviceCyclePortSynchronously,
        kPfnWdfUsbTargetDeviceFormatRequestForCyclePort,
        kPfnWdfUsbTargetDeviceSendUrbSynchronously,
        kPfnWdfUsbTargetDeviceFormatRequestForUrb,
        kPfnWdfUsbTargetPipeGetInformation,
        kPfnWdfUsbTargetPipeIsInEndpoint,
        kPfnWdfUsbTargetPipeIsOutEndpoint,
        kPfnWdfUsbTargetPipeGetType,
        kPfnWdfUsbTargetPipeSetNoMaximumPacketSizeCheck,
        kPfnWdfUsbTargetPipeWriteSynchronously,
        kPfnWdfUsbTargetPipeFormatRequestForWrite,
        kPfnWdfUsbTargetPipeReadSynchronously,
        kPfnWdfUsbTargetPipeFormatRequestForRead,
        kPfnWdfUsbTargetPipeConfigContinuousReader,
        kPfnWdfUsbTargetPipeAbortSynchronously,
        kPfnWdfUsbTargetPipeFormatRequestForAbort,
        kPfnWdfUsbTargetPipeResetSynchronously,
        kPfnWdfUsbTargetPipeFormatRequestForReset,
        kPfnWdfUsbTargetPipeSendUrbSynchronously,
        kPfnWdfUsbTargetPipeFormatRequestForUrb,
        kPfnWdfUsbInterfaceGetInterfaceNumber,
        kPfnWdfUsbInterfaceGetNumEndpoints,
        kPfnWdfUsbInterfaceGetDescriptor,
        kPfnWdfUsbInterfaceSelectSetting,
        kPfnWdfUsbInterfaceGetEndpointInformation,
        kPfnWdfUsbTargetDeviceGetInterface,
        kPfnWdfUsbInterfaceGetConfiguredSettingIndex,
        kPfnWdfUsbInterfaceGetNumConfiguredPipes,
        kPfnWdfUsbInterfaceGetConfiguredPipe,
        kPfnWdfUsbTargetPipeWdmGetPipeHandle,
        kPfnWdfVerifierDbgBreakPoint,
        kPfnWdfVerifierKeBugCheck,
        kPfnWdfWmiProviderCreate,
        kPfnWdfWmiProviderGetDevice,
        kPfnWdfWmiProviderIsEnabled,
        kPfnWdfWmiProviderGetTracingHandle,
        kUnknown0_First,
        kUnknown0_Last = kUnknown0_First + 12,
        kPfnWdfUsbInterfaceGetNumSettings,
        kUnknown1_First,
        kUnknown1_Last = kUnknown1_First + 33,
        kPfnWdfUsbTargetDeviceCreateWithParameters,
        kCount
    };
    static_assert(kCount == FIELD_COUNT, "WDFFUNCTIONS field count mismatch");

    size_t sizeof_obj() const override { return FIELD_COUNT * 8; }

    std::vector<uint8_t> get_bytes() const override {
        std::vector<uint8_t> b(FIELD_COUNT * 8, 0);
        for (size_t i = 0; i < FIELD_COUNT; i++)
            speakeasy::write_le(b, i * 8, fields[i], 8);
        return b;
    }
};

}} // namespace speakeasy::defs

#endif // SPEAKEASY_DEFS_WDF_H
