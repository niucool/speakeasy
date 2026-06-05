// usb.h  USB type definitions (new EmuStructHelper CRTP)
//
// Maps to: speakeasy/winenv/defs/usb.py
//
// Uses the new EmuStructHelper CRTP approach for auto serialize/deserialize.
// All structs use #pragma pack(push, 1) with explicit padding fields to match
// the sizeof() that Python ctypes (natural C ABI alignment) would produce.
//
// NOTE: USB_DEVICE_DESCRIPTOR is defined below.

#ifndef SPEAKEASY_DEFS_NEW_USB_H
#define SPEAKEASY_DEFS_NEW_USB_H

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include "struct.h"

namespace speakeasy { namespace defs { namespace new_structs {

#pragma pack(push, 1)

// ==========================================================================================================
// USB Device Descriptor type constants
// ==========================================================================================================
constexpr uint8_t kUsbDeviceDescriptorType         = 0x01;
constexpr uint8_t kUsbConfigurationDescriptorType  = 0x02;
constexpr uint8_t kUsbStringDescriptorType         = 0x03;
constexpr uint8_t kUsbInterfaceDescriptorType      = 0x04;
constexpr uint8_t kUsbEndpointDescriptorType       = 0x05;

constexpr uint8_t kUsbEndpointTypeMask        = 0x03;
constexpr uint8_t kUsbEndpointTypeControl     = 0x00;
constexpr uint8_t kUsbEndpointTypeIsochronous = 0x01;
constexpr uint8_t kUsbEndpointTypeBulk        = 0x02;
constexpr uint8_t kUsbEndpointTypeInterrupt   = 0x03;

constexpr uint8_t kUsbDirIn  = 0x80;
constexpr uint8_t kUsbDirOut = 0x00;

// ==========================================================================================================
// USB_DEVICE_DESCRIPTOR: 14 fields, 18 bytes
//   u8+u8+u16+u8+u8+u8+u8+u16+u16+u16+u8+u8+u8+u8 = 1+1+2+1+1+1+1+2+2+2+1+1+1+1 = 18
// ==========================================================================================================
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

// USB_DEVICE_DESCRIPTOR is defined above

// ==========================================================================================================
// USB_CONFIGURATION_DESCRIPTOR: u8+u8+u16+u8+u8+u8+u8+u8 = 9
// ==========================================================================================================
struct USB_CONFIGURATION_DESCRIPTOR_POD {
    uint8_t  bLength             = 0;   // offset 0
    uint8_t  bDescriptorType     = 0;   // offset 1
    uint16_t wTotalLength        = 0;   // offset 2
    uint8_t  bNumInterfaces      = 0;   // offset 4
    uint8_t  bConfigurationValue = 0;   // offset 5
    uint8_t  iConfiguration      = 0;   // offset 6
    uint8_t  bmAttributes        = 0;   // offset 7
    uint8_t  MaxPower            = 0;   // offset 8
    // total = 9
};

struct USB_CONFIGURATION_DESCRIPTOR
    : public EmuStructHelper<USB_CONFIGURATION_DESCRIPTOR>,
      public USB_CONFIGURATION_DESCRIPTOR_POD {
    std::string get_mem_tag() const override { return "usb_configuration_descriptor"; }
};

// ==========================================================================================================
// USB_INTERFACE_DESCRIPTOR: u8+u8+u8+u8+u8+u8+u8+u8+u8 = 9
// ==========================================================================================================
struct USB_INTERFACE_DESCRIPTOR_POD {
    uint8_t bLength             = 0;   // offset 0
    uint8_t bDescriptorType     = 0;   // offset 1
    uint8_t bInterfaceNumber    = 0;   // offset 2
    uint8_t bAlternateSetting   = 0;   // offset 3
    uint8_t bNumEndpoints       = 0;   // offset 4
    uint8_t bInterfaceClass     = 0;   // offset 5
    uint8_t bInterfaceSubClass  = 0;   // offset 6
    uint8_t bInterfaceProtocol  = 0;   // offset 7
    uint8_t iInterface          = 0;   // offset 8
    // total = 9
};

struct USB_INTERFACE_DESCRIPTOR
    : public EmuStructHelper<USB_INTERFACE_DESCRIPTOR>,
      public USB_INTERFACE_DESCRIPTOR_POD {
    std::string get_mem_tag() const override { return "usb_interface_descriptor"; }
};

// ==========================================================================================================
// USB_ENDPOINT_DESCRIPTOR: u8+u8+u8+u8+u16+u8 = 8 (u16 at offset 4, total 8)
//   bLength(1)+bDescriptorType(1)+bEndpointAddress(1)+bmAttributes(1)+wMaxPacketSize(2)+bInterval(1)
//   = 7 bytes... but actually:
//   uint8+uint8+uint8+uint8+uint16+uint8 = 1+1+1+1+2+1 = 7
//   With natural alignment: bEndpointAddress(1)@2, bmAttributes(1)@3, wMaxPacketSize(2)@4
//   bInterval(1)@6 = 7... with 7 you'd have padding to 8 for natural alignment
//   Actually in ctypes, packing is by default natural C alignment.
//   So sizeof would be: bLength(1)+bDescriptorType(1)+bEndpointAddress(1)+bmAttributes(1)=4
//   wMaxPacketSize(2)=6, bInterval(1)=7, then padding(1) to align to largest member alignment (2) = 8
// ==========================================================================================================
struct USB_ENDPOINT_DESCRIPTOR_POD {
    uint8_t  bLength            = 0;   // offset 0
    uint8_t  bDescriptorType    = 0;   // offset 1
    uint8_t  bEndpointAddress   = 0;   // offset 2
    uint8_t  bmAttributes       = 0;   // offset 3
    uint16_t wMaxPacketSize     = 0;   // offset 4
    uint8_t  bInterval          = 0;   // offset 6
    uint8_t  pad                = 0;   // offset 7 → natural alignment pad to 8
    // total = 8
};

struct USB_ENDPOINT_DESCRIPTOR
    : public EmuStructHelper<USB_ENDPOINT_DESCRIPTOR>,
      public USB_ENDPOINT_DESCRIPTOR_POD {
    std::string get_mem_tag() const override { return "usb_endpoint_descriptor"; }
};

// ==========================================================================================================
// USBD_VERSION_INFORMATION: u32+u32 = 8 (no pointer fields, ptr_size unused for layout)
// ==========================================================================================================
struct USBD_VERSION_INFORMATION_POD {
    uint32_t USBDI_Version           = 0;   // offset 0
    uint32_t Supported_USB_Version   = 0;   // offset 4
    // total = 8
};

struct USBD_VERSION_INFORMATION
    : public EmuStructHelper<USBD_VERSION_INFORMATION>,
      public USBD_VERSION_INFORMATION_POD {
    std::string get_mem_tag() const override { return "usbd_version_information"; }
};

#pragma pack(pop)

}}} // namespace speakeasy::defs::new_structs

#endif // SPEAKEASY_DEFS_NEW_USB_H
