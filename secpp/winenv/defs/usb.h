// usb.h  Universal Serial Bus type definitions
//
// Maps to: speakeasy/winenv/defs/usb.py
//
// USB descriptor structures and constants used by USB device
// emulation and KMDF USB target API handlers.

#ifndef SPEAKEASY_DEFS_USB_H
#define SPEAKEASY_DEFS_USB_H

#include <cstdint>
#include <vector>
#include "../../struct.h"

namespace speakeasy { namespace defs {

//  USB descriptor type constants 
constexpr uint32_t USB_DEVICE_DESCRIPTOR_TYPE        = 0x01;
constexpr uint32_t USB_CONFIGURATION_DESCRIPTOR_TYPE = 0x02;
constexpr uint32_t USB_STRING_DESCRIPTOR_TYPE        = 0x03;
constexpr uint32_t USB_INTERFACE_DESCRIPTOR_TYPE     = 0x04;
constexpr uint32_t USB_ENDPOINT_DESCRIPTOR_TYPE      = 0x05;

//  USB endpoint types 
constexpr uint32_t USB_ENDPOINT_TYPE_MASK       = 0x03;
constexpr uint32_t USB_ENDPOINT_TYPE_CONTROL     = 0x00;
constexpr uint32_t USB_ENDPOINT_TYPE_ISOCHRONOUS = 0x01;
constexpr uint32_t USB_ENDPOINT_TYPE_BULK        = 0x02;
constexpr uint32_t USB_ENDPOINT_TYPE_INTERRUPT   = 0x03;

//  USB direction bits 
constexpr uint32_t USB_DIR_IN  = 0x80;
constexpr uint32_t USB_DIR_OUT = 0x00;

//  USB_DEVICE_DESCRIPTOR (18 bytes) 
struct USB_DEVICE_DESCRIPTOR : speakeasy::EmuStruct {
    uint8_t  bLength            = 0;  // offset  0
    uint8_t  bDescriptorType    = 0;  // offset  1
    uint16_t bcdUSB             = 0;  // offset  2
    uint8_t  bDeviceClass       = 0;  // offset  4
    uint8_t  bDeviceSubClass    = 0;  // offset  5
    uint8_t  bDeviceProtocol    = 0;  // offset  6
    uint8_t  bMaxPacketSize0    = 0;  // offset  7
    uint16_t idVendor           = 0;  // offset  8
    uint16_t idProduct          = 0;  // offset 10
    uint16_t bcdDevice          = 0;  // offset 12
    uint8_t  iManufacturer      = 0;  // offset 14
    uint8_t  iProduct           = 0;  // offset 15
    uint8_t  iSerialNumber      = 0;  // offset 16
    uint8_t  bNumConfigurations = 0;  // offset 17

    size_t sizeof_obj() const override { return 18; }

    std::vector<uint8_t> get_bytes() const override {
        std::vector<uint8_t> b(18);
        speakeasy::write_le(b,  0, bLength,            1);
        speakeasy::write_le(b,  1, bDescriptorType,    1);
        speakeasy::write_le(b,  2, bcdUSB,             2);
        speakeasy::write_le(b,  4, bDeviceClass,       1);
        speakeasy::write_le(b,  5, bDeviceSubClass,    1);
        speakeasy::write_le(b,  6, bDeviceProtocol,    1);
        speakeasy::write_le(b,  7, bMaxPacketSize0,    1);
        speakeasy::write_le(b,  8, idVendor,           2);
        speakeasy::write_le(b, 10, idProduct,          2);
        speakeasy::write_le(b, 12, bcdDevice,          2);
        speakeasy::write_le(b, 14, iManufacturer,      1);
        speakeasy::write_le(b, 15, iProduct,           1);
        speakeasy::write_le(b, 16, iSerialNumber,      1);
        speakeasy::write_le(b, 17, bNumConfigurations, 1);
        return b;
    }
};

//  USB_CONFIGURATION_DESCRIPTOR (9 bytes) 
struct USB_CONFIGURATION_DESCRIPTOR : speakeasy::EmuStruct {
    uint8_t  bLength             = 0;  // offset 0
    uint8_t  bDescriptorType     = 0;  // offset 1
    uint16_t wTotalLength        = 0;  // offset 2
    uint8_t  bNumInterfaces      = 0;  // offset 4
    uint8_t  bConfigurationValue = 0;  // offset 5
    uint8_t  iConfiguration      = 0;  // offset 6
    uint8_t  bmAttributes        = 0;  // offset 7
    uint8_t  MaxPower            = 0;  // offset 8

    size_t sizeof_obj() const override { return 9; }

    std::vector<uint8_t> get_bytes() const override {
        std::vector<uint8_t> b(9);
        speakeasy::write_le(b, 0, bLength,             1);
        speakeasy::write_le(b, 1, bDescriptorType,     1);
        speakeasy::write_le(b, 2, wTotalLength,        2);
        speakeasy::write_le(b, 4, bNumInterfaces,      1);
        speakeasy::write_le(b, 5, bConfigurationValue, 1);
        speakeasy::write_le(b, 6, iConfiguration,      1);
        speakeasy::write_le(b, 7, bmAttributes,        1);
        speakeasy::write_le(b, 8, MaxPower,            1);
        return b;
    }
};

//  USB_INTERFACE_DESCRIPTOR (9 bytes) 
struct USB_INTERFACE_DESCRIPTOR : speakeasy::EmuStruct {
    uint8_t bLength            = 0;  // offset 0
    uint8_t bDescriptorType    = 0;  // offset 1
    uint8_t bInterfaceNumber   = 0;  // offset 2
    uint8_t bAlternateSetting  = 0;  // offset 3
    uint8_t bNumEndpoints      = 0;  // offset 4
    uint8_t bInterfaceClass    = 0;  // offset 5
    uint8_t bInterfaceSubClass = 0;  // offset 6
    uint8_t bInterfaceProtocol = 0;  // offset 7
    uint8_t iInterface         = 0;  // offset 8

    size_t sizeof_obj() const override { return 9; }

    std::vector<uint8_t> get_bytes() const override {
        std::vector<uint8_t> b(9);
        speakeasy::write_le(b, 0, bLength,            1);
        speakeasy::write_le(b, 1, bDescriptorType,    1);
        speakeasy::write_le(b, 2, bInterfaceNumber,   1);
        speakeasy::write_le(b, 3, bAlternateSetting,  1);
        speakeasy::write_le(b, 4, bNumEndpoints,      1);
        speakeasy::write_le(b, 5, bInterfaceClass,    1);
        speakeasy::write_le(b, 6, bInterfaceSubClass, 1);
        speakeasy::write_le(b, 7, bInterfaceProtocol, 1);
        speakeasy::write_le(b, 8, iInterface,         1);
        return b;
    }
};

//  USB_ENDPOINT_DESCRIPTOR (7 bytes) 
struct USB_ENDPOINT_DESCRIPTOR : speakeasy::EmuStruct {
    uint8_t  bLength          = 0;  // offset 0
    uint8_t  bDescriptorType  = 0;  // offset 1
    uint8_t  bEndpointAddress = 0;  // offset 2
    uint8_t  bmAttributes     = 0;  // offset 3
    uint16_t wMaxPacketSize   = 0;  // offset 4
    uint8_t  bInterval        = 0;  // offset 6

    size_t sizeof_obj() const override { return 7; }

    std::vector<uint8_t> get_bytes() const override {
        std::vector<uint8_t> b(7);
        speakeasy::write_le(b, 0, bLength,          1);
        speakeasy::write_le(b, 1, bDescriptorType,  1);
        speakeasy::write_le(b, 2, bEndpointAddress, 1);
        speakeasy::write_le(b, 3, bmAttributes,     1);
        speakeasy::write_le(b, 4, wMaxPacketSize,   2);
        speakeasy::write_le(b, 6, bInterval,        1);
        return b;
    }
};

//  USBD_VERSION_INFORMATION (4 bytes) 
struct USBD_VERSION_INFORMATION : speakeasy::EmuStruct {
    uint32_t USBDI_Version       = 0;  // offset 0
    uint32_t Supported_USB_Version = 0; // offset 4 -- actually this might be uint32_t...

    // The Python defines two fields: USBDI_Version and Supported_USB_Version.
    // Let's check: from usb.py line 80-83:
    //   self.USBDI_Version = ct.c_uint32
    //   self.Supported_USB_Version = ct.c_uint32
    // So both are uint32_t = 8 bytes total.

    size_t sizeof_obj() const override { return 8; }

    std::vector<uint8_t> get_bytes() const override {
        std::vector<uint8_t> b(8);
        speakeasy::write_le(b, 0, USBDI_Version,         4);
        speakeasy::write_le(b, 4, Supported_USB_Version, 4);
        return b;
    }
};

}} // namespace speakeasy::defs

#endif // SPEAKEASY_DEFS_USB_H
