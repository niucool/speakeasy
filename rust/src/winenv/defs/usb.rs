use crate::r#struct::EmuStruct;

pub const USB_DEVICE_DESCRIPTOR_TYPE: u8 = 0x01;
pub const USB_CONFIGURATION_DESCRIPTOR_TYPE: u8 = 0x02;
pub const USB_STRING_DESCRIPTOR_TYPE: u8 = 0x03;
pub const USB_INTERFACE_DESCRIPTOR_TYPE: u8 = 0x04;
pub const USB_ENDPOINT_DESCRIPTOR_TYPE: u8 = 0x05;

pub const USB_ENDPOINT_TYPE_MASK: u8 = 0x03;
pub const USB_ENDPOINT_TYPE_CONTROL: u8 = 0x00;
pub const USB_ENDPOINT_TYPE_ISOCHRONOUS: u8 = 0x01;
pub const USB_ENDPOINT_TYPE_BULK: u8 = 0x02;
pub const USB_ENDPOINT_TYPE_INTERRUPT: u8 = 0x03;

pub const USB_DIR_IN: u8 = 0x80;
pub const USB_DIR_OUT: u8 = 0x00;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct USB_DEVICE_DESCRIPTOR {
    pub bLength: u8,
    pub bDescriptorType: u8,
    pub bcdUSB: u16,
    pub bDeviceClass: u8,
    pub bDeviceSubClass: u8,
    pub bDeviceProtocol: u8,
    pub bMaxPacketSize0: u8,
    pub idVendor: u16,
    pub idProduct: u16,
    pub bcdDevice: u16,
    pub iManufacturer: u8,
    pub iProduct: u8,
    pub iSerialNumber: u8,
    pub bNumConfigurations: u8,
}
impl EmuStruct for USB_DEVICE_DESCRIPTOR {}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct USB_CONFIGURATION_DESCRIPTOR {
    pub bLength: u8,
    pub bDescriptorType: u8,
    pub wTotalLength: u16,
    pub bNumInterfaces: u8,
    pub bConfigurationValue: u8,
    pub iConfiguration: u8,
    pub bmAttributes: u8,
    pub MaxPower: u8,
}
impl EmuStruct for USB_CONFIGURATION_DESCRIPTOR {}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct USB_INTERFACE_DESCRIPTOR {
    pub bLength: u8,
    pub bDescriptorType: u8,
    pub bInterfaceNumber: u8,
    pub bAlternateSetting: u8,
    pub bNumEndpoints: u8,
    pub bInterfaceClass: u8,
    pub bInterfaceSubClass: u8,
    pub bInterfaceProtocol: u8,
    pub iInterface: u8,
}
impl EmuStruct for USB_INTERFACE_DESCRIPTOR {}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct USB_ENDPOINT_DESCRIPTOR {
    pub bLength: u8,
    pub bDescriptorType: u8,
    pub bEndpointAddress: u8,
    pub bmAttributes: u8,
    pub wMaxPacketSize: u16,
    pub bInterval: u8,
}
impl EmuStruct for USB_ENDPOINT_DESCRIPTOR {}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct USBD_VERSION_INFORMATION {
    pub USBDI_Version: u32,
    pub Supported_USB_Version: u32,
}
impl EmuStruct for USBD_VERSION_INFORMATION {}
