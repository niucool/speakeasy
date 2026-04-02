use crate::r#struct::{EmuStruct, Ptr};
use crate::winenv::defs::usb::USBD_VERSION_INFORMATION;

pub const WDF_USB_DEVICE_TRAIT_SELF_POWERED: u32 = 1;
pub const WDF_USB_DEVICE_TRAIT_REMOTE_WAKE_CAPABLE: u32 = 2;
pub const WDF_USB_DEVICE_TRAIT_AT_HIGH_SPEED: u32 = 4;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct WDF_VERSION {
    pub Major: u32,
    pub Minor: u32,
    pub Build: u32,
}
impl EmuStruct for WDF_VERSION {}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct WDF_BIND_INFO {
    pub Size: u32,
    pub Component: Ptr,
    pub Version: WDF_VERSION,
    pub FuncCount: u32,
    pub FuncTable: Ptr,
    pub Module: Ptr,
}
impl EmuStruct for WDF_BIND_INFO {}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct WDF_USB_DEVICE_INFORMATION {
    pub Size: u32,
    pub UsbdVersionInformation: USBD_VERSION_INFORMATION,
    pub HcdPortCapabilities: u32,
    pub Traits: u32,
}
impl EmuStruct for WDF_USB_DEVICE_INFORMATION {}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct WDF_DRIVER_CONFIG {
    pub Size: u32,
    pub EvtDriverDeviceAdd: Ptr,
    pub EvtDriverUnload: Ptr,
    pub DriverInitFlags: u32,
    pub DriverPoolTag: u32,
}
impl EmuStruct for WDF_DRIVER_CONFIG {}
