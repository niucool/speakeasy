use crate::r#struct::{EmuStruct, Ptr};
use crate::winenv::defs::windows::windows::GUID;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct FWPM_DISPLAY_DATA0 {
    pub name: Ptr,
    pub description: Ptr,
}
impl EmuStruct for FWPM_DISPLAY_DATA0 {}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct FWP_VALUE0 {
    pub r#type: u32,
    pub data: Ptr,
}
impl EmuStruct for FWP_VALUE0 {}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct FWP_BYTE_BLOB {
    pub size: u32,
    pub data: Ptr,
}
impl EmuStruct for FWP_BYTE_BLOB {}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct FWPM_SUBLAYER0 {
    pub subLayerKey: GUID,
    pub displayData: FWPM_DISPLAY_DATA0,
    pub flags: u32,
    pub providerKey: GUID,
    pub providerData: FWP_BYTE_BLOB,
    pub weight: u16,
}
impl EmuStruct for FWPM_SUBLAYER0 {}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct FWPS_CALLOUT1 {
    pub calloutKey: GUID,
    pub flags: u32,
    pub classifyFn: Ptr,
    pub notifyFn: Ptr,
    pub flowDeleteFn: Ptr,
}
impl EmuStruct for FWPS_CALLOUT1 {}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct FWPM_CALLOUT0 {
    pub calloutKey: GUID,
    pub displayData: FWPM_DISPLAY_DATA0,
    pub flags: u32,
    pub providerKey: GUID,
    pub providerData: FWP_BYTE_BLOB,
    pub applicableLayer: GUID,
    pub calloutId: u32,
}
impl EmuStruct for FWPM_CALLOUT0 {}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct FWPM_FILTER_CONDITION0 {
    pub fieldKey: GUID,
    pub matchType: u32,
    pub conditionValue: FWP_VALUE0,
}
impl EmuStruct for FWPM_FILTER_CONDITION0 {}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct FWPM_ACTION0 {
    pub r#type: u32,
    pub filterType: GUID,
}
impl EmuStruct for FWPM_ACTION0 {}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct FWPM_FILTER0 {
    pub filterKey: GUID,
    pub displayData: FWPM_DISPLAY_DATA0,
    pub flags: u32,
    pub providerKey: GUID,
    pub providerData: FWP_BYTE_BLOB,
    pub layerKey: GUID,
    pub subLayerKey: GUID,
    pub weight: FWP_VALUE0,
    pub numFilterConditions: u32,
    pub filterCondition: Ptr,
    pub action: FWPM_ACTION0,
    pub providerContextKey: GUID,
    pub reserved: Ptr,
    pub filterId: u64,
    pub effectiveWeight: FWP_VALUE0,
}
impl EmuStruct for FWPM_FILTER0 {}
