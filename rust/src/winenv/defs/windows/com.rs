use crate::r#struct::{EmuStruct, Ptr};
use uuid::Uuid;

pub const S_OK: u32 = 0;
pub const RPC_C_AUTHN_LEVEL_DEFAULT: u32 = 0;
pub const RPC_C_AUTHN_LEVEL_NONE: u32 = 1;
pub const RPC_C_AUTHN_LEVEL_CONNECT: u32 = 2;
pub const RPC_C_AUTHN_LEVEL_CALL: u32 = 3;
pub const RPC_C_AUTHN_LEVEL_PKT: u32 = 4;
pub const RPC_C_AUTHN_LEVEL_PKT_INTEGRITY: u32 = 5;
pub const RPC_C_AUTHN_LEVEL_PKT_PRIVACY: u32 = 6;

pub const RPC_C_IMP_LEVEL_DEFAULT: u32 = 0;
pub const RPC_C_IMP_LEVEL_ANONYMOUS: u32 = 1;
pub const RPC_C_IMP_LEVEL_IDENTIFY: u32 = 2;
pub const RPC_C_IMP_LEVEL_IMPERSONATE: u32 = 3;
pub const RPC_C_IMP_LEVEL_DELEGATE: u32 = 4;

pub const CLSID_WBEM_LOCATOR: &str = "{4590F811-1D3A-11D0-891F-00AA004B2E24}";
pub const CLSID_IWBEM_CONTEXT: &str = "{674B6698-EE92-11D0-AD71-00C04FD8FDFF}";
pub const IID_IWBEM_LOCATOR: &str = "{DC12A687-737F-11CF-884D-00AA004B2E24}";
pub const IID_IWBEM_CONTEXT: &str = "{44ACA674-E8FC-11D0-A07C-00C04FB68820}";

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct IUnknown {
    pub QueryInterface: Ptr,
    pub AddRef: Ptr,
    pub Release: Ptr,
}
impl EmuStruct for IUnknown {}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct IWbemLocator {
    pub IUnknown: IUnknown,
    pub ConnectServer: Ptr,
}
impl EmuStruct for IWbemLocator {}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct IMalloc {
    pub IUnknown: IUnknown,
    pub Alloc: Ptr,
    pub Realloc: Ptr,
    pub Free: Ptr,
    pub GetSize: Ptr,
    pub DidAlloc: Ptr,
    pub HeapMinimize: Ptr,
}
impl EmuStruct for IMalloc {}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct IWbemServices {
    pub IUnknown: IUnknown,
    pub OpenNamespace: Ptr,
    pub CancelAsyncCall: Ptr,
    pub QueryObjectSink: Ptr,
    pub GetObject: Ptr,
    pub GetObjectAsync: Ptr,
    pub PutClass: Ptr,
    pub PutClassAsync: Ptr,
    pub DeleteClass: Ptr,
    pub DeleteClassAsync: Ptr,
    pub CreateClassEnum: Ptr,
    pub CreateClassEnumAsync: Ptr,
    pub PutInstance: Ptr,
    pub PutInstanceAsync: Ptr,
    pub DeleteInstance: Ptr,
    pub DeleteInstanceAsync: Ptr,
    pub CreateInstanceEnum: Ptr,
    pub CreateInstanceEnumAsync: Ptr,
    pub ExecQuery: Ptr,
    pub ExecQueryAsync: Ptr,
    pub ExecNotificationQuery: Ptr,
    pub ExecNotificationQueryAsync: Ptr,
    pub ExecMethod: Ptr,
    pub ExecMethodAsync: Ptr,
}
impl EmuStruct for IWbemServices {}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct IWbemContext {
    pub IUnknown: IUnknown,
    pub Clone: Ptr,
    pub GetNames: Ptr,
    pub BeginEnumeration: Ptr,
    pub Next: Ptr,
    pub EndEnumeration: Ptr,
    pub SetValue: Ptr,
    pub GetValue: Ptr,
    pub DeleteValue: Ptr,
    pub DeleteAll: Ptr,
}
impl EmuStruct for IWbemContext {}

#[derive(Clone, Copy, Debug)]
pub struct ComInterface<T: EmuStruct + Copy> {
    pub iface: T,
    pub address: u64,
    pub name: &'static str,
}

impl<T: EmuStruct + Copy> ComInterface<T> {
    pub fn new(iface: T, name: &'static str) -> Self {
        Self {
            iface,
            address: 0,
            name,
        }
    }
}

pub fn get_define_int(define: u32, prefix: &str) -> Option<&'static str> {
    let defs = [
        ("RPC_C_AUTHN_LEVEL_DEFAULT", RPC_C_AUTHN_LEVEL_DEFAULT),
        ("RPC_C_AUTHN_LEVEL_NONE", RPC_C_AUTHN_LEVEL_NONE),
        ("RPC_C_AUTHN_LEVEL_CONNECT", RPC_C_AUTHN_LEVEL_CONNECT),
        ("RPC_C_AUTHN_LEVEL_CALL", RPC_C_AUTHN_LEVEL_CALL),
        ("RPC_C_AUTHN_LEVEL_PKT", RPC_C_AUTHN_LEVEL_PKT),
        ("RPC_C_AUTHN_LEVEL_PKT_INTEGRITY", RPC_C_AUTHN_LEVEL_PKT_INTEGRITY),
        ("RPC_C_AUTHN_LEVEL_PKT_PRIVACY", RPC_C_AUTHN_LEVEL_PKT_PRIVACY),
        ("RPC_C_IMP_LEVEL_DEFAULT", RPC_C_IMP_LEVEL_DEFAULT),
        ("RPC_C_IMP_LEVEL_ANONYMOUS", RPC_C_IMP_LEVEL_ANONYMOUS),
        ("RPC_C_IMP_LEVEL_IDENTIFY", RPC_C_IMP_LEVEL_IDENTIFY),
        ("RPC_C_IMP_LEVEL_IMPERSONATE", RPC_C_IMP_LEVEL_IMPERSONATE),
        ("RPC_C_IMP_LEVEL_DELEGATE", RPC_C_IMP_LEVEL_DELEGATE),
    ];
    defs.iter()
        .find_map(|(name, value)| (name.starts_with(prefix) && *value == define).then_some(*name))
}

pub fn get_define_str(define: &str, prefix: &str) -> Option<&'static str> {
    let defs = [
        ("CLSID_WBEM_LOCATOR", CLSID_WBEM_LOCATOR),
        ("CLSID_IWBEM_CONTEXT", CLSID_IWBEM_CONTEXT),
        ("IID_IWBEM_LOCATOR", IID_IWBEM_LOCATOR),
        ("IID_IWBEM_CONTEXT", IID_IWBEM_CONTEXT),
    ];
    defs.iter()
        .find_map(|(name, value)| (name.starts_with(prefix) && *value == define).then_some(*name))
}

pub fn get_clsid(define: &str) -> Option<&'static str> {
    get_define_str(define, "CLSID_")
}

pub fn get_iid(define: &str) -> Option<&'static str> {
    get_define_str(define, "IID_")
}

pub fn get_rpc_authlevel(define: u32) -> Option<&'static str> {
    get_define_int(define, "RPC_C_AUTHN_LEVEL_")
}

pub fn get_rcp_implevel(define: u32) -> Option<&'static str> {
    get_define_int(define, "RPC_C_IMP_LEVEL_")
}

pub const IFACE_TYPES: &[&str] = &[
    "IUnknown",
    "IMalloc",
    "IWbemLocator",
    "IWbemServices",
    "IWbemContext",
];

pub fn convert_guid_bytes_to_str(guid_bytes: [u8; 16]) -> String {
    format!("{{{}}}", Uuid::from_bytes_le(guid_bytes).hyphenated()).to_uppercase()
}
