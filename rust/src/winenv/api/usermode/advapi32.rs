use crate::binemu::BinaryEmulator;
use crate::errors::Result;
use crate::windows::cryptman::CryptoManager;
use crate::windows::regman::RegistryManager;
use crate::winenv::api::ApiHandler;
use crate::winenv::defs::windows::windows as windefs;

pub struct Advapi32Handler {
    regman: RegistryManager,
    cryptman: CryptoManager,
    curr_handle: u32,
}

impl Advapi32Handler {
    pub fn new() -> Self {
        Self {
            regman: RegistryManager::new(),
            cryptman: CryptoManager::new(),
            curr_handle: 0x2800,
        }
    }

    pub fn get_handle(&mut self) -> u32 {
        self.curr_handle += 4;
        self.curr_handle
    }

    pub fn reg_open_key(
        &mut self,
        root: &str,
        sub_key: Option<&str>,
    ) -> std::result::Result<u64, u32> {
        let path = join_reg_path(root, sub_key);
        self.regman
            .open_key(&path, false)
            .ok_or(windefs::ERROR_PATH_NOT_FOUND)
    }

    pub fn reg_create_key(&mut self, root: &str, sub_key: Option<&str>) -> u64 {
        let path = join_reg_path(root, sub_key);
        self.regman.create_key(&path)
    }

    pub fn reg_set_value_ex(
        &mut self,
        key: u64,
        value_name: &str,
        value_type: u32,
        data: &[u8],
    ) -> u32 {
        if self
            .regman
            .set_key_value(key, value_name, value_type, data.to_vec())
        {
            windefs::ERROR_SUCCESS
        } else {
            windefs::ERROR_INVALID_HANDLE
        }
    }

    pub fn reg_query_value_ex(
        &mut self,
        key: u64,
        value_name: &str,
    ) -> std::result::Result<(u32, Vec<u8>), u32> {
        self.regman
            .get_key_value(key, value_name)
            .map(|value| (value.val_type, value.data.clone()))
            .ok_or(windefs::ERROR_FILE_NOT_FOUND)
    }

    pub fn crypt_acquire_context(
        &mut self,
        container: Option<String>,
        provider: Option<String>,
        provider_type: Option<u32>,
        flags: Option<u32>,
    ) -> u32 {
        self.cryptman
            .crypt_open(container, provider, provider_type, flags)
    }

    pub fn crypt_release_context(&mut self, handle: u32) -> bool {
        self.cryptman.crypt_close(handle);
        true
    }

    pub fn registry_type_name(value_type: u32) -> Option<&'static str> {
        match value_type {
            0 => Some("REG_NONE"),
            1 => Some("REG_SZ"),
            2 => Some("REG_EXPAND_SZ"),
            3 => Some("REG_BINARY"),
            4 => Some("REG_DWORD"),
            5 => Some("REG_DWORD_LITTLE_ENDIAN"),
            6 => Some("REG_QWORD"),
            7 => Some("REG_QWORD_LITTLE_ENDIAN"),
            _ => None,
        }
    }
}

impl Default for Advapi32Handler {
    fn default() -> Self {
        Self::new()
    }
}

impl ApiHandler for Advapi32Handler {
    fn call(&mut self, emu: &mut dyn BinaryEmulator, name: &str, args: &[u64]) -> Result<u64> {
        match name {
            "RegOpenKeyA" | "RegOpenKeyW" | "RegOpenKeyExA" | "RegOpenKeyExW" => {
                Ok(self.get_handle() as u64)
            }
            "RegQueryValueExA" | "RegQueryValueExW" => Ok(0),
            "RegSetValueExA" | "RegSetValueExW" => Ok(0),
            "RegCloseKey" => Ok(0),
            "RegEnumKeyA" | "RegEnumKeyW" | "RegEnumKeyExA" | "RegEnumKeyExW" => Ok(0),
            "RegCreateKeyA" | "RegCreateKeyW" | "RegCreateKeyExA" | "RegCreateKeyExW" => {
                Ok(self.get_handle() as u64)
            }
            "RegDeleteValueA" | "RegDeleteValueW" => Ok(0),
            "RegDeleteKeyA" | "RegDeleteKeyW" => Ok(0),
            "RegQueryInfoKeyA" | "RegQueryInfoKeyW" => Ok(0),
            "RegGetValueA" | "RegGetValueW" => Ok(0),
            "RegSaveKeyA" | "RegSaveKeyW" => Ok(0),
            "RegLoadKeyA" | "RegLoadKeyW" => Ok(0),
            "RegUnLoadKeyA" | "RegUnLoadKeyW" => Ok(0),
            "OpenProcessToken" => Ok(1),
            "OpenThreadToken" => Ok(1),
            "DuplicateTokenEx" => Ok(self.get_handle() as u64),
            "SetTokenInformation" => Ok(1),
            "GetTokenInformation" => Ok(1),
            "StartServiceCtrlDispatcherA" | "StartServiceCtrlDispatcherW" => Ok(1),
            "RegisterServiceCtrlHandlerA"
            | "RegisterServiceCtrlHandlerW"
            | "RegisterServiceCtrlHandlerExA"
            | "RegisterServiceCtrlHandlerExW" => Ok(self.get_handle() as u64),
            "SetServiceStatus" => Ok(1),
            "RevertToSelf" => Ok(1),
            "ImpersonateLoggedOnUser" => Ok(1),
            "OpenSCManagerA" | "OpenSCManagerW" => Ok(self.get_handle() as u64),
            "CreateServiceA" | "CreateServiceW" => Ok(self.get_handle() as u64),
            "OpenServiceA" | "OpenServiceW" => Ok(self.get_handle() as u64),
            "StartServiceA" | "StartServiceW" => Ok(1),
            "ControlService" => Ok(1),
            "QueryServiceStatus" => Ok(1),
            "QueryServiceConfigA" | "QueryServiceConfigW" => Ok(1),
            "CloseServiceHandle" => Ok(1),
            "ChangeServiceConfigA" | "ChangeServiceConfigW" => Ok(1),
            "ChangeServiceConfig2A" | "ChangeServiceConfig2W" => Ok(1),
            "DeleteService" => Ok(1),
            "SystemFunction036" => Ok(1),
            "CryptAcquireContextA" | "CryptAcquireContextW" => {
                Ok(self.crypt_acquire_context(None, None, Some(1), Some(0)) as u64)
            }
            "CryptReleaseContext" => Ok(1),
            "CryptGenRandom" => Ok(1),
            "CryptCreateHash" => Ok(self.get_handle() as u64),
            "CryptHashData" => Ok(1),
            "CryptGetHashParam" => Ok(1),
            "CryptDestroyHash" => Ok(1),
            "CryptDeriveKey" => Ok(self.get_handle() as u64),
            "CryptEncrypt" => Ok(1),
            "CryptDecrypt" => Ok(1),
            "CryptExportKey" => Ok(1),
            "CryptImportKey" => Ok(self.get_handle() as u64),
            "CryptGetUserKey" => Ok(1),
            "CryptSignHashA" | "CryptSignHashW" => Ok(1),
            "CryptVerifySignatureA" | "CryptVerifySignatureW" => Ok(1),
            "AllocateAndInitializeSid" => Ok(1),
            "FreeSid" => Ok(0),
            "CheckTokenMembership" => Ok(1),
            "GetCurrentHwProfileA" | "GetCurrentHwProfileW" => Ok(1),
            "GetUserNameA" | "GetUserNameW" => Ok(1),
            "LookupPrivilegeValueA" | "LookupPrivilegeValueW" => Ok(1),
            "LookupAccountNameA" | "LookupAccountNameW" => Ok(1),
            "LookupAccountSidA" | "LookupAccountSidW" => Ok(1),
            "AdjustTokenPrivileges" => Ok(1),
            "EqualSid" => Ok(1),
            "GetSidIdentifierAuthority" => Ok(0),
            "GetSidSubAuthorityCount" => Ok(0),
            "GetSidSubAuthority" => Ok(0),
            "CreateProcessAsUserA" | "CreateProcessAsUserW" => Ok(1),
            "LogonUserA" | "LogonUserW" => Ok(1),
            "CreateRestrictedToken" => Ok(self.get_handle() as u64),
            "IsValidSid" => Ok(1),
            "IsValidSecurityDescriptor" => Ok(1),
            "GetLengthSid" => Ok(0),
            "CopySid" => Ok(1),
            "EqualPrefixSid" => Ok(1),
            "GetTokenSid" => Ok(1),
            "SetTokenInformation" => Ok(1),
            "QuerySecurityAttributes" => Ok(0),
            "GetNamedSecurityInfoA" | "GetNamedSecurityInfoW" => Ok(0),
            "SetNamedSecurityInfoA" | "SetNamedSecurityInfoW" => Ok(0),
            "GetSecurityDescriptorLength" => Ok(0x50),
            "BuildSecurityDescriptor" => Ok(0),
            "MakeAbsoluteSD" => Ok(0),
            "GetSecurityDescriptorDacl" => Ok(1),
            "SetSecurityDescriptorDacl" => Ok(1),
            "GetSecurityDescriptorSacl" => Ok(1),
            "SetSecurityDescriptorSacl" => Ok(1),
            "GetSecurityDescriptorOwner" => Ok(1),
            "SetSecurityDescriptorOwner" => Ok(1),
            "GetSecurityDescriptorGroup" => Ok(1),
            "SetSecurityDescriptorGroup" => Ok(1),
            "InitializeSecurityDescriptor" => Ok(1),
            "GetAclInformation" => Ok(1),
            "SetAclInformation" => Ok(1),
            "GetAce" => Ok(1),
            "SetAce" => Ok(1),
            "AddAce" => Ok(1),
            "DeleteAce" => Ok(1),
            "AddAccessAllowedAce" => Ok(1),
            "AddAccessDeniedAce" => Ok(1),
            "AddAuditAccessAce" => Ok(1),
            "FindFirstFreeAce" => Ok(0),
            "AccessCheck" => Ok(1),
            "AccessCheckByType" => Ok(1),
            "AccessCheckByTypeAndAuditAlarm" => Ok(1),
            "AccessCheckByTypeResultList" => Ok(1),
            "ObjectCloseAuditAlarm" => Ok(1),
            "ObjectOpenAuditAlarm" => Ok(1),
            "ObjectPrivilegeAuditAlarm" => Ok(1),
            "PrivilegeCheck" => Ok(1),
            "ImpersonateNamedPipeClient" => Ok(1),
            "ImpersonateTcpClient" => Ok(1),
            "RevertToSelf" => Ok(1),
            "SetThreadToken" => Ok(1),
            "OpenThreadToken" => Ok(1),
            _ => Ok(0),
        }
    }

    fn get_name(&self) -> &str {
        "Advapi32"
    }
}

fn join_reg_path(root: &str, sub_key: Option<&str>) -> String {
    match sub_key {
        Some(sub_key) if !sub_key.is_empty() => format!(
            "{}\\{}",
            root.trim_end_matches('\\'),
            sub_key.trim_start_matches('\\')
        ),
        _ => root.to_string(),
    }
}
