use crate::windows::cryptman::CryptoManager;
use crate::windows::regman::RegistryManager;
use crate::winenv::api::ApiHandler;
use crate::winenv::defs::registry::reg as regdefs;
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

    pub fn reg_open_key(&mut self, root: &str, sub_key: Option<&str>) -> Result<u64, u32> {
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

    pub fn reg_query_value_ex(&mut self, key: u64, value_name: &str) -> Result<(u32, Vec<u8>), u32> {
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

    pub fn crypt_import_key(&mut self, handle: u32, blob: &[u8], flags: u32) -> Option<u32> {
        let ctx = self.cryptman.crypt_get(handle)?;
        Some(ctx.import_key(None, Some(blob.to_vec()), Some(blob.len() as u32), None, None, Some(flags)))
    }

    pub fn registry_type_name(value_type: u32) -> Option<&'static str> {
        regdefs::get_value_type(value_type)
    }
}

impl Default for Advapi32Handler {
    fn default() -> Self {
        Self::new()
    }
}

impl ApiHandler for Advapi32Handler {
    fn call(&mut self, args: &[u64]) -> u64 {
        match args.len() {
            3 => self.reg_create_key("HKEY_CURRENT_USER", Some("Software\\Speakeasy")),
            5 => self
                .crypt_acquire_context(None, None, Some(args[2] as u32), Some(args[3] as u32))
                as u64,
            6 => self
                .reg_query_value_ex(args[0], "Default")
                .map(|(_, data)| data.len() as u64)
                .unwrap_or(windefs::ERROR_FILE_NOT_FOUND as u64),
            _ => 0,
        }
    }

    fn get_name(&self) -> &str {
        "Advapi32"
    }
}

fn join_reg_path(root: &str, sub_key: Option<&str>) -> String {
    match sub_key {
        Some(sub_key) if !sub_key.is_empty() => format!("{root}\\{}", sub_key.trim_start_matches('\\')),
        _ => root.to_string(),
    }
}
