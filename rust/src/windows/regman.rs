// Registry Manager for Windows emulator

use crate::errors::{Result, SpeakeasyError};
use crate::winenv::defs::registry::reg;
use std::collections::HashMap;

#[derive(Clone, Debug)]
pub enum RegData {
    String(String),
    Dword(u32),
    Qword(u64),
    Binary(Vec<u8>),
}

#[derive(Clone, Debug)]
pub struct RegValue {
    pub name: String,
    pub val_type: u32,
    pub data: RegData,
}

pub struct RegKey {
    pub path: String,
    pub values: Vec<RegValue>,
    pub handle: u32,
}

pub struct RegistryManager {
    pub keys: Vec<RegKey>,
    pub handle_table: HashMap<u32, String>,
    pub next_handle: u32,
}

impl RegistryManager {
    pub fn new() -> Self {
        let mut mgr = Self {
            keys: Vec::new(),
            handle_table: HashMap::new(),
            next_handle: 0x180,
        };

        // Initialize root keys
        mgr.create_key("HKEY_CLASSES_ROOT".to_string());
        mgr.create_key("HKEY_CURRENT_USER".to_string());
        mgr.create_key("HKEY_LOCAL_MACHINE".to_string());
        mgr.create_key("HKEY_USERS".to_string());

        mgr
    }

    pub fn normalize_path(&self, path: &str) -> String {
        let p = path.to_lowercase();
        if p.starts_with("\\registry\\machine\\") {
            format!("HKEY_LOCAL_MACHINE\\{}", &path[18..])
        } else if p.starts_with("hklm\\") {
            format!("HKEY_LOCAL_MACHINE\\{}", &path[5..])
        } else {
            path.to_string()
        }
    }

    pub fn create_key(&mut self, path: String) -> u32 {
        let path = self.normalize_path(&path);
        if let Some(key) = self.keys.iter().find(|k| k.path == path) {
            return key.handle;
        }

        let handle = self.next_handle;
        self.next_handle += 4;

        let key = RegKey {
            path: path.clone(),
            values: Vec::new(),
            handle,
        };
        self.keys.push(key);
        self.handle_table.insert(handle, path);
        handle
    }

    pub fn open_key(&mut self, path: &str) -> Option<u32> {
        let path = self.normalize_path(path);
        self.keys.iter().find(|k| k.path.to_lowercase() == path.to_lowercase()).map(|k| k.handle)
    }

    pub fn set_value(&mut self, handle: u32, name: String, val_type: u32, data: RegData) -> Result<()> {
        let path = self.handle_table.get(&handle).ok_err(|| SpeakeasyError::ApiError("Invalid handle".to_string()))?;
        let key = self.keys.iter_mut().find(|k| &k.path == path).unwrap();
        
        if let Some(val) = key.values.iter_mut().find(|v| v.name == name) {
            val.val_type = val_type;
            val.data = data;
        } else {
            key.values.push(RegValue { name, val_type, data });
        }
        Ok(())
    }
}

trait OptionExt<T> {
    fn ok_err<E>(self, err: E) -> core::result::Result<T, E>;
}

impl<T> OptionExt<T> for Option<T> {
    fn ok_err<E>(self, err: E) -> core::result::Result<T, E> {
        self.ok_or(err)
    }
}
