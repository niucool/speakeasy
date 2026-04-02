use std::collections::HashMap;

pub struct RegValue {
    pub name: String,
    pub val_type: u32,
    pub data: Vec<u8>,
}

pub struct RegKey {
    pub path: String,
    pub values: Vec<RegValue>,
    pub handle: u64,
}

pub struct RegistryManager {
    keys: Vec<RegKey>,
    handles: HashMap<u64, usize>,
    next_handle: u64,
}

impl RegistryManager {
    pub fn new() -> Self {
        Self {
            keys: Vec::new(),
            handles: HashMap::new(),
            next_handle: 0x180,
        }
    }

    pub fn normalize_reg_path(&self, path: &str) -> String {
        let n = path.to_lowercase();
        if n.starts_with("\\registry\\machine\\") || n.starts_with("hklm\\") {
            let offset = if n.starts_with("hklm\\") { 5 } else { 18 };
            return format!("HKEY_LOCAL_MACHINE\\{}", &path[offset..]);
        }
        path.to_string()
    }

    pub fn get_key_from_handle(&mut self, handle: u64) -> Option<&mut RegKey> {
        let idx = *self.handles.get(&handle)?;
        self.keys.get_mut(idx)
    }

    pub fn create_key(&mut self, path: &str) -> u64 {
        let path = self.normalize_reg_path(path);
        if let Some(idx) = self.keys.iter().position(|k| k.path.to_lowercase() == path.to_lowercase()) {
            return self.keys[idx].handle;
        }

        let handle = self.next_handle;
        self.next_handle += 4;

        let key = RegKey {
            path,
            values: Vec::new(),
            handle,
        };

        let idx = self.keys.len();
        self.keys.push(key);
        self.handles.insert(handle, idx);

        handle
    }

    pub fn create_key_path(&mut self, path: &str) -> &mut RegKey {
        let handle = self.create_key(path);
        self.get_key_from_handle(handle).expect("created key must exist")
    }

    pub fn open_key(&mut self, path: &str, create: bool) -> Option<u64> {
        let path = self.normalize_reg_path(path);
        
        if let Some(idx) = self.keys.iter().position(|k| k.path.to_lowercase() == path.to_lowercase()) {
            return Some(self.keys[idx].handle);
        }

        if create {
            Some(self.create_key(&path))
        } else {
            None
        }
    }

    pub fn get_subkeys(&self, path: &str) -> Vec<String> {
        let parent = path.to_lowercase();
        let mut subkeys = Vec::new();

        for k in &self.keys {
            let test = k.path.to_lowercase();
            if test.starts_with(&parent) && test.len() > parent.len() {
                let sub = test[parent.len()..].trim_start_matches('\\');
                if let Some(end) = sub.find('\\') {
                    subkeys.push(sub[..end].to_string());
                } else if !sub.is_empty() {
                    subkeys.push(sub.to_string());
                }
            }
        }
        subkeys
    }

    pub fn set_key_value(&mut self, handle: u64, name: &str, val_type: u32, data: Vec<u8>) -> bool {
        let Some(key) = self.get_key_from_handle(handle) else {
            return false;
        };

        if let Some(value) = key.values.iter_mut().find(|value| value.name.eq_ignore_ascii_case(name)) {
            value.val_type = val_type;
            value.data = data;
            return true;
        }

        key.values.push(RegValue {
            name: name.to_string(),
            val_type,
            data,
        });
        true
    }

    pub fn get_key_value(&mut self, handle: u64, name: &str) -> Option<&RegValue> {
        let key = self.get_key_from_handle(handle)?;
        key.values
            .iter()
            .find(|value| value.name.eq_ignore_ascii_case(name))
    }
}
