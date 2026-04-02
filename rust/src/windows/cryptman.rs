// Crypto Manager
use std::collections::HashMap;

pub struct CryptKey {
    pub blob_type: Option<u32>,
    pub blob: Option<Vec<u8>>,
    pub blob_len: Option<u32>,
    pub import_key: Option<u32>,
    pub param_list: Option<Vec<u32>>,
    pub flags: Option<u32>,
}

pub struct CryptContext {
    pub container_name: Option<String>,
    pub provider_name: Option<String>,
    pub ptype: Option<u32>,
    pub flags: Option<u32>,
    pub keys: HashMap<u32, CryptKey>,
    next_key_handle: u32,
    pub handle: u32,
}

impl CryptContext {
    pub fn new(handle: u32, cname: Option<String>, pname: Option<String>, ptype: Option<u32>, flags: Option<u32>) -> Self {
        Self {
            container_name: cname,
            provider_name: pname,
            ptype,
            flags,
            keys: HashMap::new(),
            next_key_handle: 0x9000,
            handle,
        }
    }

    pub fn import_key(
        &mut self,
        blob_type: Option<u32>,
        blob: Option<Vec<u8>>,
        blob_len: Option<u32>,
        import_key: Option<u32>,
        param_list: Option<Vec<u32>>,
        flags: Option<u32>,
    ) -> u32 {
        let key = CryptKey {
            blob_type,
            blob,
            blob_len,
            import_key,
            param_list,
            flags,
        };
        let hnd = self.next_key_handle;
        self.next_key_handle += 4;
        self.keys.insert(hnd, key);
        hnd
    }

    pub fn get_key(&self, hnd: u32) -> Option<&CryptKey> {
        self.keys.get(&hnd)
    }

    pub fn delete_key(&mut self, hnd: u32) {
        self.keys.remove(&hnd);
    }
}

pub struct CryptoManager {
    ctx_handles: HashMap<u32, CryptContext>,
    next_handle: u32,
}

impl CryptoManager {
    pub fn new() -> Self {
        Self {
            ctx_handles: HashMap::new(),
            next_handle: 0x680,
        }
    }

    pub fn crypt_open(
        &mut self,
        cname: Option<String>,
        pname: Option<String>,
        ptype: Option<u32>,
        flags: Option<u32>,
    ) -> u32 {
        let hnd = self.next_handle;
        self.next_handle += 4;
        let ctx = CryptContext::new(hnd, cname, pname, ptype, flags);
        self.ctx_handles.insert(hnd, ctx);
        hnd
    }

    pub fn crypt_close(&mut self, hnd: u32) {
        self.ctx_handles.remove(&hnd);
    }

    pub fn crypt_get(&mut self, hnd: u32) -> Option<&mut CryptContext> {
        self.ctx_handles.get_mut(&hnd)
    }
}

impl Default for CryptoManager {
    fn default() -> Self {
        Self::new()
    }
}
