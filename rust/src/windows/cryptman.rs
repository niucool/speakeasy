// Crypto Manager for Windows emulator

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};

static CURR_HANDLE: AtomicU32 = AtomicU32::new(0x680);

fn get_next_handle() -> u32 {
    CURR_HANDLE.fetch_add(4, Ordering::SeqCst)
}

#[derive(Clone, Debug)]
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
}

impl CryptContext {
    pub fn new(
        cname: Option<String>,
        pname: Option<String>,
        ptype: Option<u32>,
        flags: Option<u32>,
    ) -> Self {
        Self {
            container_name: cname,
            provider_name: pname,
            ptype,
            flags,
            keys: HashMap::new(),
        }
    }

    pub fn import_key(
        &mut self,
        blob_type: Option<u32>,
        blob: Option<Vec<u8>>,
        blob_len: Option<u32>,
        hnd_import_key: Option<u32>,
        param_list: Option<Vec<u32>>,
        flags: Option<u32>,
    ) -> u32 {
        let key = CryptKey {
            blob_type,
            blob,
            blob_len,
            import_key: hnd_import_key,
            param_list,
            flags,
        };
        let hnd = get_next_handle();
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
    pub ctx_handles: HashMap<u32, CryptContext>,
}

impl CryptoManager {
    pub fn new() -> Self {
        Self {
            ctx_handles: HashMap::new(),
        }
    }

    pub fn crypt_open(
        &mut self,
        cname: Option<String>,
        pname: Option<String>,
        ptype: Option<u32>,
        flags: Option<u32>,
    ) -> u32 {
        let ctx = CryptContext::new(cname, pname, ptype, flags);
        let hnd = get_next_handle();
        self.ctx_handles.insert(hnd, ctx);
        hnd
    }

    pub fn crypt_close(&mut self, hnd: u32) {
        self.ctx_handles.remove(&hnd);
    }

    pub fn crypt_get(&self, hnd: u32) -> Option<&CryptContext> {
        self.ctx_handles.get(&hnd)
    }
}
