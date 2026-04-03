// Object Manager for Windows emulator

use crate::errors::{Result, SpeakeasyError};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

pub type Handle = u32;

#[derive(Debug, Clone, PartialEq)]
pub enum ObjectType {
    Process,
    Thread,
    Event,
    Mutant,
    File,
    Driver,
    Device,
    Token,
    SymbolicLink,
}

pub trait KernelObject: Send + Sync {
    fn get_id(&self) -> u32;
    fn get_type(&self) -> ObjectType;
    fn get_name(&self) -> &str;
    fn get_address(&self) -> u64;
}

pub struct BaseObject {
    pub id: u32,
    pub name: String,
    pub address: u64,
    pub obj_type: ObjectType,
    pub handles: Vec<Handle>,
    pub ref_cnt: u32,
}

pub struct ObjectManager {
    pub objects: HashMap<u64, Arc<Mutex<BaseObject>>>,
    pub handle_table: HashMap<Handle, u64>,
    pub next_handle: Handle,
    pub next_id: u32,
}

impl ObjectManager {
    pub fn new() -> Self {
        Self {
            objects: HashMap::new(),
            handle_table: HashMap::new(),
            next_handle: 0x220,
            next_id: 0x400,
        }
    }

    pub fn new_id(&mut self) -> u32 {
        let id = self.next_id;
        self.next_id += 4;
        id
    }

    pub fn new_handle(&mut self) -> Handle {
        let h = self.next_handle;
        self.next_handle += 4;
        h
    }

    pub fn add_object(
        &mut self,
        address: u64,
        name: String,
        obj_type: ObjectType,
    ) -> Arc<Mutex<BaseObject>> {
        let id = self.new_id();
        let obj = Arc::new(Mutex::new(BaseObject {
            id,
            name,
            address,
            obj_type,
            handles: Vec::new(),
            ref_cnt: 1,
        }));
        self.objects.insert(address, obj.clone());
        obj
    }

    pub fn create_handle(&mut self, address: u64) -> Result<Handle> {
        if !self.objects.contains_key(&address) {
            return Err(SpeakeasyError::ApiError("Object not found".to_string()));
        }
        let handle = self.new_handle();
        self.handle_table.insert(handle, address);

        let obj = self.objects.get(&address).unwrap();
        obj.lock().unwrap().handles.push(handle);

        Ok(handle)
    }

    pub fn get_object_by_handle(&self, handle: Handle) -> Option<Arc<Mutex<BaseObject>>> {
        self.handle_table
            .get(&handle)
            .and_then(|addr| self.objects.get(addr))
            .cloned()
    }

    pub fn get_object_by_name(&self, name: &str) -> Option<Arc<Mutex<BaseObject>>> {
        self.objects
            .values()
            .find(|o| o.lock().unwrap().name.to_lowercase() == name.to_lowercase())
            .cloned()
    }
}
