use std::collections::HashMap;
use std::sync::{Arc, Mutex};

pub trait KernelObject {
    fn get_id(&self) -> u32;
    fn get_address(&self) -> u64;
    fn get_handles(&self) -> Vec<u64>;
    fn add_handle(&mut self, handle: u64);
    fn get_name(&self) -> Option<String>;
    fn increment_ref(&mut self);
    fn decrement_ref(&mut self) -> i32;
}

pub struct EThread {
    pub id: u32,
    pub address: u64,
    pub handles: Vec<u64>,
    pub ref_cnt: i32,
    pub stack_base: u64,
    pub stack_commit: u64,
    pub tid: u32,
}

impl KernelObject for EThread {
    fn get_id(&self) -> u32 { self.id }
    fn get_address(&self) -> u64 { self.address }
    fn get_handles(&self) -> Vec<u64> { self.handles.clone() }
    fn add_handle(&mut self, handle: u64) { self.handles.push(handle); }
    fn get_name(&self) -> Option<String> { None }
    fn increment_ref(&mut self) { self.ref_cnt += 1; }
    fn decrement_ref(&mut self) -> i32 { 
        self.ref_cnt -= 1; 
        self.ref_cnt 
    }
}

pub struct EProcess {
    pub id: u32,
    pub address: u64,
    pub handles: Vec<u64>,
    pub ref_cnt: i32,
    pub name: String,
    pub pid: u32,
    pub base: u64,
    pub cmdline: String,
}

impl KernelObject for EProcess {
    fn get_id(&self) -> u32 { self.id }
    fn get_address(&self) -> u64 { self.address }
    fn get_handles(&self) -> Vec<u64> { self.handles.clone() }
    fn add_handle(&mut self, handle: u64) { self.handles.push(handle); }
    fn get_name(&self) -> Option<String> { Some(self.name.clone()) }
    fn increment_ref(&mut self) { self.ref_cnt += 1; }
    fn decrement_ref(&mut self) -> i32 { 
        self.ref_cnt -= 1; 
        self.ref_cnt 
    }
}

pub struct ObjectManager {
    objects: HashMap<u64, Arc<Mutex<dyn KernelObject>>>,
    symlinks: Vec<(String, String)>,
    next_id: u32,
    next_handle: u64,
}

impl ObjectManager {
    pub fn new() -> Self {
        Self {
            objects: HashMap::new(),
            symlinks: Vec::new(),
            next_id: 0x400,
            next_handle: 0x220,
        }
    }

    pub fn new_id(&mut self) -> u32 {
        let id = self.next_id;
        self.next_id += 4;
        id
    }

    pub fn get_handle(&mut self, object_address: u64) -> Option<u64> {
        if let Some(obj) = self.objects.get_mut(&object_address) {
            let handle = self.next_handle;
            self.next_handle += 4;
            obj.lock().unwrap().add_handle(handle);
            Some(handle)
        } else {
            None
        }
    }

    pub fn add_object(&mut self, mut obj: Arc<Mutex<dyn KernelObject>>) {
        let address = {
            let mut o = obj.lock().unwrap();
            o.increment_ref();
            o.get_address()
        };
        self.objects.insert(address, obj);
    }

    pub fn remove_object(&mut self, address: u64) {
        self.objects.remove(&address);
    }

    pub fn dec_ref(&mut self, address: u64) {
        let should_remove = if let Some(obj) = self.objects.get_mut(&address) {
            let mut o = obj.lock().unwrap();
            o.decrement_ref() <= 0
        } else {
            false
        };

        if should_remove {
            self.remove_object(address);
        }
    }

    pub fn get_object_from_id(&self, id: u32) -> Option<Arc<Mutex<dyn KernelObject>>> {
        for obj in self.objects.values() {
            if obj.lock().unwrap().get_id() == id {
                return Some(Arc::clone(obj));
            }
        }
        None
    }

    pub fn get_object_from_addr(&self, addr: u64) -> Option<Arc<Mutex<dyn KernelObject>>> {
        self.objects.get(&addr).map(|o| Arc::clone(o))
    }

    pub fn get_object_from_handle(&self, handle: u64) -> Option<Arc<Mutex<dyn KernelObject>>> {
        for obj in self.objects.values() {
            if obj.lock().unwrap().get_handles().contains(&handle) {
                return Some(Arc::clone(obj));
            }
        }
        None
    }

    pub fn get_object_from_name(&self, name: &str) -> Option<Arc<Mutex<dyn KernelObject>>> {
        let n = name.trim_end_matches('\\').to_lowercase();
        for obj in self.objects.values() {
            if let Some(obj_name) = obj.lock().unwrap().get_name() {
                if obj_name.to_lowercase() == n {
                    return Some(Arc::clone(obj));
                }
            }
        }
        
        for (link, target) in &self.symlinks {
            if link.to_lowercase() == n {
                return self.get_object_from_name(target);
            }
        }
        None
    }
}
