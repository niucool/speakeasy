use std::collections::HashMap;

pub struct MapView {
    pub base: u64,
    pub offset: u64,
    pub size: u64,
    pub protect: u32,
}

pub struct FileMap {
    pub name: String,
    pub size: u64,
    pub prot: u32,
    pub views: HashMap<u64, MapView>,
    pub handle: u64,
}

pub struct File {
    pub path: String,
    pub data: Vec<u8>,
    pub is_dir: bool,
    pub curr_offset: u64,
    pub handle: u64,
}

pub struct Pipe {
    pub path: String,
    pub mode: u32,
    pub handle: u64,
}

pub struct FileSystemManager {
    files: HashMap<u64, File>,
    maps: HashMap<u64, FileMap>,
    pipes: HashMap<u64, Pipe>,
    next_handle: u64,
}

impl FileSystemManager {
    pub fn new() -> Self {
        Self {
            files: HashMap::new(),
            maps: HashMap::new(),
            pipes: HashMap::new(),
            next_handle: 0x80,
        }
    }

    pub fn file_open(&mut self, path: &str, create: bool, _truncate: bool) -> Option<u64> {
        if !create {
            for (hnd, file) in &self.files {
                if file.path.to_lowercase() == path.to_lowercase() {
                    return Some(*hnd);
                }
            }
            return None;
        }

        let handle = self.next_handle;
        self.next_handle += 4;
        self.files.insert(handle, File {
            path: path.to_string(),
            data: Vec::new(),
            is_dir: false,
            curr_offset: 0,
            handle,
        });
        Some(handle)
    }

    pub fn file_create_mapping(&mut self, hfile: u64, name: &str, size: u64, prot: u32) -> u64 {
        let handle = self.next_handle;
        self.next_handle += 4;
        
        self.maps.insert(handle, FileMap {
            name: name.to_string(),
            size,
            prot,
            views: HashMap::new(),
            handle,
        });
        handle
    }

    pub fn get_file_from_handle(&mut self, handle: u64) -> Option<&mut File> {
        self.files.get_mut(&handle)
    }
}
