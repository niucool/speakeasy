// File Manager for Windows emulator

use crate::errors::{Result, SpeakeasyError};
use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom, Write};

pub struct File {
    pub path: String,
    pub data: Vec<u8>,
    pub cursor: usize,
    pub is_dir: bool,
    pub handle: u32,
}

impl File {
    pub fn new(path: String, data: Vec<u8>, is_dir: bool, handle: u32) -> Self {
        Self {
            path,
            data,
            cursor: 0,
            is_dir,
            handle,
        }
    }

    pub fn read(&mut self, size: usize) -> Vec<u8> {
        let end = (self.cursor + size).min(self.data.len());
        let result = self.data[self.cursor..end].to_vec();
        self.cursor = end;
        result
    }

    pub fn write(&mut self, data: &[u8]) {
        let end = self.cursor + data.len();
        if end > self.data.len() {
            self.data.resize(end, 0);
        }
        self.data[self.cursor..end].copy_from_slice(data);
        self.cursor = end;
    }
}

pub struct FileManager {
    pub files: Vec<File>,
    pub handle_table: HashMap<u32, String>,
    pub next_handle: u32,
}

impl FileManager {
    pub fn new() -> Self {
        Self {
            files: Vec::new(),
            handle_table: HashMap::new(),
            next_handle: 0x80,
        }
    }

    pub fn create_file(&mut self, path: String, data: Vec<u8>) -> u32 {
        let handle = self.next_handle;
        self.next_handle += 4;

        let file = File::new(path.clone(), data, false, handle);
        self.files.push(file);
        self.handle_table.insert(handle, path);
        handle
    }

    pub fn open_file(&mut self, path: &str) -> Option<u32> {
        self.files
            .iter()
            .find(|f| f.path.to_lowercase() == path.to_lowercase())
            .map(|f| f.handle)
    }

    pub fn get_file_mut(&mut self, handle: u32) -> Option<&mut File> {
        let path = self.handle_table.get(&handle)?;
        self.files.iter_mut().find(|f| &f.path == path)
    }
}
