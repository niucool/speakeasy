// Loaders
use pelite::pe64::Pe;
use pelite::pe64::PeFile;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct ResourceEntry {
    pub id: String,
    pub data_rva: u32,
    pub size: u32,
    pub type_id: String,
    pub entry_rva: u32,
    pub lang_id: u32,
}

#[derive(Debug, Clone)]
pub struct PeMetadata {
    pub subsystem: u32,
    pub timestamp: u32,
    pub machine: u32,
    pub magic: u32,
    pub resources: Vec<ResourceEntry>,
    pub string_table: HashMap<u32, String>,
}

#[derive(Debug, Clone)]
pub struct MemoryRegion {
    pub base: u64,
    pub data: Vec<u8>,
    pub name: String,
    pub perms: u32,
}

#[derive(Debug, Clone)]
pub struct SectionEntry {
    pub name: String,
    pub virtual_address: u32,
    pub virtual_size: u32,
    pub perms: u32,
}

#[derive(Debug, Clone)]
pub struct ImportEntry {
    pub iat_address: u64,
    pub dll_name: String,
    pub func_name: String,
}

#[derive(Debug, Clone)]
pub struct ExportEntry {
    pub name: Option<String>,
    pub address: u64,
    pub ordinal: u32,
    pub execution_mode: String,
}

#[derive(Debug, Clone)]
pub struct LoadedImage {
    pub arch: String,
    pub module_type: String,
    pub name: String,
    pub emu_path: String,
    pub image_base: u64,
    pub image_size: u32,
    pub regions: Vec<MemoryRegion>,
    pub imports: Vec<ImportEntry>,
    pub exports: Vec<ExportEntry>,
    pub default_export_mode: String,
    pub entry_points: Vec<u64>,
    pub visible_in_peb: bool,
    pub stack_size: u32,
    pub tls_callbacks: Vec<u64>,
    pub tls_directory_va: Option<u64>,
    pub sections: Vec<SectionEntry>,
    pub pe_metadata: Option<PeMetadata>,
}

pub trait Loader {
    fn make_image(&self) -> LoadedImage;
}

pub struct RuntimeModule {
    pub image: LoadedImage,
    pub base: u64,
    pub image_size: u32,
    pub ep: u64,
    pub arch: String,
    pub emu_path: String,
    pub module_type: String,
    pub stack_commit: u32,
    pub visible_in_peb: bool,
    pub name: String,
    pub sections: Vec<SectionEntry>,
}

pub struct PeLoader {
    pub path: Option<String>,
    pub data: Option<Vec<u8>>,
    pub base_override: Option<u64>,
    pub emu_path: String,
}

impl Loader for PeLoader {
    fn make_image(&self) -> LoadedImage {
        let mut loaded = LoadedImage {
            arch: "x86".to_string(), // Default fallback
            module_type: "exe".to_string(),
            name: self.emu_path.clone(),
            emu_path: self.emu_path.clone(),
            image_base: self.base_override.unwrap_or(0x400000),
            image_size: 0,
            regions: Vec::new(),
            imports: Vec::new(),
            exports: Vec::new(),
            default_export_mode: "intercepted".to_string(),
            entry_points: Vec::new(),
            visible_in_peb: true,
            stack_size: 0x12000,
            tls_callbacks: Vec::new(),
            tls_directory_va: None,
            sections: Vec::new(),
            pe_metadata: None,
        };

        if let Some(data) = &self.data {
            if let Ok(pe) = pelite::pe64::PeFile::from_bytes(data) {
                loaded.arch = "x64".to_string();
                let opt = pe.optional_header();
                loaded.image_base = self.base_override.unwrap_or(opt.ImageBase);
                loaded.image_size = opt.SizeOfImage;
                loaded.stack_size = opt.SizeOfStackCommit as u32;

                if let Ok(exports) = pe.exports() {
                    // Export extraction deferred to specialized mapper
                }
            } else if let Ok(pe) = pelite::pe32::PeFile::from_bytes(data) {
                use pelite::pe32::Pe;
                loaded.arch = "x86".to_string();
                let opt = pe.optional_header();
                loaded.image_base = self.base_override.unwrap_or(opt.ImageBase as u64);
                loaded.image_size = opt.SizeOfImage;
                loaded.stack_size = opt.SizeOfStackCommit;
                
                if let Ok(exports) = pe.exports() {
                    // Export extraction deferred to specialized mapper
                }
            }
        }
        loaded
    }
}

pub struct ShellcodeLoader {
    pub data: Vec<u8>,
    pub arch: String,
}

impl Loader for ShellcodeLoader {
    fn make_image(&self) -> LoadedImage {
        let entry = 0x1000u64;
        LoadedImage {
            arch: self.arch.clone(),
            module_type: "shellcode".to_string(),
            name: "shellcode".to_string(),
            emu_path: "shellcode".to_string(),
            image_base: entry,
            image_size: self.data.len() as u32,
            regions: vec![MemoryRegion {
                base: entry,
                data: self.data.clone(),
                name: "shellcode".to_string(),
                perms: 0x40,
            }],
            imports: Vec::new(),
            exports: Vec::new(),
            default_export_mode: "intercepted".to_string(),
            entry_points: vec![entry],
            visible_in_peb: false,
            stack_size: 0x12000,
            tls_callbacks: Vec::new(),
            tls_directory_va: None,
            sections: vec![SectionEntry {
                name: ".text".to_string(),
                virtual_address: 0,
                virtual_size: self.data.len() as u32,
                perms: 0x40,
            }],
            pe_metadata: None,
        }
    }
}

pub struct ApiModuleLoader {
    pub name: String,
    pub arch: String,
    pub base: u64,
    pub emu_path: String,
}

impl Loader for ApiModuleLoader {
    fn make_image(&self) -> LoadedImage {
        LoadedImage {
            arch: self.arch.clone(),
            module_type: "dll".to_string(),
            name: self.name.clone(),
            emu_path: self.emu_path.clone(),
            image_base: self.base,
            image_size: 0x1000,
            regions: vec![MemoryRegion {
                base: self.base,
                data: vec![0; 0x1000],
                name: self.name.clone(),
                perms: 0x20,
            }],
            imports: Vec::new(),
            exports: Vec::new(),
            default_export_mode: "intercepted".to_string(),
            entry_points: Vec::new(),
            visible_in_peb: true,
            stack_size: 0x12000,
            tls_callbacks: Vec::new(),
            tls_directory_va: None,
            sections: vec![SectionEntry {
                name: ".text".to_string(),
                virtual_address: 0,
                virtual_size: 0x1000,
                perms: 0x20,
            }],
            pe_metadata: None,
        }
    }
}

pub struct DecoyLoader {
    pub name: String,
    pub base: u64,
    pub emu_path: String,
    pub image_size: u32,
}

impl Loader for DecoyLoader {
    fn make_image(&self) -> LoadedImage {
        LoadedImage {
            arch: "x86".to_string(),
            module_type: "decoy".to_string(),
            name: self.name.clone(),
            emu_path: self.emu_path.clone(),
            image_base: self.base,
            image_size: self.image_size,
            regions: vec![MemoryRegion {
                base: self.base,
                data: vec![0; self.image_size as usize],
                name: self.name.clone(),
                perms: 0x20,
            }],
            imports: Vec::new(),
            exports: Vec::new(),
            default_export_mode: "intercepted".to_string(),
            entry_points: Vec::new(),
            visible_in_peb: true,
            stack_size: 0x12000,
            tls_callbacks: Vec::new(),
            tls_directory_va: None,
            sections: vec![SectionEntry {
                name: ".text".to_string(),
                virtual_address: 0,
                virtual_size: self.image_size,
                perms: 0x20,
            }],
            pe_metadata: None,
        }
    }
}
