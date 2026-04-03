// Loaders for Windows binaries

use crate::errors::{Result, SpeakeasyError};
use crate::common;
use std::collections::HashMap;
use goblin::pe::PE;

#[derive(Clone, Debug)]
pub struct ImportEntry {
    pub iat_address: u64,
    pub dll_name: String,
    pub func_name: String,
}

#[derive(Clone, Debug)]
pub struct ExportEntry {
    pub name: Option<String>,
    pub address: u64,
    pub ordinal: u32,
}

#[derive(Clone, Debug)]
pub struct MemoryRegion {
    pub base: u64,
    pub data: Vec<u8>,
    pub name: String,
    pub perms: u32,
}

#[derive(Clone, Debug)]
pub struct SectionEntry {
    pub name: String,
    pub virtual_address: u64,
    pub virtual_size: u32,
    pub perms: u32,
}

#[derive(Clone, Debug)]
pub struct ResourceEntry {
    pub id: String,
    pub type_id: String,
    pub data_rva: u32,
    pub size: u32,
    pub lang_id: u32,
    pub entry_rva: u32,
}

#[derive(Clone, Debug)]
pub struct PeMetadata {
    pub subsystem: u16,
    pub timestamp: u32,
    pub machine: u16,
    pub magic: u16,
    pub resources: Vec<ResourceEntry>,
    pub string_table: HashMap<u32, String>,
}

#[derive(Clone, Debug)]
pub struct LoadedImage {
    pub arch: u32,
    pub module_type: String,
    pub name: String,
    pub emu_path: String,
    pub image_base: u64,
    pub image_size: u32,
    pub regions: Vec<MemoryRegion>,
    pub imports: Vec<ImportEntry>,
    pub exports: Vec<ExportEntry>,
    pub entry_points: Vec<u64>,
    pub sections: Vec<SectionEntry>,
    pub pe_metadata: Option<PeMetadata>,
    pub stack_size: u32,
    pub tls_callbacks: Vec<u64>,
}

pub struct RuntimeModule {
    pub image: LoadedImage,
    pub base: u64,
    pub image_size: u32,
}

impl RuntimeModule {
    pub fn new(image: LoadedImage) -> Self {
        let base = image.image_base;
        let image_size = image.image_size;
        Self {
            image,
            base,
            image_size,
        }
    }

    pub fn get_base_name(&self) -> &str {
        &self.image.name
    }
}

pub struct PeLoader {
    pub path: Option<String>,
    pub data: Option<Vec<u8>>,
    pub base_override: Option<u64>,
    pub emu_path: String,
}

impl PeLoader {
    pub fn new(path: Option<String>, data: Option<Vec<u8>>, base_override: Option<u64>, emu_path: String) -> Self {
        Self {
            path,
            data,
            base_override,
            emu_path,
        }
    }

    pub fn make_image(&self) -> Result<LoadedImage> {
        let bytes = if let Some(ref d) = self.data {
            d.clone()
        } else if let Some(ref p) = self.path {
            std::fs::read(p).map_err(|e| SpeakeasyError::ConfigError(e.to_string()))?
        } else {
            return Err(SpeakeasyError::ConfigError("No data or path provided for PeLoader".to_string()));
        };

        let pe = PE::parse(&bytes).map_err(|e| SpeakeasyError::ConfigError(e.to_string()))?;
        
        let arch = if pe.is_64 { 9 } else { 0 }; // ARCH_AMD64 = 9, ARCH_X86 = 0
        let image_base = self.base_override.unwrap_or(pe.image_base);
        
        let mut sections = Vec::new();
        for sect in &pe.sections {
            sections.push(SectionEntry {
                name: sect.name().unwrap_or("").to_string(),
                virtual_address: sect.virtual_address as u64,
                virtual_size: sect.virtual_size,
                perms: self.perms_from_chars(sect.characteristics),
            });
        }

        let mut imports = Vec::new();
        for import in &pe.imports {
            imports.push(ImportEntry {
                iat_address: import.offset as u64,
                dll_name: import.dll.to_string(),
                func_name: import.name.to_string(),
            });
        }

        let mut exports = Vec::new();
        for export in &pe.exports {
            exports.push(ExportEntry {
                name: export.name.map(|n| n.to_string()),
                address: export.rva as u64 + image_base,
                ordinal: export.ordinal as u32,
            });
        }

        let pe_metadata = PeMetadata {
            subsystem: pe.header.optional_header.map(|h| h.windows_fields.subsystem).unwrap_or(0),
            timestamp: pe.header.coff_header.time_date_stamp,
            machine: pe.header.coff_header.machine,
            magic: pe.header.optional_header.map(|h| h.standard_fields.magic).unwrap_or(0),
            resources: Vec::new(), // TODO: Implement resource parsing
            string_table: HashMap::new(),
        };

        let module_type = if pe_metadata.subsystem == 1 {
            "driver".to_string()
        } else if pe.header.coff_header.characteristics & 0x2000 != 0 {
            "dll".to_string()
        } else {
            "exe".to_string()
        };

        let mut entry_points = Vec::new();
        if pe.entry != 0 {
            entry_points.push(image_base + pe.entry as u64);
        }

        let name = self.path.as_ref()
            .and_then(|p| std::path::Path::new(p).file_stem())
            .and_then(|s| s.to_str())
            .unwrap_or("unknown")
            .to_string();

        // Placeholder for memory mapping - in reality we should map sections to a buffer
        let region = MemoryRegion {
            base: image_base,
            data: bytes, // Simplified: should be mapped image
            name: "pe_image".to_string(),
            perms: common::PERM_MEM_RWX,
        };

        Ok(LoadedImage {
            arch,
            module_type,
            name,
            emu_path: self.emu_path.clone(),
            image_base,
            image_size: pe.header.optional_header.map(|h| h.windows_fields.size_of_image).unwrap_or(0),
            regions: vec![region],
            imports,
            exports,
            entry_points,
            sections,
            pe_metadata: Some(pe_metadata),
            stack_size: pe.header.optional_header.map(|h| h.windows_fields.size_of_stack_reserve as u32).unwrap_or(0x12000),
            tls_callbacks: Vec::new(), // TODO: Implement TLS callback parsing
        })
    }

    fn perms_from_chars(&self, chars: u32) -> u32 {
        let mut perms = common::PERM_MEM_NONE;
        if chars & 0x40000000 != 0 { perms |= common::PERM_MEM_READ; }
        if chars & 0x80000000 != 0 { perms |= common::PERM_MEM_WRITE; }
        if chars & 0x20000000 != 0 { perms |= common::PERM_MEM_EXEC; }
        perms
    }
}

pub struct ShellcodeLoader {
    pub data: Vec<u8>,
    pub arch: u32,
}

impl ShellcodeLoader {
    pub fn make_image(&self) -> Result<LoadedImage> {
        let size = self.data.len() as u32;
        Ok(LoadedImage {
            arch: self.arch,
            module_type: "shellcode".to_string(),
            name: "shellcode".to_string(),
            emu_path: "".to_string(),
            image_base: 0,
            image_size: size,
            regions: vec![MemoryRegion {
                base: 0,
                data: self.data.clone(),
                name: "shellcode".to_string(),
                perms: common::PERM_MEM_RWX,
            }],
            imports: Vec::new(),
            exports: Vec::new(),
            entry_points: Vec::new(),
            sections: vec![SectionEntry {
                name: "shellcode".to_string(),
                virtual_address: 0,
                virtual_size: size,
                perms: common::PERM_MEM_RWX,
            }],
            pe_metadata: None,
            stack_size: 0x12000,
            tls_callbacks: Vec::new(),
        })
    }
}

pub struct ApiModuleLoader {
    pub name: String,
    pub arch: u32,
    pub base: u64,
    pub emu_path: String,
}

impl ApiModuleLoader {
    pub fn make_image(&self) -> Result<LoadedImage> {
        // Implementation for generating JIT PE
        Ok(LoadedImage {
            arch: self.arch,
            module_type: "dll".to_string(),
            name: self.name.clone(),
            emu_path: self.emu_path.clone(),
            image_base: self.base,
            image_size: 0x1000, // Placeholder
            regions: Vec::new(),
            imports: Vec::new(),
            exports: Vec::new(),
            entry_points: Vec::new(),
            sections: Vec::new(),
            pe_metadata: None,
            stack_size: 0x12000,
            tls_callbacks: Vec::new(),
        })
    }
}

pub struct DecoyLoader {
    pub name: String,
    pub base: u64,
    pub emu_path: String,
    pub image_size: u32,
}

impl DecoyLoader {
    pub fn make_image(&self) -> Result<LoadedImage> {
        Ok(LoadedImage {
            arch: 0,
            module_type: "decoy".to_string(),
            name: self.name.clone(),
            emu_path: self.emu_path.clone(),
            image_base: self.base,
            image_size: self.image_size,
            regions: Vec::new(),
            imports: Vec::new(),
            exports: Vec::new(),
            entry_points: Vec::new(),
            sections: Vec::new(),
            pe_metadata: None,
            stack_size: 0x12000,
            tls_callbacks: Vec::new(),
        })
    }
}
