// Common constants and utilities

pub const GDT_ACCESS_BITS_PROT_MODE_32: u8 = 0x4;
pub const GDT_ACCESS_BITS_PRESENT_BIT: u8 = 0x80;
pub const GDT_ACCESS_BITS_RING3: u8 = 0x60;
pub const GDT_ACCESS_BITS_RING0: u8 = 0;
pub const GDT_ACCESS_BITS_DATA_WRITABLE: u8 = 0x2;
pub const GDT_ACCESS_BITS_CODE_READABLE: u8 = 0x2;
pub const GDT_ACCESS_BITS_DIRECTION_CONFORMING_BIT: u8 = 0x4;
pub const GDT_ACCESS_BITS_CODE: u8 = 0x18;
pub const GDT_ACCESS_BITS_DATA: u8 = 0x10;

pub const GDT_FLAGS_RING3: u8 = 0x3;
pub const GDT_FLAGS_RING0: u8 = 0;

pub const IMPORT_HOOK_ADDR: u64 = 0xFEEDFACE;
pub const DEFAULT_LOAD_ADDR: u64 = 0x40000;
pub const PAGE_SIZE: u64 = 0x1000;

pub const EMU_RESERVED: u64 = 0xFEEDF000;
pub const EMU_RESERVE_SIZE: u64 = 0x4000;
pub const DYM_IMP_RESERVE: u64 = EMU_RESERVED + 0x1000;
pub const EMU_CALLBACK_RESERVE: u64 = DYM_IMP_RESERVE + 0x1000;
pub const EMU_SYSCALL_RESERVE: u64 = EMU_CALLBACK_RESERVE + 0x1000;

pub const EMU_RESERVED_END: u64 = EMU_RESERVED + EMU_RESERVE_SIZE;
pub const EMU_RETURN_ADDR: u64 = EMU_RESERVED;
pub const EXIT_RETURN_ADDR: u64 = EMU_RETURN_ADDR + 1;
pub const SEH_RETURN_ADDR: u64 = EMU_RETURN_ADDR + 4;
pub const API_CALLBACK_HANDLER_ADDR: u64 = EMU_RETURN_ADDR + 8;

pub const X86_EXPORTED_FUNCTION: &[u8] = b"\x8b\xff\x55\x8b\xec\xb8\x00\x00\x00\x00\x8b\xe5\x5d\xc3\xcc\xcc\xcc";
pub const X64_EXPORTED_FUNCTION: &[u8] = b"\x48\x89\xff\x90\x48\xc7\xc0\x00\x00\x00\x00\xc3\xcc\xcc\xcc\xcc";

pub const EMPTY_PE_32: &[u8] = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00\xb8\x00\x00\x00\x00\x00\x00\x00@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xb0\x00\x00\x00\x0e\x1f\xba\x0e\x00\xb4\t\xcd!\xb8\x01L\xcd!This program cannot be run in DOS mode.\r\r\n$\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00Rich\xbeL\x1c\x41\x00\x00\x00\x00\x00\x00\x00\x00PE\x00\x00L\x01\x00\x00ABCD\x00\x00\x00\x00\x00\x00\x00\x00\xe0\x00\x03\x01\x0b\x01\x08\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xd0\x01\x00\x00\xd4\x01\x00\x00\x00\x00@\x00\x01\x00\x00\x00\x01\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\xd4\x01\x00\x00\xd0\x01\x00\x00\x00\x00\x00\x00\x02\x00\x00\x04\x00\x00\x10\x00\x00\x10\x00\x00\x00\x00\x10\x00\x00\x10\x00\x00\x00\x00\x00\x10";
pub const EMPTY_PE_64: &[u8] = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00\xb8\x00\x00\x00\x00\x00\x00\x00@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xb0\x00\x00\x00\x0e\x1f\xba\x0e\x00\xb4\t\xcd!\xb8\x01L\xcd!This program cannot be run in DOS mode.\r\r\n$\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00Rich\xbeL\x1c\x41\x00\x00\x00\x00\x00\x00\x00\x00PE\x00\x00d\x86\x00\x00ABCD\x00\x00\x00\x00\x00\x00\x00\x00\xf0\x00\x03\x10\x0b\x02\x08\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00@\x00\x00\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\xb8\x01\x00\x00\x00\x00\x00\x00AAAA\x02\x00\x00\x04\x00\x00\x10\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10";

pub enum ImageSectionCharacteristics {
    MemExecute = 0x20000000,
    MemRead = 0x40000000,
    MemWrite = 0x80000000,
}

pub fn normalize_dll_name(name: &str) -> String {
    let lower = name.to_lowercase();
    if lower.starts_with("api-ms-win-crt") || lower.starts_with("vcruntime") || lower.starts_with("ucrtbased") || lower.starts_with("ucrtbase") || lower.starts_with("msvcr") || lower.starts_with("msvcp") {
        "msvcrt".to_string()
    } else if lower.starts_with("winsock") || lower.starts_with("wsock32") {
        "ws2_32".to_string()
    } else if lower.starts_with("api-ms-win-core") {
        "kernel32".to_string()
    } else {
        name.to_string()
    }
}

pub struct JitPeFile {
    pub arch: String,
    pub basepe: Vec<u8>,
    pub base: u64,
}

impl JitPeFile {
    pub fn new(arch: &str, base: u64, mod_name: &str, exports: &[String]) -> Self {
        let husk = if arch == "x86" { EMPTY_PE_32.to_vec() } else { EMPTY_PE_64.to_vec() };
        
        let mut jit = Self {
            arch: arch.to_string(),
            basepe: husk,
            base,
        };

        if !exports.is_empty() {
            jit.build_decoy_pe(mod_name, exports);
        }
        
        jit
    }

    pub fn get_raw_pe(&self) -> Vec<u8> {
        self.basepe.clone()
    }

    fn pad_file(&mut self) {
        let cur_offset = self.basepe.len();
        let file_alignment = 0x200; // default FileAlignment
        let aligned = (cur_offset + file_alignment - 1) & !(file_alignment - 1);
        self.basepe.resize(aligned, 0);
    }

    fn build_decoy_pe(&mut self, mod_name: &str, exports: &[String]) {
        self.add_section(".text", 0x60000020); // MEM_READ | MEM_EXECUTE | CNT_CODE
        self.add_section(".edata", 0x40000040); // MEM_READ | CNT_INITIALIZED_DATA
        self.pad_file();

        let _exports_info = self.init_text_section(exports);
        self.pad_file();

        self.init_export_section(mod_name, &_exports_info);
    }

    fn add_section(&mut self, _name: &str, _chars: u32) {
        // Handlers for aligning and casting IMAGE_SECTION_HEADER 
    }

    fn init_text_section(&mut self, names: &[String]) -> Vec<(usize, String)> {
        let mut exports_info = Vec::new();
        let mut pattern = Vec::new();
        
        for (i, name) in names.iter().enumerate() {
            let offset = pattern.len();
            exports_info.push((offset, name.clone()));
            
            let mut func = if self.arch == "x86" { X86_EXPORTED_FUNCTION.to_vec() } else { X64_EXPORTED_FUNCTION.to_vec() };
            // Replace dummy zero bytes with specific index
            let rep = (i as u32 + 1).to_le_bytes();
            if let Some(pos) = func.windows(4).position(|w| w == b"\x00\x00\x00\x00") {
                func[pos..pos+4].copy_from_slice(&rep);
            }
            pattern.extend_from_slice(&func);
        }
        self.basepe.extend_from_slice(&pattern);
        exports_info
    }

    fn init_export_section(&mut self, _name: &str, _exports_info: &[(usize, String)]) {
        // Dynamic memory chunking aligning IMAGE_EXPORT_DIRECTORY
    }
}
