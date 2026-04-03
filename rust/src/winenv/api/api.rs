// API handler base class - Ported from Python api.py

use crate::binemu::BinaryEmulator;
use crate::errors::Result;
use crate::structs::EmuStruct;
use std::collections::HashMap;

pub type ApiContext = Option<HashMap<String, String>>;

pub trait ApiHandler {
    fn call(&mut self, emu: &mut dyn BinaryEmulator, name: &str, args: &[u64]) -> Result<u64>;
    fn get_name(&self) -> &str;
}

pub struct ApiHandlerBase {
    pub funcs: HashMap<String, ApiFuncInfo>,
    pub data: HashMap<String, fn(addr: u64) -> u64>,
    pub mod_name: String,
    pub ptr_size: u32,
}

#[derive(Clone)]
pub struct ApiFuncInfo {
    pub name: String,
    pub argc: usize,
    pub conv: u32,
    pub ordinal: Option<u32>,
}

impl ApiHandlerBase {
    pub fn new(arch: u32) -> Self {
        let ptr_size = if arch == 9 { 8 } else { 4 }; // ARCH_AMD64 = 9
        Self {
            funcs: HashMap::new(),
            data: HashMap::new(),
            mod_name: String::new(),
            ptr_size,
        }
    }

    pub fn get_ptr_size(&self) -> u32 {
        self.ptr_size
    }

    pub fn sizeof<T: EmuStruct>(&self) -> usize {
        T::sizeof(&unsafe { std::mem::zeroed() })
    }

    pub fn get_bytes<T: EmuStruct>(&self, obj: &T) -> Vec<u8> {
        obj.get_bytes()
    }

    pub fn cast<T: EmuStruct>(&self, bytez: &[u8]) -> T {
        T::cast(bytez)
    }

    pub fn mem_cast<T: EmuStruct>(&self, emu: &dyn BinaryEmulator, addr: u64) -> T {
        let size = self.sizeof::<T>();
        if let Ok(data) = emu.mem_read(addr, size) {
            self.cast(&data)
        } else {
            unsafe { std::mem::zeroed() }
        }
    }

    pub fn read_ansi_string(&self, emu: &dyn BinaryEmulator, addr: u64) -> String {
        let ans = self.mem_cast::<crate::winenv::defs::nt::ntoskrnl::STRING>(emu, addr);
        emu.read_mem_string(ans.Buffer, 1, ans.Length as usize)
    }

    pub fn read_unicode_string(&self, emu: &dyn BinaryEmulator, addr: u64) -> String {
        let us = self.mem_cast::<crate::winenv::defs::nt::ntoskrnl::UNICODE_STRING>(emu, addr);
        emu.read_mem_string(us.Buffer, 2, (us.Length / 2) as usize)
    }

    pub fn read_wide_string(
        &self,
        emu: &dyn BinaryEmulator,
        addr: u64,
        max_chars: usize,
    ) -> String {
        emu.read_mem_string(addr, 2, max_chars)
    }

    pub fn read_string(&self, emu: &dyn BinaryEmulator, addr: u64, max_chars: usize) -> String {
        emu.read_mem_string(addr, 1, max_chars)
    }

    pub fn write_wide_string(
        &self,
        emu: &mut dyn BinaryEmulator,
        string: &str,
        addr: u64,
    ) -> Result<()> {
        let wide: Vec<u8> = string
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        emu.mem_write(addr, &wide)?;
        Ok(())
    }

    pub fn write_string(
        &self,
        emu: &mut dyn BinaryEmulator,
        string: &str,
        addr: u64,
    ) -> Result<()> {
        emu.mem_write(addr, string.as_bytes())?;
        Ok(())
    }

    pub fn get_max_int(&self) -> u64 {
        if self.ptr_size == 8 {
            0xFFFFFFFFFFFFFFFF
        } else {
            0xFFFFFFFF
        }
    }

    pub fn get_data_handler(&self, exp_name: &str) -> Option<&fn(addr: u64) -> u64> {
        self.data.get(exp_name)
    }

    pub fn get_func_handler(&self, exp_name: &str) -> Option<&ApiFuncInfo> {
        if exp_name.starts_with("ordinal_") {
            let parts: Vec<&str> = exp_name.split('_').collect();
            if parts.len() == 2 {
                if let Ok(ord_num) = parts[1].parse::<u32>() {
                    return self.funcs.get(&ord_num.to_string());
                }
            }
        }
        self.funcs.get(exp_name)
    }

    pub fn get_encoding(&self, char_width: u32) -> &'static str {
        match char_width {
            2 => "utf-16le",
            1 => "utf-8",
            _ => panic!("No encoding found for char width: {}", char_width),
        }
    }

    pub fn get_char_width(&self, func_name: &str) -> u32 {
        if func_name.ends_with('A') {
            1
        } else if func_name.ends_with('W') {
            2
        } else {
            1 // Default to ANSI
        }
    }

    pub fn get_va_arg_count(&self, fmt: &str) -> usize {
        let i = fmt.matches("%%").count();
        let c = fmt.matches('%').count();
        let ll = fmt.matches("%ll").count();
        c - i + ll
    }

    pub fn va_args(&self, emu: &dyn BinaryEmulator, va_list: u64, num_args: usize) -> Vec<u64> {
        let mut args = Vec::new();
        let mut ptr = va_list;
        let ptrsize = self.ptr_size as usize;

        for _ in 0..num_args {
            if let Ok(data) = emu.mem_read(ptr, ptrsize) {
                let val = match ptrsize {
                    4 => u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as u64,
                    8 => u64::from_le_bytes([
                        data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
                    ]),
                    _ => 0,
                };
                args.push(val);
            }
            ptr += ptrsize as u64;
        }
        args
    }

    pub fn do_str_format(&self, fmt: &str, argv: &[u64]) -> String {
        let mut result = String::new();
        let mut args: Vec<u64> = argv.to_vec();
        let mut inside_fmt = false;
        let mut curr_fmt = String::new();
        let mut new_fmts: Vec<String> = Vec::new();

        let chars: Vec<char> = fmt.chars().collect();
        let mut i = 0;
        while i < chars.len() {
            let c = chars[i];

            if c == '%' {
                if inside_fmt {
                    inside_fmt = false;
                } else {
                    inside_fmt = true;
                    curr_fmt = String::new();
                }
            }

            if inside_fmt {
                match c {
                    'S' => {
                        // Wide string
                        let s = String::new();
                        new_fmts.push(s);
                        inside_fmt = false;
                    }
                    's' => {
                        if curr_fmt.starts_with('w') {
                            // Wide string
                            let s = String::new();
                            new_fmts.push(s);
                        } else {
                            // ANSI string
                            let s = String::new();
                            new_fmts.push(s);
                        }
                        inside_fmt = false;
                    }
                    'x' | 'X' | 'd' | 'u' | 'i' => {
                        if curr_fmt.starts_with("ll") && self.ptr_size == 8 {
                            if !args.is_empty() {
                                new_fmts.push(format!("{:x}", args.remove(0)));
                            }
                        } else {
                            if !args.is_empty() {
                                new_fmts.push(format!("{}", 0xFFFFFFFF & args.remove(0)));
                            }
                        }
                        inside_fmt = false;
                    }
                    'c' => {
                        if !args.is_empty() {
                            new_fmts.push(format!("{}", 0xFF & args.remove(0) as u8 as char));
                        }
                        inside_fmt = false;
                    }
                    'P' => {
                        if !args.is_empty() {
                            new_fmts.push(format!("{:X}", args.remove(0)));
                        }
                        inside_fmt = false;
                    }
                    'p' => {
                        if !args.is_empty() {
                            new_fmts.push(format!("{:x}", args.remove(0)));
                        }
                        inside_fmt = false;
                    }
                    'l' => {
                        curr_fmt.push(c);
                    }
                    'w' => {
                        curr_fmt.push(c);
                    }
                    _ => {}
                }

                if inside_fmt && "diuxXfFeEgGaAcspn".contains(c) {
                    inside_fmt = false;
                }
            }

            if args.is_empty() && !new_fmts.is_empty() {
                break;
            }

            i += 1;
        }

        // Build result string
        result = fmt.to_string();
        for fm in new_fmts.iter() {
            if let Some(pos) = result.find("%s") {
                result = format!("{}{}{}", &result[..pos], fm, &result[pos + 2..]);
            } else if let Some(pos) = result.find("%x") {
                result = format!("{}{}{}", &result[..pos], fm, &result[pos + 2..]);
            } else if let Some(pos) = result.find("%d") {
                result = format!("{}{}{}", &result[..pos], fm, &result[pos + 2..]);
            } else if let Some(pos) = result.find("%X") {
                result = format!("{}{}{}", &result[..pos], fm, &result[pos + 2..]);
            }
        }

        result
    }
}

// Call conv constants (from Python _arch)
pub const CALL_CONV_STDCALL: u32 = 0;
pub const CALL_CONV_CDECL: u32 = 1;
pub const CALL_CONV_FASTCALL: u32 = 2;
pub const VAR_ARGS: usize = 999;

// Architecture constants
pub const ARCH_X86: u32 = 5;
pub const ARCH_AMD64: u32 = 9;

// Decorator functions (for compatibility with Python code generation)
pub struct ApiHook;

impl ApiHook {
    pub fn apihook(
        impname: Option<&str>,
        argc: usize,
        conv: u32,
        ordinal: Option<u32>,
    ) -> ApiFuncInfo {
        ApiFuncInfo {
            name: impname.map(|s| s.to_string()).unwrap_or_default(),
            argc,
            conv,
            ordinal,
        }
    }

    pub fn impdata(impname: &str) -> fn(addr: u64) -> u64 {
        |addr| addr
    }
}
