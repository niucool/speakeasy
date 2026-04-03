// Windows API - Central API handler management

use crate::binemu::BinaryEmulator;
use crate::errors::Result;
use crate::winenv::api::{kernelmode, usermode, ApiHandler};
use std::collections::HashMap;

pub struct WindowsApi {
    mods: HashMap<String, Box<dyn ApiHandler>>,
    instances: Vec<Box<dyn ApiHandler>>,
    data: HashMap<String, u64>,
    ptr_size: u32,
}

impl WindowsApi {
    pub fn new(arch: u32) -> Self {
        let ptr_size = if arch == 9 { 8 } else { 4 }; // ARCH_AMD64 = 9

        Self {
            mods: HashMap::new(),
            instances: Vec::new(),
            data: HashMap::new(),
            ptr_size,
        }
    }

    pub fn load_api_handler(&mut self, mod_name: &str) -> Option<&mut Box<dyn ApiHandler>> {
        let name = mod_name.to_lowercase();
        
        if let Some(handler) = self.mods.get_mut(&name) {
            return Some(handler);
        }

        let handler: Option<Box<dyn ApiHandler>> = match name.as_str() {
            "ntoskrnl" => Some(Box::new(kernelmode::NtoskrnlHandler::new())),
            "hal" => Some(Box::new(kernelmode::HalHandler::new())),
            "ndis" => Some(Box::new(kernelmode::NdisHandler::new())),
            "netio" => Some(Box::new(kernelmode::NetioHandler::new())),
            "wdfldr" => Some(Box::new(kernelmode::WdfldrHandler::new())),
            "fwpkclnt" => Some(Box::new(kernelmode::FwpkclntHandler::new())),
            "usbd" => Some(Box::new(kernelmode::UsbdHandler::new())),
            "kernel32" => Some(Box::new(usermode::Kernel32Handler::new())),
            "user32" => Some(Box::new(usermode::User32Handler::new())),
            "ws2_32" => Some(Box::new(usermode::Ws2_32Handler::new())),
            "ntdll" => Some(Box::new(usermode::NtdllHandler::new())),
            "advapi32" => Some(Box::new(usermode::Advapi32Handler::new())),
            "shell32" => Some(Box::new(usermode::Shell32Handler::new())),
            "shlwapi" => Some(Box::new(usermode::ShlwapiHandler::new())),
            "wininet" => Some(Box::new(usermode::WininetHandler::new())),
            "winhttp" => Some(Box::new(usermode::WinhttpHandler::new())),
            "gdi32" => Some(Box::new(usermode::Gdi32Handler::new())),
            "crypt32" => Some(Box::new(usermode::Crypt32Handler::new())),
            "msvcrt" => Some(Box::new(usermode::MsvcrtHandler::new())),
            "ole32" => Some(Box::new(usermode::Ole32Handler::new())),
            "oleaut32" => Some(Box::new(usermode::Oleaut32Handler::new())),
            "netapi32" => Some(Box::new(usermode::Netapi32Handler::new())),
            "netutils" => Some(Box::new(usermode::NetutilsHandler::new())),
            "bcrypt" => Some(Box::new(usermode::BcryptHandler::new())),
            "ncrypt" => Some(Box::new(usermode::NcryptHandler::new())),
            "psapi" => Some(Box::new(usermode::PsapiHandler::new())),
            "iphlpapi" => Some(Box::new(usermode::IphlpapiHandler::new())),
            "dnsapi" => Some(Box::new(usermode::DnsapiHandler::new())),
            "mpr" => Some(Box::new(usermode::MprHandler::new())),
            "winmm" => Some(Box::new(usermode::WinmmHandler::new())),
            "comctl32" => Some(Box::new(usermode::Comctl32Handler::new())),
            "com_api" => Some(Box::new(usermode::ComApiHandler::new())),
            "bcryptprimitives" => Some(Box::new(usermode::BcryptprimitivesHandler::new())),
            "advpack" => Some(Box::new(usermode::AdvpackHandler::new())),
            "wkscli" => Some(Box::new(usermode::WkscliHandler::new())),
            "lz32" => Some(Box::new(usermode::Lz32Handler::new())),
            "mscoree" => Some(Box::new(usermode::MscoreeHandler::new())),
            "msi32" => Some(Box::new(usermode::Msi32Handler::new())),
            "msimg32" => Some(Box::new(usermode::Msimg32Handler::new())),
            "msvfw32" => Some(Box::new(usermode::Msvfw32Handler::new())),
            "urlmon" => Some(Box::new(usermode::UrlmonHandler::new())),
            "sfc" => Some(Box::new(usermode::SfcHandler::new())),
            "sfc_os" => Some(Box::new(usermode::SfcOsHandler::new())),
            "secur32" => Some(Box::new(usermode::Secur32Handler::new())),
            "rpcrt4" => Some(Box::new(usermode::Rpcrt4Handler::new())),
            "wtsapi32" => Some(Box::new(usermode::Wtsapi32Handler::new())),
            _ => None,
        };

        if let Some(h) = handler {
            self.instances.push(h);
            if let Some(instance) = self.instances.last() {
                let h = self.instances.remove(self.instances.len() - 1);
                self.mods.insert(name.clone(), Box::new(h));
            }
        }

        self.mods.get_mut(&name)
    }

    pub fn get_data_export_handler(&mut self, mod_name: &str, _exp_name: &str) -> (Option<&mut Box<dyn ApiHandler>>, Option<fn(&mut Box<dyn ApiHandler>, u64) -> u64>)> {
        let name = mod_name.to_lowercase();
        
        if !self.mods.contains_key(&name) {
            self.load_api_handler(mod_name);
        }
        
        (self.mods.get_mut(&name), None)
    }

    pub fn get_export_func_handler(&mut self, mod_name: &str, _exp_name: &str) -> (Option<&mut Box<dyn ApiHandler>>, Option<fn(&mut Box<dyn ApiHandler>, &mut dyn BinaryEmulator, &str, &[u64]) -> Result<u64>>) {
        let name = mod_name.to_lowercase();
        
        if !self.mods.contains_key(&name) {
            self.load_api_handler(mod_name);
        }
        
        (self.mods.get_mut(&name), None)
    }

    pub fn call_api_func(&mut self, emu: &mut dyn BinaryEmulator, mod_name: &str, func_name: &str, args: &[u64]) -> Result<u64> {
        let name = mod_name.to_lowercase();
        
        if let Some(handler) = self.mods.get_mut(&name) {
            return handler.call(emu, func_name, args);
        }
        
        Ok(0)
    }

    pub fn call_data_func(&mut self, mod_name: &str, ptr: u64) -> u64 {
        let name = mod_name.to_lowercase();
        
        if let Some(_handler) = self.mods.get(&name) {
            if ptr == 0 {
                return 0x10000;
            }
        }
        
        0
    }

    pub fn get_ptr_size(&self) -> u32 {
        self.ptr_size
    }
}
