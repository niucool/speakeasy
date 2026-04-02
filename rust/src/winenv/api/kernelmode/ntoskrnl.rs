use crate::winenv::api::ApiHandler;
use crate::winenv::defs::nt::ddk;
use crate::winenv::defs::windows::windows as windefs;

pub struct NtOsKrnlHandler {
    current_irql: u32,
    next_pool_address: u64,
}

impl NtOsKrnlHandler {
    pub fn new() -> Self {
        Self {
            current_irql: ddk::PASSIVE_LEVEL,
            next_pool_address: 0x7000_0000,
        }
    }

    pub fn get_current_irql(&self) -> u32 {
        self.current_irql
    }

    pub fn set_current_irql(&mut self, irql: u32) -> u32 {
        let previous = self.current_irql;
        self.current_irql = irql;
        previous
    }

    pub fn win_perms_to_emu_perms(&self, win_perms: u32) -> u32 {
        let mut perms = 0;
        if win_perms & windefs::PAGE_EXECUTE_READWRITE != 0 {
            return 0b111;
        }
        if win_perms & windefs::PAGE_NOACCESS != 0 {
            return 0;
        }
        if win_perms & (windefs::PAGE_EXECUTE | windefs::PAGE_EXECUTE_READ) != 0 {
            perms |= 0b001;
        }
        if win_perms
            & (windefs::PAGE_EXECUTE_READ | windefs::PAGE_READONLY | windefs::PAGE_READWRITE)
            != 0
        {
            perms |= 0b010;
        }
        if win_perms & windefs::PAGE_READWRITE != 0 {
            perms |= 0b100;
        }
        perms
    }

    pub fn rtl_init_ansi_string(&self, source: &str) -> NtString {
        NtString {
            length: source.len() as u16,
            maximum_length: source.len() as u16,
            buffer: source.as_ptr() as u64,
        }
    }

    pub fn rtl_init_unicode_string(&self, source: &str) -> NtString {
        let wide_len = source.encode_utf16().count() as u16 * 2;
        NtString {
            length: wide_len,
            maximum_length: wide_len,
            buffer: source.as_ptr() as u64,
        }
    }

    pub fn ex_allocate_pool_with_tag(&mut self, _pool_type: u32, number_of_bytes: usize, _tag: u32) -> u64 {
        let base = self.next_pool_address;
        self.next_pool_address += number_of_bytes.max(0x10) as u64;
        base
    }

    pub fn ex_free_pool(&mut self, _pool: u64) -> u32 {
        ddk::STATUS_SUCCESS
    }

    pub fn dbg_print(&self, format_string: &str, args: &[u64]) -> String {
        if args.is_empty() {
            return format_string.to_string();
        }
        format!("{format_string} {:?}", args)
    }
}

impl Default for NtOsKrnlHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl ApiHandler for NtOsKrnlHandler {
    fn call(&mut self, args: &[u64]) -> u64 {
        match args.len() {
            1 => self.ex_free_pool(args[0]).into(),
            3 => self.ex_allocate_pool_with_tag(args[0] as u32, args[1] as usize, args[2] as u32),
            _ => 0,
        }
    }

    fn get_name(&self) -> &str {
        "NTOSKRNL"
    }
}

#[derive(Clone, Debug, Default)]
pub struct NtString {
    pub length: u16,
    pub maximum_length: u16,
    pub buffer: u64,
}
