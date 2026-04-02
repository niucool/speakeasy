use crate::winenv::api::ApiHandler;

pub struct Gdi32Handler {
    next_dc: u32,
}

impl Gdi32Handler {
    pub fn new() -> Self {
        Self { next_dc: 0x5000 }
    }

    pub fn create_compatible_dc(&mut self) -> u32 {
        let dc = self.next_dc;
        self.next_dc += 4;
        dc
    }

    pub fn delete_dc(&self, dc: u32) -> bool {
        dc != 0
    }

    pub fn get_device_caps(&self, _dc: u32, index: i32) -> i32 {
        match index {
            8 => 800,
            10 => 600,
            12 => 32,
            _ => 1,
        }
    }

    pub fn set_bk_mode(&self, _dc: u32, mode: i32) -> i32 {
        mode
    }
}

impl Default for Gdi32Handler {
    fn default() -> Self {
        Self::new()
    }
}

impl ApiHandler for Gdi32Handler {
    fn call(&mut self, args: &[u64]) -> u64 {
        match args.len() {
            0 => self.create_compatible_dc() as u64,
            1 => u64::from(self.delete_dc(args[0] as u32)),
            2 => self.get_device_caps(args[0] as u32, args[1] as i32) as u64,
            _ => 0,
        }
    }

    fn get_name(&self) -> &str {
        "Gdi32"
    }
}
