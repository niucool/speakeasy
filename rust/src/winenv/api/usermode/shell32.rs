use crate::winenv::api::ApiHandler;
use crate::winenv::defs::windows::shell32 as shell32defs;

pub struct Shell32Handler {
    next_handle: u32,
}

impl Shell32Handler {
    pub fn new() -> Self {
        Self { next_handle: 0x4000 }
    }

    fn new_handle(&mut self) -> u32 {
        let handle = self.next_handle;
        self.next_handle += 4;
        handle
    }

    pub fn shell_execute(
        &mut self,
        _verb: Option<&str>,
        file: &str,
        _parameters: Option<&str>,
        _directory: Option<&str>,
        _show: i32,
    ) -> u32 {
        if file.is_empty() {
            return 0;
        }
        self.new_handle()
    }

    pub fn shell_execute_info(&mut self, execute_info: &shell32defs::SHELLEXECUTEINFOA) -> u32 {
        if execute_info.lpFile == 0 {
            return 0;
        }
        self.new_handle()
    }

    pub fn sh_get_folder_path(&self, csidl: u32) -> Option<String> {
        match csidl {
            0x24 => Some("C:\\Windows".to_string()),
            0x25 => Some("C:\\Windows\\System32".to_string()),
            0x1A => Some("C:\\Users\\User\\AppData\\Roaming".to_string()),
            0x1C => Some("C:\\Users\\User\\AppData\\Local".to_string()),
            0x28 => Some("C:\\Users\\User".to_string()),
            0x26 => Some("C:\\Program Files".to_string()),
            0x00..=0x45 => Some("C:\\".to_string()),
            _ => None,
        }
    }
}

impl Default for Shell32Handler {
    fn default() -> Self {
        Self::new()
    }
}

impl ApiHandler for Shell32Handler {
    fn call(&mut self, args: &[u64]) -> u64 {
        match args.len() {
            2 => self.sh_get_folder_path(args[0] as u32).map(|path| path.len() as u64).unwrap_or(0),
            4 => self.shell_execute(None, "cmd.exe", None, None, args[3] as i32) as u64,
            _ => 0,
        }
    }

    fn get_name(&self) -> &str {
        "Shell32"
    }
}
