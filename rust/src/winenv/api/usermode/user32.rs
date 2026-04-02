use std::collections::HashMap;

use crate::config::SpeakeasyConfig;
use crate::windows::sessman::SessionManager;
use crate::winenv::api::ApiHandler;
use crate::winenv::defs::windows::user32 as windefs;

pub struct User32Handler {
    sessman: SessionManager,
    window_hooks: HashMap<u32, (i32, u64, u64)>,
    wndprocs: HashMap<u32, u64>,
    next_handle: u32,
    synthetic_async_keys: Vec<u32>,
    synthetic_async_key_index: usize,
}

impl User32Handler {
    pub fn new() -> Self {
        Self {
            sessman: SessionManager::new(&SpeakeasyConfig::default()),
            window_hooks: HashMap::new(),
            wndprocs: HashMap::new(),
            next_handle: 4,
            synthetic_async_keys: vec![0x41, 0x42, 0x43],
            synthetic_async_key_index: 0,
        }
    }

    fn get_handle(&mut self) -> u32 {
        self.next_handle += 4;
        self.next_handle
    }

    pub fn get_desktop_window(&self) -> u32 {
        self.sessman
            .get_current_desktop()
            .map(|desktop| desktop.desktop_window.handle)
            .unwrap_or(0)
    }

    pub fn register_class_ex(&mut self, class_name: Option<String>, wndproc: u64) -> u32 {
        let atom = self.sessman.create_window_class(wndproc, class_name.clone());
        if let Some(name) = class_name {
            self.wndprocs.insert(atom, wndproc);
            self.sessman.create_window(Some(name), None);
        }
        atom
    }

    pub fn create_window_ex(&mut self, class_name: Option<String>, window_name: Option<String>) -> u32 {
        self.sessman.create_window(window_name, class_name)
    }

    pub fn message_box(&self, _text: &str, _caption: &str, _message_type: u32) -> i32 {
        2
    }

    pub fn get_async_key_state(&mut self, vkey: u32) -> u16 {
        if self.synthetic_async_key_index >= self.synthetic_async_keys.len() {
            return 0;
        }
        if vkey != self.synthetic_async_keys[self.synthetic_async_key_index] {
            return 0;
        }
        self.synthetic_async_key_index += 1;
        0x8001
    }

    pub fn get_keyboard_type(&self, type_flag: i32) -> i32 {
        match type_flag {
            0 => 4,
            1 => 0,
            2 => 12,
            _ => 0,
        }
    }

    pub fn get_system_metrics(&self, _index: i32) -> i32 {
        1
    }

    pub fn set_windows_hook_ex(&mut self, hook_type: i32, proc: u64, module: u64) -> u32 {
        let handle = self.get_handle();
        self.window_hooks.insert(handle, (hook_type, proc, module));
        handle
    }

    pub fn unhook_windows_hook_ex(&mut self, hook: u32) -> bool {
        self.window_hooks.remove(&hook).is_some()
    }

    pub fn post_message(&self, _hwnd: u32, _msg: u32, _wparam: u64, _lparam: u64) -> bool {
        true
    }

    pub fn send_message(&self, hwnd: u32, _msg: u32, _wparam: u64, _lparam: u64) -> u64 {
        self.wndprocs.get(&hwnd).copied().unwrap_or(0)
    }

    pub fn register_window_message(&self, _message: &str) -> u32 {
        0xC000
    }
}

impl Default for User32Handler {
    fn default() -> Self {
        Self::new()
    }
}

impl ApiHandler for User32Handler {
    fn call(&mut self, args: &[u64]) -> u64 {
        match args.len() {
            0 => self.get_desktop_window() as u64,
            1 => self.get_async_key_state(args[0] as u32) as u64,
            2 => self.message_box("", "", args[1] as u32) as u64,
            4 => self.send_message(args[0] as u32, args[1] as u32, args[2], args[3]),
            12 => self.create_window_ex(None, None) as u64,
            _ => 0,
        }
    }

    fn get_name(&self) -> &str {
        "User32"
    }
}

pub fn get_windowhook_flags(flags: i32) -> Vec<&'static str> {
    const DEFINES: &[(i32, &str)] = &[
        (windefs::WH_CALLWNDPROC, "WH_CALLWNDPROC"),
        (windefs::WH_CALLWNDPROCRET, "WH_CALLWNDPROCRET"),
        (windefs::WH_CBT, "WH_CBT"),
        (windefs::WH_DEBUG, "WH_DEBUG"),
        (windefs::WH_FOREGROUNDIDLE, "WH_FOREGROUNDIDLE"),
        (windefs::WH_GETMESSAGE, "WH_GETMESSAGE"),
        (windefs::WH_JOURNALPLAYBACK, "WH_JOURNALPLAYBACK"),
        (windefs::WH_JOURNALRECORD, "WH_JOURNALRECORD"),
        (windefs::WH_KEYBOARD, "WH_KEYBOARD"),
        (windefs::WH_KEYBOARD_LL, "WH_KEYBOARD_LL"),
        (windefs::WH_MOUSE, "WH_MOUSE"),
        (windefs::WH_MOUSE_LL, "WH_MOUSE_LL"),
        (windefs::WH_MSGFILTER, "WH_MSGFILTER"),
        (windefs::WH_SHELL, "WH_SHELL"),
        (windefs::WH_SYSMSGFILTER, "WH_SYSMSGFILTER"),
    ];
    DEFINES
        .iter()
        .filter_map(|(value, name)| if *value == flags { Some(*name) } else { None })
        .collect()
}
