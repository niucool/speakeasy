// User32 API implementations

use crate::winenv::api::ApiHandler;

pub struct User32Handler;

impl ApiHandler for User32Handler {
    fn call(&mut self, _args: &[u64]) -> u64 {
        0
    }

    fn get_name(&self) -> &str {
        "User32"
    }
}

// Specific User32 function implementations
pub fn find_window(_class_name: &str, _window_name: &str) -> u32 {
    0
}

pub fn send_message(_hwnd: u32, _msg: u32, _wparam: u64, _lparam: u64) -> u64 {
    0
}

pub fn post_message(_hwnd: u32, _msg: u32, _wparam: u64, _lparam: u64) -> bool {
    true
}

pub fn get_message(_hwnd: u32) -> Option<u32> {
    None
}
