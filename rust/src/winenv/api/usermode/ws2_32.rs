// Winsock2 (WS2_32) API implementations

use crate::winenv::api::ApiHandler;

pub struct WS2_32Handler;

impl ApiHandler for WS2_32Handler {
    fn call(&mut self, _args: &[u64]) -> u64 {
        0
    }

    fn get_name(&self) -> &str {
        "WS2_32"
    }
}

// Specific WS2_32 function implementations
pub fn socket(_af: i32, _sock_type: i32, _protocol: i32) -> u32 {
    0xffffffff // INVALID_SOCKET
}

pub fn connect(_socket: u32, _address: &str, _port: u16) -> i32 {
    0
}

pub fn send(_socket: u32, _data: &[u8]) -> i32 {
    _data.len() as i32
}

pub fn recv(_socket: u32, _buffer: &mut [u8]) -> i32 {
    0
}

pub fn close_socket(_socket: u32) -> i32 {
    0
}
