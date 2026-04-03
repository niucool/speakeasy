use crate::binemu::BinaryEmulator;
use crate::winenv::api::usermode::wininet::WininetHandler;
use crate::winenv::api::{ApiHandler, Result};

pub struct WinhttpHandler {
    wininet: WininetHandler,
}

impl WinhttpHandler {
    pub fn new() -> Self {
        Self {
            wininet: WininetHandler::new(),
        }
    }
}

impl Default for WinhttpHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl ApiHandler for WinhttpHandler {
    fn call(&mut self, emu: &mut dyn BinaryEmulator, name: &str, args: &[u64]) -> Result<u64> {
        match name {
            "WinHttpOpen" => {
                let user_agent_ptr = args[0];
                let user_agent = if user_agent_ptr != 0 {
                    if let Ok(data) = emu.mem_read(user_agent_ptr, 256) {
                        Some(
                            String::from_utf8_lossy(&data)
                                .trim_end_matches('\0')
                                .to_string(),
                        )
                    } else {
                        None
                    }
                } else {
                    None
                };
                Ok(self.wininet.internet_open(
                    user_agent,
                    args[1] as u32,
                    None,
                    None,
                    args[4] as u32,
                ) as u64)
            }
            "WinHttpConnect" => {
                let server_ptr = args[1];
                let server = if let Ok(data) = emu.mem_read(server_ptr, 256) {
                    String::from_utf8_lossy(&data)
                        .trim_end_matches('\0')
                        .to_string()
                } else {
                    "example.com".to_string()
                };
                Ok(self.wininet.internet_connect(
                    args[0] as u32,
                    &server,
                    args[2] as u16,
                    None,
                    None,
                    0,
                    0,
                    0,
                ) as u64)
            }
            "WinHttpOpenRequest" => {
                let verb_ptr = args[1];
                let verb = if let Ok(data) = emu.mem_read(verb_ptr, 32) {
                    String::from_utf8_lossy(&data)
                        .trim_end_matches('\0')
                        .to_string()
                } else {
                    "GET".to_string()
                };
                let object_ptr = args[2];
                let object_name = if let Ok(data) = emu.mem_read(object_ptr, 1024) {
                    String::from_utf8_lossy(&data)
                        .trim_end_matches('\0')
                        .to_string()
                } else {
                    "/".to_string()
                };
                Ok(self.wininet.http_open_request(
                    args[0] as u32,
                    &verb,
                    &object_name,
                    Some("HTTP/1.1".to_string()),
                    None,
                    args[5] as u32,
                    0,
                ) as u64)
            }
            "WinHttpSendRequest" => {
                let headers_ptr = args[1];
                let headers = if headers_ptr != 0 {
                    if let Ok(data) = emu.mem_read(headers_ptr, 1024) {
                        Some(
                            String::from_utf8_lossy(&data)
                                .trim_end_matches('\0')
                                .to_string(),
                        )
                    } else {
                        None
                    }
                } else {
                    None
                };
                let body_len = args[3] as usize;
                let body = if body_len > 0 {
                    let body_ptr = args[4];
                    if let Ok(data) = emu.mem_read(body_ptr, body_len) {
                        data.to_vec()
                    } else {
                        vec![]
                    }
                } else {
                    vec![]
                };
                Ok(u64::from(self.wininet.http_send_request(
                    args[0] as u32,
                    headers,
                    &body,
                )))
            }
            "WinHttpReceiveResponse" => Ok(1),
            "WinHttpQueryHeaders" => Ok(0),
            "WinHttpCloseHandle" => Ok(1),
            _ => Ok(0),
        }
    }

    fn get_name(&self) -> &str {
        "Winhttp"
    }
}
