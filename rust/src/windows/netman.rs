// Network Manager for Windows emulator

use crate::errors::{Result, SpeakeasyError};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};

static CURR_FD: AtomicU32 = AtomicU32::new(4);
static CURR_WININET_HANDLE: AtomicU32 = AtomicU32::new(0x20);

fn get_next_fd() -> u32 {
    CURR_FD.fetch_add(4, Ordering::SeqCst)
}

fn get_next_wininet_handle() -> u32 {
    CURR_WININET_HANDLE.fetch_add(4, Ordering::SeqCst)
}

#[derive(Clone, Debug)]
pub struct Socket {
    pub fd: u32,
    pub family: u32,
    pub stype: u32,
    pub protocol: u32,
    pub flags: u32,
    pub connected_host: String,
    pub connected_port: u16,
    pub recv_buffer: Vec<u8>,
    pub recv_cursor: usize,
}

impl Socket {
    pub fn new(family: u32, stype: u32, protocol: u32, flags: u32) -> Self {
        Self {
            fd: get_next_fd(),
            family,
            stype,
            protocol,
            flags,
            connected_host: String::new(),
            connected_port: 0,
            recv_buffer: Vec::new(),
            recv_cursor: 0,
        }
    }

    pub fn set_connection_info(&mut self, host: String, port: u16) {
        self.connected_host = host;
        self.connected_port = port;
    }
}

pub struct WininetRequest {
    pub handle: u32,
    pub verb: String,
    pub objname: String,
    pub version: String,
    pub referrer: String,
    pub response: Vec<u8>,
    pub response_cursor: usize,
}

pub struct WininetSession {
    pub handle: u32,
    pub server: String,
    pub port: u16,
    pub requests: HashMap<u32, WininetRequest>,
}

pub struct WininetInstance {
    pub handle: u32,
    pub user_agent: String,
    pub sessions: HashMap<u32, WininetSession>,
}

pub enum WininetObject {
    Instance(u32),
    Session(u32, u32), // Instance handle, Session handle
    Request(u32, u32, u32), // Instance handle, Session handle, Request handle
}

pub struct NetworkManager {
    pub sockets: HashMap<u32, Socket>,
    pub wininets: HashMap<u32, WininetInstance>,
    pub dns_names: HashMap<String, String>,
}

impl NetworkManager {
    pub fn new() -> Self {
        Self {
            sockets: HashMap::new(),
            wininets: HashMap::new(),
            dns_names: HashMap::new(),
        }
    }

    pub fn new_socket(&mut self, family: u32, stype: u32, protocol: u32, flags: u32) -> u32 {
        let sock = Socket::new(family, stype, protocol, flags);
        let fd = sock.fd;
        self.sockets.insert(fd, sock);
        fd
    }

    pub fn get_socket_mut(&mut self, fd: u32) -> Option<&mut Socket> {
        self.sockets.get_mut(&fd)
    }

    pub fn close_socket(&mut self, fd: u32) {
        self.sockets.remove(&fd);
    }

    pub fn name_lookup(&self, domain: &str) -> Option<String> {
        self.dns_names.get(&domain.to_lowercase())
            .or_else(|| self.dns_names.get("default"))
            .cloned()
    }

    pub fn new_wininet_instance(&mut self, ua: String) -> u32 {
        let handle = get_next_wininet_handle();
        let inst = WininetInstance {
            handle,
            user_agent: ua,
            sessions: HashMap::new(),
        };
        self.wininets.insert(handle, inst);
        handle
    }

    pub fn new_wininet_session(&mut self, inst_handle: u32, server: String, port: u16) -> Result<u32> {
        let inst = self.wininets.get_mut(&inst_handle).ok_or(SpeakeasyError::ApiError("Invalid wininet instance".to_string()))?;
        let handle = get_next_wininet_handle();
        let sess = WininetSession {
            handle,
            server,
            port,
            requests: HashMap::new(),
        };
        inst.sessions.insert(handle, sess);
        Ok(handle)
    }

    pub fn new_wininet_request(&mut self, inst_handle: u32, sess_handle: u32, verb: String, obj: String) -> Result<u32> {
        let inst = self.wininets.get_mut(&inst_handle).ok_or(SpeakeasyError::ApiError("Invalid wininet instance".to_string()))?;
        let sess = inst.sessions.get_mut(&sess_handle).ok_or(SpeakeasyError::ApiError("Invalid wininet session".to_string()))?;
        let handle = get_next_wininet_handle();
        let req = WininetRequest {
            handle,
            verb,
            objname: obj,
            version: "HTTP/1.1".to_string(),
            referrer: String::new(),
            response: Vec::new(),
            response_cursor: 0,
        };
        sess.requests.insert(handle, req);
        Ok(handle)
    }
}
