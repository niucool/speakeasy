// Network activity emulation

use std::collections::HashMap;
use std::io::Cursor;

pub struct Socket {
    pub fd: u32,
    pub family: u32,
    pub socket_type: u32,
    pub protocol: u32,
    pub flags: u32,
    pub connected_host: String,
    pub connected_port: u16,
    pub curr_packet: Cursor<Vec<u8>>,
    pub packet_queue: Vec<Vec<u8>>,
}

impl Socket {
    pub fn new(fd: u32, family: u32, socket_type: u32, protocol: u32, flags: u32) -> Self {
        Self {
            fd,
            family,
            socket_type,
            protocol,
            flags,
            connected_host: String::new(),
            connected_port: 0,
            curr_packet: Cursor::new(Vec::new()),
            packet_queue: Vec::new(),
        }
    }

    pub fn set_connection_info(&mut self, host: String, port: u16) {
        self.connected_host = host;
        self.connected_port = port;
    }

    pub fn get_connection_info(&self) -> (&str, u16) {
        (&self.connected_host, self.connected_port)
    }
}

pub struct WininetRequest {
    pub handle: u32,
    pub verb: String,
    pub objname: String,
    pub ver: String,
    pub referrer: Option<String>,
    pub accept_types: Option<Vec<String>>,
    pub flags: u32,
    pub ctx: u32,
    pub session_handle: u32,
}

pub struct WininetSession {
    pub handle: u32,
    pub server: String,
    pub port: u16,
    pub user: Option<String>,
    pub password: Option<String>,
    pub service: u32,
    pub flags: u32,
    pub ctx: u32,
    pub instance_handle: u32,
    pub requests: HashMap<u32, WininetRequest>,
}

pub struct WininetInstance {
    pub handle: u32,
    pub user_agent: Option<String>,
    pub access: u32,
    pub proxy: Option<String>,
    pub bypass: Option<String>,
    pub flags: u32,
    pub sessions: HashMap<u32, WininetSession>,
}

pub struct NetworkManager {
    pub sockets: HashMap<u32, Socket>,
    pub wininets: HashMap<u32, WininetInstance>,
    curr_fd: u32,
    curr_handle: u32,
}

impl NetworkManager {
    pub fn new() -> Self {
        Self {
            sockets: HashMap::new(),
            wininets: HashMap::new(),
            curr_fd: 4,
            curr_handle: 0x20,
        }
    }

    fn new_handle(&mut self) -> u32 {
        let tmp = self.curr_handle;
        self.curr_handle += 4;
        tmp
    }

    pub fn new_socket(&mut self, family: u32, stype: u32, protocol: u32, flags: u32) -> u32 {
        let fd = self.curr_fd;
        self.curr_fd += 4;
        let sock = Socket::new(fd, family, stype, protocol, flags);
        self.sockets.insert(fd, sock);
        fd
    }

    pub fn new_wininet_inst(
        &mut self,
        user_agent: Option<String>,
        access: u32,
        proxy: Option<String>,
        bypass: Option<String>,
        flags: u32,
    ) -> u32 {
        let handle = self.new_handle();
        let inst = WininetInstance {
            handle,
            user_agent,
            access,
            proxy,
            bypass,
            flags,
            sessions: HashMap::new(),
        };
        self.wininets.insert(handle, inst);
        handle
    }

    pub fn get_socket(&mut self, fd: u32) -> Option<&mut Socket> {
        self.sockets.get_mut(&fd)
    }

    pub fn close_socket(&mut self, fd: u32) {
        self.sockets.remove(&fd);
    }
}

impl Default for NetworkManager {
    fn default() -> Self {
        Self::new()
    }
}
