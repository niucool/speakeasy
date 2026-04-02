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
    pub headers: Option<String>,
    pub body: Vec<u8>,
    pub response: Vec<u8>,
    pub read_offset: usize,
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

    pub fn new_wininet_session(
        &mut self,
        instance_handle: u32,
        server: String,
        port: u16,
        user: Option<String>,
        password: Option<String>,
        service: u32,
        flags: u32,
        ctx: u32,
    ) -> Option<u32> {
        let handle = self.new_handle();
        let session = WininetSession {
            handle,
            server,
            port,
            user,
            password,
            service,
            flags,
            ctx,
            instance_handle,
            requests: HashMap::new(),
        };
        let inst = self.wininets.get_mut(&instance_handle)?;
        inst.sessions.insert(handle, session);
        Some(handle)
    }

    pub fn new_wininet_request(
        &mut self,
        session_handle: u32,
        verb: String,
        objname: String,
        ver: String,
        referrer: Option<String>,
        accept_types: Option<Vec<String>>,
        flags: u32,
        ctx: u32,
    ) -> Option<u32> {
        let handle = self.new_handle();
        let request = WininetRequest {
            handle,
            verb,
            objname,
            ver,
            referrer,
            accept_types,
            flags,
            ctx,
            session_handle,
            headers: None,
            body: Vec::new(),
            response: Vec::new(),
            read_offset: 0,
        };

        for inst in self.wininets.values_mut() {
            if let Some(session) = inst.sessions.get_mut(&session_handle) {
                session.requests.insert(handle, request);
                return Some(handle);
            }
        }
        None
    }

    pub fn get_wininet_instance(&self, handle: u32) -> Option<&WininetInstance> {
        self.wininets.get(&handle)
    }

    pub fn get_wininet_session(&self, handle: u32) -> Option<&WininetSession> {
        self.wininets
            .values()
            .find_map(|inst| inst.sessions.get(&handle))
    }

    pub fn get_wininet_session_mut(&mut self, handle: u32) -> Option<&mut WininetSession> {
        for inst in self.wininets.values_mut() {
            if let Some(session) = inst.sessions.get_mut(&handle) {
                return Some(session);
            }
        }
        None
    }

    pub fn get_wininet_request(&self, handle: u32) -> Option<&WininetRequest> {
        self.wininets.values().find_map(|inst| {
            inst.sessions
                .values()
                .find_map(|session| session.requests.get(&handle))
        })
    }

    pub fn get_wininet_request_mut(&mut self, handle: u32) -> Option<&mut WininetRequest> {
        for inst in self.wininets.values_mut() {
            for session in inst.sessions.values_mut() {
                if let Some(request) = session.requests.get_mut(&handle) {
                    return Some(request);
                }
            }
        }
        None
    }

    pub fn get_wininet_server_port(&self, handle: u32) -> Option<(String, u16)> {
        if let Some(session) = self.get_wininet_session(handle) {
            return Some((session.server.clone(), session.port));
        }
        if let Some(request) = self.get_wininet_request(handle) {
            if let Some(session) = self.get_wininet_session(request.session_handle) {
                return Some((session.server.clone(), session.port));
            }
        }
        None
    }

    pub fn set_wininet_request_state(
        &mut self,
        handle: u32,
        headers: Option<String>,
        body: Vec<u8>,
        response: Vec<u8>,
    ) -> bool {
        if let Some(request) = self.get_wininet_request_mut(handle) {
            request.headers = headers;
            request.body = body;
            request.response = response;
            request.read_offset = 0;
            return true;
        }
        false
    }

    pub fn read_wininet_response(&mut self, handle: u32, size: usize) -> Option<Vec<u8>> {
        let request = self.get_wininet_request_mut(handle)?;
        let start = request.read_offset;
        let end = (start + size).min(request.response.len());
        let chunk = request.response[start..end].to_vec();
        request.read_offset = end;
        Some(chunk)
    }

    pub fn get_wininet_bytes_available(&self, handle: u32) -> Option<usize> {
        let request = self.get_wininet_request(handle)?;
        Some(request.response.len().saturating_sub(request.read_offset))
    }

    pub fn close_wininet_object(&mut self, handle: u32) -> bool {
        if self.wininets.remove(&handle).is_some() {
            return true;
        }

        for inst in self.wininets.values_mut() {
            if inst.sessions.remove(&handle).is_some() {
                return true;
            }
            for session in inst.sessions.values_mut() {
                if session.requests.remove(&handle).is_some() {
                    return true;
                }
            }
        }

        false
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
