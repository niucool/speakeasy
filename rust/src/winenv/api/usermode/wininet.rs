use std::net::Ipv4Addr;

use crate::windows::netman::NetworkManager;
use crate::winenv::api::ApiHandler;
use crate::winenv::defs::wininet as windefs;

pub struct WininetHandler {
    netman: NetworkManager,
}

impl WininetHandler {
    pub fn new() -> Self {
        Self {
            netman: NetworkManager::new(),
        }
    }

    pub fn internet_open(
        &mut self,
        user_agent: Option<String>,
        access: u32,
        proxy: Option<String>,
        bypass: Option<String>,
        flags: u32,
    ) -> u32 {
        self.netman
            .new_wininet_inst(user_agent, access, proxy, bypass, flags)
    }

    pub fn internet_connect(
        &mut self,
        internet: u32,
        server: &str,
        port: u16,
        user: Option<String>,
        password: Option<String>,
        service: u32,
        flags: u32,
        ctx: u32,
    ) -> u32 {
        self.netman
            .new_wininet_session(
                internet,
                server.to_string(),
                port,
                user,
                password,
                service,
                flags,
                ctx,
            )
            .unwrap_or(0)
    }

    pub fn http_open_request(
        &mut self,
        connect: u32,
        verb: &str,
        object_name: &str,
        version: Option<String>,
        referrer: Option<String>,
        flags: u32,
        ctx: u32,
    ) -> u32 {
        self.netman
            .new_wininet_request(
                connect,
                verb.to_string(),
                object_name.to_string(),
                version.unwrap_or_else(|| "HTTP/1.1".to_string()),
                referrer,
                None,
                flags,
                ctx,
            )
            .unwrap_or(0)
    }

    pub fn internet_open_url(
        &mut self,
        internet: u32,
        url: &str,
        headers: Option<String>,
        flags: u32,
        ctx: u32,
    ) -> u32 {
        let (scheme, host, port, path) = crack_url(url);
        let session = self.internet_connect(internet, &host, port, None, None, 0, flags, ctx);
        if session == 0 {
            return 0;
        }

        let request = self.http_open_request(
            session,
            "GET",
            &path,
            Some("HTTP/1.1".to_string()),
            None,
            flags,
            ctx,
        );
        let response = format!("HTTP/1.1 200 OK\r\nServer: speakeasy\r\nScheme: {scheme}\r\n\r\n").into_bytes();
        let _ = self
            .netman
            .set_wininet_request_state(request, headers, Vec::new(), response);
        request
    }

    pub fn http_send_request(&mut self, request: u32, headers: Option<String>, body: &[u8]) -> bool {
        let response = if let Some((server, port)) = self.netman.get_wininet_server_port(request) {
            format!(
                "HTTP/1.1 200 OK\r\nServer: {server}\r\nX-Speakeasy-Port: {port}\r\nContent-Length: {}\r\n\r\n",
                body.len()
            )
            .into_bytes()
        } else {
            b"HTTP/1.1 404 Not Found\r\n\r\n".to_vec()
        };
        self.netman
            .set_wininet_request_state(request, headers, body.to_vec(), response)
    }

    pub fn internet_read_file(&mut self, request: u32, size: usize) -> Vec<u8> {
        self.netman
            .read_wininet_response(request, size)
            .unwrap_or_default()
    }

    pub fn internet_query_data_available(&self, request: u32) -> usize {
        self.netman.get_wininet_bytes_available(request).unwrap_or(0)
    }

    pub fn internet_query_option(&self, option: u32) -> Option<u32> {
        match option {
            windefs::INTERNET_OPTION_SECURITY_FLAGS => Some(windefs::SECURITY_FLAG_SECURE),
            _ => None,
        }
    }

    pub fn internet_close_handle(&mut self, handle: u32) -> bool {
        self.netman.close_wininet_object(handle)
    }

    pub fn is_ip_address(server: &str) -> bool {
        server.parse::<Ipv4Addr>().is_ok()
    }
}

impl Default for WininetHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl ApiHandler for WininetHandler {
    fn call(&mut self, args: &[u64]) -> u64 {
        match args.len() {
            5 => self.internet_open(None, args[1] as u32, None, None, args[4] as u32) as u64,
            8 => self.internet_connect(
                args[0] as u32,
                "server",
                args[2] as u16,
                None,
                None,
                args[5] as u32,
                args[6] as u32,
                args[7] as u32,
            ) as u64,
            6 => self.internet_open_url(args[0] as u32, "http://example.com/", None, args[4] as u32, args[5] as u32)
                as u64,
            4 => self.internet_query_data_available(args[0] as u32) as u64,
            _ => 0,
        }
    }

    fn get_name(&self) -> &str {
        "Wininet"
    }
}

fn crack_url(url: &str) -> (String, String, u16, String) {
    let (scheme, remainder) = url
        .split_once("://")
        .map(|(scheme, rest)| (scheme.to_string(), rest))
        .unwrap_or_else(|| ("http".to_string(), url));

    let (host_port, path) = remainder
        .split_once('/')
        .map(|(host_port, path)| (host_port, format!("/{}", path)))
        .unwrap_or((remainder, "/".to_string()));

    let default_port = if scheme.eq_ignore_ascii_case("https") { 443 } else { 80 };
    let (host, port) = host_port
        .split_once(':')
        .and_then(|(host, port)| port.parse::<u16>().ok().map(|port| (host.to_string(), port)))
        .unwrap_or((host_port.to_string(), default_port));

    (scheme, host, port, path)
}
