use std::net::Ipv4Addr;

use crate::windows::netman::NetworkManager;
use crate::winenv::api::ApiHandler;
use crate::binemu::BinaryEmulator;
use crate::errors::Result;
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
    fn call(&mut self, emu: &mut dyn BinaryEmulator, name: &str, args: &[u64]) -> Result<u64> {
        match name {
            "InternetOpenA" | "InternetOpenW" => {
                let user_agent = args[0];
                let access = args[1] as u32;
                let proxy = args[2];
                let bypass = args[3];
                let flags = args[4] as u32;
                Ok(self.internet_open(None, access, None, None, flags) as u64)
            },
            "InternetConnectA" | "InternetConnectW" => {
                Ok(self.internet_connect(args[0] as u32, "server", 80, None, None, 0, 0, 0) as u64)
            },
            "HttpOpenRequestA" | "HttpOpenRequestW" => {
                Ok(self.http_open_request(args[0] as u32, "GET", "/", None, None, 0, 0) as u64)
            },
            "InternetOpenUrlA" | "InternetOpenUrlW" => {
                Ok(self.internet_open_url(args[0] as u32, "http://example.com/", None, 0, 0) as u64)
            },
            "HttpSendRequestA" | "HttpSendRequestW" => Ok(1),
            "InternetReadFile" => {
                let request = args[0] as u32;
                let buffer = args[1];
                let size = args[2] as usize;
                let data = self.internet_read_file(request, size);
                let bytes_read = data.len();
                emu.mem_write(buffer, &data)?;
                Ok(bytes_read as u64)
            },
            "InternetQueryDataAvailable" => {
                Ok(self.internet_query_data_available(args[0] as u32) as u64)
            },
            "InternetQueryOptionA" | "InternetQueryOptionW" => Ok(0),
            "InternetSetOptionA" | "InternetSetOptionW" => Ok(1),
            "InternetSetStatusCallbackA" | "InternetSetStatusCallbackW" => Ok(0),
            "InternetGetConnectedState" => Ok(1),
            "InternetGetConnectedStateExA" | "InternetGetConnectedStateExW" => Ok(1),
            "InternetSetFeatureEnabled" => Ok(1),
            "InternetQueryFeatureEnabled" => Ok(0),
            "InternetCloseHandle" => Ok(1),
            "InternetTimeFromSystemTimeA" | "InternetTimeFromSystemTimeW" => Ok(1),
            "InternetTimeToSystemTimeA" | "InternetTimeToSystemTimeW" => Ok(1),
            "InternetCrackUrlA" | "InternetCrackUrlW" => Ok(0),
            "InternetCreateUrlA" | "InternetCreateUrlW" => Ok(0),
            "InternetCanonicalizeUrlA" | "InternetCanonicalizeUrlW" => Ok(0),
            "InternetCombineUrlA" | "InternetCombineUrlW" => Ok(0),
            "InternetSetCookieA" | "InternetSetCookieW" => Ok(0),
            "InternetGetCookieA" | "InternetGetCookieW" => Ok(0),
            "InternetGetCookieExA" | "InternetGetCookieExW" => Ok(0),
            "InternetEnumProtocolsA" | "InternetEnumProtocolsW" => Ok(0),
            "InternetInitializeAutoProxyDll" => Ok(0),
            "InternetGetProxyForUrl" => Ok(0),
            "InternetDestroyAutoProxyDll" => Ok(0),
            "InternetAutodial" => Ok(1),
            "InternetAutodialCallback" => Ok(0),
            "InternetDial" => Ok(0),
            "InternetHangUp" => Ok(0),
            "InternetGoOnline" => Ok(1),
            "InternetGetLastResponseInfoA" | "InternetGetLastResponseInfoW" => Ok(0),
            "InternetConfirmZoneCrossing" => Ok(0),
            "InternetSecuritySetByCertId" => Ok(0),
            "HttpOpenRequestW" => Ok(0),
            "HttpAddRequestHeadersA" | "HttpAddRequestHeadersW" => Ok(1),
            "HttpQueryInfoA" | "HttpQueryInfoW" => Ok(0),
            "HttpSendRequestExA" | "HttpSendRequestExW" => Ok(0),
            "HttpEndRequestA" | "HttpEndRequestW" => Ok(0),
            "HttpQueryHeadersA" | "HttpQueryHeadersW" => Ok(0),
            "InternetConnectW" => Ok(0),
            _ => Ok(0),
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
