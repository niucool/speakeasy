use crate::winenv::api::usermode::wininet::WininetHandler;
use crate::winenv::api::ApiHandler;
use crate::winenv::defs::wininet as windefs;

pub struct WinhttpHandler {
    wininet: WininetHandler,
}

impl WinhttpHandler {
    pub fn new() -> Self {
        Self {
            wininet: WininetHandler::new(),
        }
    }

    pub fn win_http_open(&mut self, user_agent: Option<String>, access: u32, flags: u32) -> u32 {
        self.wininet
            .internet_open(user_agent, access, None, None, flags)
    }

    pub fn win_http_connect(&mut self, session: u32, server: &str, port: u16) -> u32 {
        self.wininet
            .internet_connect(session, server, port, None, None, 0, 0, 0)
    }

    pub fn win_http_open_request(&mut self, connect: u32, verb: &str, object_name: &str, flags: u32) -> u32 {
        self.wininet
            .http_open_request(connect, verb, object_name, Some("HTTP/1.1".to_string()), None, flags, 0)
    }

    pub fn win_http_send_request(&mut self, request: u32, headers: Option<String>, body: &[u8]) -> bool {
        self.wininet.http_send_request(request, headers, body)
    }

    pub fn win_http_query_headers(&self, query: u32) -> Option<&'static str> {
        match query {
            windefs::WINHTTP_QUERY_CONTENT_TYPE => Some("WINHTTP_QUERY_CONTENT_TYPE"),
            windefs::WINHTTP_QUERY_CONTENT_LENGTH => Some("WINHTTP_QUERY_CONTENT_LENGTH"),
            windefs::WINHTTP_QUERY_STATUS_CODE => Some("WINHTTP_QUERY_STATUS_CODE"),
            windefs::WINHTTP_QUERY_STATUS_TEXT => Some("WINHTTP_QUERY_STATUS_TEXT"),
            windefs::WINHTTP_QUERY_RAW_HEADERS => Some("WINHTTP_QUERY_RAW_HEADERS"),
            windefs::WINHTTP_QUERY_CONTENT_ENCODING => Some("WINHTTP_QUERY_CONTENT_ENCODING"),
            windefs::WINHTTP_QUERY_USER_AGENT => Some("WINHTTP_QUERY_USER_AGENT"),
            windefs::WINHTTP_QUERY_HOST => Some("WINHTTP_QUERY_HOST"),
            _ => None,
        }
    }
}

impl Default for WinhttpHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl ApiHandler for WinhttpHandler {
    fn call(&mut self, args: &[u64]) -> u64 {
        match args.len() {
            5 => self.win_http_open(None, args[1] as u32, args[4] as u32) as u64,
            8 => self.win_http_connect(args[0] as u32, "example.com", args[2] as u16) as u64,
            _ => 0,
        }
    }

    fn get_name(&self) -> &str {
        "Winhttp"
    }
}
