use crate::winenv::api::ApiHandler;
use crate::binemu::BinaryEmulator;
use crate::errors::Result;

pub struct WS2_32Handler {
    next_socket: u32,
}

impl WS2_32Handler {
    pub fn new() -> Self {
        Self {
            next_socket: 0x2000,
        }
    }

    fn alloc_socket(&mut self) -> u32 {
        let sock = self.next_socket;
        self.next_socket += 1;
        sock
    }
}

impl Default for WS2_32Handler {
    fn default() -> Self {
        Self::new()
    }
}

impl ApiHandler for WS2_32Handler {
    fn call(&mut self, emu: &mut dyn BinaryEmulator, name: &str, args: &[u64]) -> Result<u64> {
        match name {
            "WSAStartup" | "WSAStartupA" | "WSAStartupW" => Ok(0),
            "WSACleanup" => Ok(0),
            "WSAGetLastError" => Ok(0),
            "WSASetLastError" => Ok(0),
            "WSAEnumNameResolutionProviders" => Ok(0),
            "WSAEnumNameResolutionProvidersEx" => Ok(0),
            "WSASocketA" | "WSASocketW" | "socket" => {
                let _af = args[0] as i32;
                let _sock_type = args[1] as i32;
                let _protocol = args[2] as i32;
                Ok(self.alloc_socket() as u64)
            },
            "WSAAccept" | "accept" => Ok(self.alloc_socket() as u64),
            "connect" | "WSAConnect" => Ok(0),
            "WSAConnectByName" | "WSAConnectByNameW" => Ok(0),
            "WSAConnectByList" => Ok(0),
            "bind" | "WSABind" => Ok(0),
            "listen" | "WSAListen" => Ok(0),
            "send" | "WSASend" => {
                let _socket = args[0];
                let _buf = args[1];
                let _len = args[2] as usize;
                let _flags = args[3];
                Ok(1)
            },
            "sendto" => Ok(1),
            "WSASendTo" => Ok(1),
            "WSASendMsg" => Ok(1),
            "recv" | "WSARecv" => {
                let _socket = args[0];
                let _buf = args[1];
                let _len = args[2] as usize;
                let _flags = args[3];
                Ok(0)
            },
            "recvfrom" => Ok(0),
            "WSARecvFrom" => Ok(0),
            "WSARecvMsg" => Ok(0),
            "closesocket" | "close" => Ok(0),
            "shutdown" => Ok(0),
            "WSAShutdown" => Ok(0),
            "WSAResetEvent" => Ok(0),
            "WSASetEvent" => Ok(0),
            "WSACreateEvent" => Ok(0),
            "WSACloseEvent" => Ok(0),
            "WSAWaitForMultipleEvents" => Ok(0),
            "WSASelect" => Ok(0),
            "WSAIoctl" | "ioctlsocket" => Ok(0),
            "getsockopt" | "WSAGetSockOpt" => Ok(0),
            "setsockopt" | "WSASetSockOpt" => Ok(0),
            "getpeername" => Ok(0),
            "getsockname" => Ok(0),
            "WSAPoll" => Ok(0),
            "gethostbyname" => Ok(0),
            "gethostbynameA" | "gethostbynameW" => Ok(0),
            "gethostbyaddr" => Ok(0),
            "gethostent" => Ok(0),
            "gethostent" => Ok(0),
            "GetHost" => Ok(0),
            "WSALookupServiceBeginA" | "WSALookupServiceBeginW" => Ok(0),
            "WSALookupServiceEnd" => Ok(0),
            "WSALookupServiceBegin" | "WSALookupServiceContinueA" | "WSALookupServiceContinueW" => Ok(0),
            "getaddrinfo" | "GetAddrInfoW" => Ok(0),
            "freeaddrinfo" => Ok(0),
            "getnameinfo" => Ok(0),
            "WSAStringToAddressA" | "WSAStringToAddressW" => Ok(0),
            "WSAAddressToStringA" | "WSAAddressToStringW" => Ok(0),
            "WSASetServiceA" | "WSASetServiceW" => Ok(0),
            "getservbyname" => Ok(0),
            "getservbyport" => Ok(0),
            "getprotobyname" => Ok(0),
            "getprotobynumber" => Ok(0),
            "WSASocketA" | "WSASocketW" => Ok(0),
            "WSAFlagGetSocket" => Ok(0),
            "WSAFlagSetSocket" => Ok(0),
            "WSADuplicateSocketA" | "WSADuplicateSocketW" => Ok(0),
            "WSASendDisconnect" => Ok(0),
            "WSARecvDisconnect" => Ok(0),
            "WSAAccept" | "WSAAccept" => Ok(self.alloc_socket() as u64),
            "WSAEventSelect" => Ok(0),
            "WSAEnumNetworkEvents" => Ok(0),
            "WSAGetOverlappedResult" => Ok(0),
            "WSAGetQueuedStatus" => Ok(0),
            "WSASetQueuedCompletionStatus" => Ok(0),
            "WSASocketPair" => Ok(0),
            "WSADuplicateSocketEx" => Ok(0),
            "WSASendFile" => Ok(0),
            "WSADeleteSocket" => Ok(0),
            "WSAGetProviderGuid" => Ok(0),
            "WSAProviderConfigChange" => Ok(0),
            "WSAEnumProtocolsA" | "WSAEnumProtocolsW" => Ok(0),
            "WSASetServiceA" | "WSASetServiceW" => Ok(0),
            "WSAInstallServiceProvider" => Ok(0),
            "WSARemoveServiceProvider" => Ok(0),
            "__WSAFDIsSet" => Ok(0),
            "WSAFDIsSet" => Ok(0),
            _ => Ok(0),
        }
    }

    fn get_name(&self) -> &str {
        "WS2_32"
    }
}
