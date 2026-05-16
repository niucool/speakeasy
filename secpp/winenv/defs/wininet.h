// wininet.h — Windows Internet (WinINet/WinHTTP) type definitions
//
// Maps to: speakeasy/winenv/defs/wininet.py
//
// Internet API constants and URL_COMPONENTS structure used by
// WinINet and WinHTTP API handlers.

#ifndef SPEAKEASY_DEFS_WININET_H
#define SPEAKEASY_DEFS_WININET_H

#include <cstdint>
#include <vector>
#include "../../struct.h"

namespace speakeasy { namespace defs {

// ── Internet flags ──────────────────────────────────────────
constexpr uint32_t INTERNET_FLAG_ASYNC              = 0x10000000;
constexpr uint32_t INTERNET_FLAG_CACHE_ASYNC        = 0x00000080;
constexpr uint32_t INTERNET_FLAG_CACHE_IF_NET_FAIL  = 0x00010000;
constexpr uint32_t INTERNET_FLAG_DONT_CACHE         = 0x04000000;
constexpr uint32_t INTERNET_FLAG_EXISTING_CONNECT   = 0x20000000;
constexpr uint32_t INTERNET_FLAG_FORMS_SUBMIT       = 0x00000040;
constexpr uint32_t INTERNET_FLAG_FROM_CACHE         = 0x01000000;
constexpr uint32_t INTERNET_FLAG_FWD_BACK           = 0x00000020;
constexpr uint32_t INTERNET_FLAG_HYPERLINK          = 0x00000400;
constexpr uint32_t INTERNET_FLAG_IGNORE_CERT_CN_INVALID      = 0x00001000;
constexpr uint32_t INTERNET_FLAG_IGNORE_CERT_DATE_INVALID    = 0x00002000;
constexpr uint32_t INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTP     = 0x00008000;
constexpr uint32_t INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTPS    = 0x00004000;
constexpr uint32_t INTERNET_FLAG_KEEP_CONNECTION   = 0x00400000;
constexpr uint32_t INTERNET_FLAG_MAKE_PERSISTENT   = 0x02000000;
constexpr uint32_t INTERNET_FLAG_MUST_CACHE_REQUEST = 0x00000010;
constexpr uint32_t INTERNET_FLAG_NEED_FILE          = 0x00000010;
constexpr uint32_t INTERNET_FLAG_NO_AUTH            = 0x00040000;
constexpr uint32_t INTERNET_FLAG_NO_AUTO_REDIRECT   = 0x00200000;
constexpr uint32_t INTERNET_FLAG_NO_COOKIES         = 0x00080000;
constexpr uint32_t INTERNET_FLAG_NO_UI              = 0x00000200;
constexpr uint32_t INTERNET_FLAG_OFFLINE            = 0x01000000;
constexpr uint32_t INTERNET_FLAG_PASSIVE            = 0x08000000;
constexpr uint32_t INTERNET_FLAG_PRAGMA_NOCACHE     = 0x00000100;
constexpr uint32_t INTERNET_FLAG_RAW_DATA           = 0x40000000;
constexpr uint32_t INTERNET_FLAG_READ_PREFETCH      = 0x00100000;
constexpr uint32_t INTERNET_FLAG_RELOAD             = 0x80000000;
constexpr uint32_t INTERNET_FLAG_RESTRICTED_ZONE    = 0x00020000;
constexpr uint32_t INTERNET_FLAG_RESYNCHRONIZE      = 0x00000800;
constexpr uint32_t INTERNET_FLAG_SECURE             = 0x00800000;
constexpr uint32_t INTERNET_FLAG_TRANSFER_ASCII     = 0x00000001;
constexpr uint32_t INTERNET_FLAG_TRANSFER_BINARY    = 0x00000002;

// ── Connection types ───────────────────────────────────────
constexpr uint32_t INTERNET_NO_CALLBACK             = 0x00000000;
constexpr uint32_t INTERNET_CONNECTION_MODEM        = 0x00000001;
constexpr uint32_t INTERNET_CONNECTION_LAN          = 0x00000002;
constexpr uint32_t INTERNET_CONNECTION_PROXY        = 0x00000004;
constexpr uint32_t INTERNET_CONNECTION_MODEM_BUSY   = 0x00000008;
constexpr uint32_t INTERNET_RAS_INSTALLED           = 0x00000010;
constexpr uint32_t INTERNET_CONNECTION_OFFLINE      = 0x00000020;
constexpr uint32_t INTERNET_CONNECTION_CONFIGURED   = 0x00000040;

// ── Options ────────────────────────────────────────────────
constexpr uint32_t INTERNET_OPTION_SUPPRESS_SERVER_AUTH = 104;
constexpr uint32_t INTERNET_OPTION_SECURITY_FLAGS       = 31;

// ── API flags ──────────────────────────────────────────────
constexpr uint32_t WININET_API_FLAG_ASYNC         = 0x00000001;
constexpr uint32_t WININET_API_FLAG_SYNC          = 0x00000004;
constexpr uint32_t WININET_API_FLAG_USE_CONTEXT   = 0x00000008;

// ── Internet schemes ───────────────────────────────────────
constexpr int32_t INTERNET_SCHEME_PARTIAL  = -2;
constexpr int32_t INTERNET_SCHEME_UNKNOWN  = -1;
constexpr int32_t INTERNET_SCHEME_DEFAULT  = 0;
constexpr int32_t INTERNET_SCHEME_FTP      = 1;
constexpr int32_t INTERNET_SCHEME_GOPHER   = 2;
constexpr int32_t INTERNET_SCHEME_HTTP     = 3;
constexpr int32_t INTERNET_SCHEME_HTTPS    = 4;

// ── WinHTTP add/replace flags ───────────────────────────────
constexpr uint32_t WINHTTP_ADDREQ_INDEX_MASK               = 0x0000FFFF;
constexpr uint32_t WINHTTP_ADDREQ_FLAGS_MASK               = 0xFFFF0000;
constexpr uint32_t WINHTTP_ADDREQ_FLAG_ADD_IF_NEW          = 0x10000000;
constexpr uint32_t WINHTTP_ADDREQ_FLAG_ADD                 = 0x20000000;
constexpr uint32_t WINHTTP_ADDREQ_FLAG_COALESCE_WITH_COMMA = 0x40000000;
constexpr uint32_t WINHTTP_ADDREQ_FLAG_COALESCE_WITH_SEMICOLON = 0x01000000;

// ── WinHTTP query info types ───────────────────────────────
constexpr uint32_t WINHTTP_QUERY_MIME_VERSION            = 0;
constexpr uint32_t WINHTTP_QUERY_CONTENT_TYPE            = 1;
constexpr uint32_t WINHTTP_QUERY_CONTENT_TRANSFER_ENCODING = 2;
constexpr uint32_t WINHTTP_QUERY_CONTENT_ID              = 3;
constexpr uint32_t WINHTTP_QUERY_CONTENT_DESCRIPTION     = 4;
constexpr uint32_t WINHTTP_QUERY_CONTENT_LENGTH          = 5;
constexpr uint32_t WINHTTP_QUERY_CONTENT_LANGUAGE        = 6;
constexpr uint32_t WINHTTP_QUERY_ALLOW                   = 7;
constexpr uint32_t WINHTTP_QUERY_PUBLIC                  = 8;
constexpr uint32_t WINHTTP_QUERY_DATE                    = 9;
constexpr uint32_t WINHTTP_QUERY_EXPIRES                 = 10;
constexpr uint32_t WINHTTP_QUERY_LAST_MODIFIED           = 11;
constexpr uint32_t WINHTTP_QUERY_MESSAGE_ID              = 12;
constexpr uint32_t WINHTTP_QUERY_URI                     = 13;
constexpr uint32_t WINHTTP_QUERY_DERIVED_FROM            = 14;
constexpr uint32_t WINHTTP_QUERY_COST                    = 15;
constexpr uint32_t WINHTTP_QUERY_LINK                    = 16;
constexpr uint32_t WINHTTP_QUERY_PRAGMA                  = 17;
constexpr uint32_t WINHTTP_QUERY_VERSION                 = 18;
constexpr uint32_t WINHTTP_QUERY_STATUS_CODE             = 19;
constexpr uint32_t WINHTTP_QUERY_STATUS_TEXT             = 20;
constexpr uint32_t WINHTTP_QUERY_RAW_HEADERS             = 21;
constexpr uint32_t WINHTTP_QUERY_RAW_HEADERS_CRLF        = 22;
constexpr uint32_t WINHTTP_QUERY_CONNECTION              = 23;
constexpr uint32_t WINHTTP_QUERY_ACCEPT                  = 24;
constexpr uint32_t WINHTTP_QUERY_ACCEPT_CHARSET          = 25;
constexpr uint32_t WINHTTP_QUERY_ACCEPT_ENCODING         = 26;
constexpr uint32_t WINHTTP_QUERY_ACCEPT_LANGUAGE         = 27;
constexpr uint32_t WINHTTP_QUERY_AUTHORIZATION           = 28;
constexpr uint32_t WINHTTP_QUERY_CONTENT_ENCODING        = 29;
constexpr uint32_t WINHTTP_QUERY_FORWARDED               = 30;
constexpr uint32_t WINHTTP_QUERY_FROM                    = 31;
constexpr uint32_t WINHTTP_QUERY_IF_MODIFIED_SINCE       = 32;
constexpr uint32_t WINHTTP_QUERY_LOCATION                = 33;
constexpr uint32_t WINHTTP_QUERY_ORIG_URI                = 34;
constexpr uint32_t WINHTTP_QUERY_REFERER                 = 35;
constexpr uint32_t WINHTTP_QUERY_RETRY_AFTER             = 36;
constexpr uint32_t WINHTTP_QUERY_SERVER                  = 37;
constexpr uint32_t WINHTTP_QUERY_TITLE                   = 38;
constexpr uint32_t WINHTTP_QUERY_USER_AGENT              = 39;
constexpr uint32_t WINHTTP_QUERY_WWW_AUTHENTICATE        = 40;
constexpr uint32_t WINHTTP_QUERY_PROXY_AUTHENTICATE      = 41;
constexpr uint32_t WINHTTP_QUERY_ACCEPT_RANGES           = 42;
constexpr uint32_t WINHTTP_QUERY_SET_COOKIE              = 43;
constexpr uint32_t WINHTTP_QUERY_COOKIE                  = 44;
constexpr uint32_t WINHTTP_QUERY_REQUEST_METHOD          = 45;
constexpr uint32_t WINHTTP_QUERY_REFRESH                 = 46;
constexpr uint32_t WINHTTP_QUERY_CONTENT_DISPOSITION     = 47;
constexpr uint32_t WINHTTP_QUERY_AGE                     = 48;
constexpr uint32_t WINHTTP_QUERY_CACHE_CONTROL           = 49;
constexpr uint32_t WINHTTP_QUERY_CONTENT_BASE            = 50;
constexpr uint32_t WINHTTP_QUERY_CONTENT_LOCATION        = 51;
constexpr uint32_t WINHTTP_QUERY_CONTENT_MD5             = 52;
constexpr uint32_t WINHTTP_QUERY_CONTENT_RANGE           = 53;
constexpr uint32_t WINHTTP_QUERY_ETAG                    = 54;
constexpr uint32_t WINHTTP_QUERY_HOST                    = 55;
constexpr uint32_t WINHTTP_QUERY_IF_MATCH                = 56;
constexpr uint32_t WINHTTP_QUERY_IF_NONE_MATCH           = 57;
constexpr uint32_t WINHTTP_QUERY_IF_RANGE                = 58;
constexpr uint32_t WINHTTP_QUERY_IF_UNMODIFIED_SINCE     = 59;
constexpr uint32_t WINHTTP_QUERY_MAX_FORWARDS            = 60;
constexpr uint32_t WINHTTP_QUERY_PROXY_AUTHORIZATION     = 61;
constexpr uint32_t WINHTTP_QUERY_RANGE                   = 62;
constexpr uint32_t WINHTTP_QUERY_TRANSFER_ENCODING       = 63;
constexpr uint32_t WINHTTP_QUERY_UPGRADE                 = 64;
constexpr uint32_t WINHTTP_QUERY_VARY                    = 65;
constexpr uint32_t WINHTTP_QUERY_VIA                     = 66;
constexpr uint32_t WINHTTP_QUERY_WARNING                 = 67;
constexpr uint32_t WINHTTP_QUERY_EXPECT                  = 68;
constexpr uint32_t WINHTTP_QUERY_PROXY_CONNECTION        = 69;
constexpr uint32_t WINHTTP_QUERY_UNLESS_MODIFIED_SINCE   = 70;
constexpr uint32_t WINHTTP_QUERY_PROXY_SUPPORT           = 75;
constexpr uint32_t WINHTTP_QUERY_AUTHENTICATION_INFO     = 76;
constexpr uint32_t WINHTTP_QUERY_PASSPORT_URLS           = 77;
constexpr uint32_t WINHTTP_QUERY_PASSPORT_CONFIG         = 78;
constexpr uint32_t WINHTTP_QUERY_MAX                     = 78;

// ── Security flags ─────────────────────────────────────────
constexpr uint32_t SECURITY_FLAG_SECURE = 1;

// ── Errors ─────────────────────────────────────────────────
constexpr uint32_t ERROR_INSUFFICIENT_BUFFER = 122;

// ── URL_COMPONENTS structure (x64 layout) ──────────────────
//
// On x64 Windows each LPWSTR/LPTSTR is 8 bytes, requiring
// padding after uint32_t fields that precede a pointer.
//
struct URL_COMPONENTS : speakeasy::EmuStruct {
    uint32_t dwStructSize      = 0;  // offset  0
    uint32_t __pad0            = 0;  // offset  4 (padding)
    uint64_t lpszScheme        = 0;  // offset  8
    uint32_t dwSchemeLength    = 0;  // offset 16
    uint32_t nScheme           = 0;  // offset 20
    uint64_t lpszHostName      = 0;  // offset 24
    uint32_t dwHostNameLength  = 0;  // offset 32
    uint16_t nPort             = 0;  // offset 36
    uint16_t __pad1            = 0;  // offset 38 (padding)
    uint64_t lpszUserName      = 0;  // offset 40
    uint32_t dwUserNameLength  = 0;  // offset 48
    uint32_t __pad2            = 0;  // offset 52 (padding)
    uint64_t lpszPassword      = 0;  // offset 56
    uint32_t dwPasswordLength  = 0;  // offset 64
    uint32_t __pad3            = 0;  // offset 68 (padding)
    uint64_t lpszUrlPath       = 0;  // offset 72
    uint32_t dwUrlPathLength   = 0;  // offset 80
    uint32_t __pad4            = 0;  // offset 84 (padding)
    uint64_t lpszExtraInfo     = 0;  // offset 88
    uint32_t dwExtraInfoLength = 0;  // offset 96
    uint32_t __pad5            = 0;  // offset 100 (tail padding)

    size_t sizeof_obj() const override { return 104; }

    std::vector<uint8_t> get_bytes() const override {
        std::vector<uint8_t> b(104, 0);
        speakeasy::write_le(b,  0, dwStructSize,      4);
        // __pad0 is padding, stays 0
        speakeasy::write_le(b,  8, lpszScheme,        8);
        speakeasy::write_le(b, 16, dwSchemeLength,    4);
        speakeasy::write_le(b, 20, nScheme,           4);
        speakeasy::write_le(b, 24, lpszHostName,      8);
        speakeasy::write_le(b, 32, dwHostNameLength,  4);
        speakeasy::write_le(b, 36, nPort,             2);
        // __pad1 is padding
        speakeasy::write_le(b, 40, lpszUserName,      8);
        speakeasy::write_le(b, 48, dwUserNameLength,  4);
        // __pad2 is padding
        speakeasy::write_le(b, 56, lpszPassword,      8);
        speakeasy::write_le(b, 64, dwPasswordLength,  4);
        // __pad3 is padding
        speakeasy::write_le(b, 72, lpszUrlPath,       8);
        speakeasy::write_le(b, 80, dwUrlPathLength,   4);
        // __pad4 is padding
        speakeasy::write_le(b, 88, lpszExtraInfo,     8);
        speakeasy::write_le(b, 96, dwExtraInfoLength, 4);
        // __pad5 is tail padding
        return b;
    }
};

}} // namespace speakeasy::defs

#endif // SPEAKEASY_DEFS_WININET_H
