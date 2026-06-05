// wininet.h  WinINet type definitions (new EmuStructHelper CRTP)
//
// Maps to: speakeasy/winenv/defs/wininet.py
//
// Uses the new EmuStructHelper CRTP approach for auto serialize/deserialize.
// All structs use #pragma pack(push, 1) with explicit padding fields to match
// the sizeof() that Python ctypes (natural C ABI alignment) would produce.

#ifndef SPEAKEASY_DEFS_NEW_WININET_H
#define SPEAKEASY_DEFS_NEW_WININET_H

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include "struct.h"

namespace speakeasy { namespace deffs {

#pragma pack(push, 1)

// ==========================================================================================================
// WinINet flag constants
// ==========================================================================================================
constexpr uint32_t kInternetFlagAsync                  = 0x10000000;
constexpr uint32_t kInternetFlagCacheAsync             = 0x00000080;
constexpr uint32_t kInternetFlagCacheIfNetFail         = 0x00010000;
constexpr uint32_t kInternetFlagDontCache              = 0x04000000;
constexpr uint32_t kInternetFlagExistingConnect        = 0x20000000;
constexpr uint32_t kInternetFlagFormsSubmit            = 0x00000040;
constexpr uint32_t kInternetFlagFromCache              = 0x01000000;
constexpr uint32_t kInternetFlagFwdBack                = 0x00000020;
constexpr uint32_t kInternetFlagHyperlink              = 0x00000400;
constexpr uint32_t kInternetFlagIgnoreCertCnInvalid    = 0x00001000;
constexpr uint32_t kInternetFlagIgnoreCertDateInvalid  = 0x00002000;
constexpr uint32_t kInternetFlagIgnoreRedirectToHttp   = 0x00008000;
constexpr uint32_t kInternetFlagIgnoreRedirectToHttps  = 0x00004000;
constexpr uint32_t kInternetFlagKeepConnection         = 0x00400000;
constexpr uint32_t kInternetFlagMakePersistent         = 0x02000000;
constexpr uint32_t kInternetFlagMustCacheRequest       = 0x00000010;
constexpr uint32_t kInternetFlagNeedFile               = 0x00000010;
constexpr uint32_t kInternetFlagNoAuth                 = 0x00040000;
constexpr uint32_t kInternetFlagNoAutoRedirect         = 0x00200000;
constexpr uint32_t kInternetFlagNoCookies              = 0x00080000;
constexpr uint32_t kInternetFlagNoUi                   = 0x00000200;
constexpr uint32_t kInternetFlagOffline                = 0x01000000;
constexpr uint32_t kInternetFlagPassive                = 0x08000000;
constexpr uint32_t kInternetFlagPragmaNocache          = 0x00000100;
constexpr uint32_t kInternetFlagRawData                = 0x40000000;
constexpr uint32_t kInternetFlagReadPrefetch           = 0x00100000;
constexpr uint32_t kInternetFlagReload                 = 0x80000000;
constexpr uint32_t kInternetFlagRestrictedZone         = 0x00020000;
constexpr uint32_t kInternetFlagResynchronize          = 0x00000800;
constexpr uint32_t kInternetFlagSecure                 = 0x00800000;
constexpr uint32_t kInternetFlagTransferAscii          = 0x00000001;
constexpr uint32_t kInternetFlagTransferBinary         = 0x00000002;
constexpr uint32_t kInternetNoCallback                 = 0x00000000;
constexpr uint32_t kInternetConnectionModem            = 0x00000001;
constexpr uint32_t kInternetConnectionLan              = 0x00000002;
constexpr uint32_t kInternetConnectionProxy            = 0x00000004;
constexpr uint32_t kInternetConnectionModemBusy        = 0x00000008;
constexpr uint32_t kInternetRasInstalled               = 0x00000010;
constexpr uint32_t kInternetConnectionOffline          = 0x00000020;
constexpr uint32_t kInternetConnectionConfigured       = 0x00000040;
constexpr int      kInternetOptionSuppressServerAuth   = 104;
constexpr uint32_t kWininetApiFlagAsync                = 0x00000001;
constexpr uint32_t kWininetApiFlagSync                 = 0x00000004;
constexpr uint32_t kWininetApiFlagUseContext           = 0x00000008;

constexpr int kInternetSchemePartial = -2;
constexpr int kInternetSchemeUnknown = -1;
constexpr int kInternetSchemeDefault =  0;
constexpr int kInternetSchemeFtp     =  1;
constexpr int kInternetSchemeGopher  =  2;
constexpr int kInternetSchemeHttp    =  3;
constexpr int kInternetSchemeHttps   =  4;

// ==========================================================================================================
// URL_COMPONENTS:
//   dwStructSize(u32)+lpszScheme(Ptr)+dwSchemeLength(u32)+nScheme(u32)+
//   lpszHostName(Ptr)+dwHostNameLength(u32)+nPort(u16)+
//   lpszUserName(Ptr)+dwUserNameLength(u32)+
//   lpszPassword(Ptr)+dwPasswordLength(u32)+
//   lpszUrlPath(Ptr)+dwUrlPathLength(u32)+
//   lpszExtraInfo(Ptr)+dwExtraInfoLength(u32)
//
//   x86: 4+4+4+4+4+4+2+4+4+4+4+4+4+4+4 = 58
//        Let me calculate properly:
//        4+4=8, +4=12, +4=16, +4=20, +4=24, +2=26, +4=30, +4=34, +4=38, +4=42, +4=46, +4=50, +4=54
//        Total = 58... hmm wait
//        lpszScheme(Ptr,4)=8, dwSchemeLength(u32,4)=12, nScheme(u32,4)=16
//        lpszHostName(Ptr,4)=20, dwHostNameLength(u32,4)=24, nPort(u16,2)=26
//        lpszUserName(Ptr,4)=30, dwUserNameLength(u32,4)=34
//        lpszPassword(Ptr,4)=38, dwPasswordLength(u32,4)=42
//        lpszUrlPath(Ptr,4)=46, dwUrlPathLength(u32,4)=50
//        lpszExtraInfo(Ptr,4)=54, dwExtraInfoLength(u32,4)=58
//
//   x64: 4+pad(4)+8+4+4+8+4+2+pad(2)+8+4+pad(4)+8+4+pad(4)+8+4+pad(4)+8+4
//        Let me calculate:
//        dwStructSize(4)+pad(4)=8, lpszScheme(8)=16, dwSchemeLength(4)=20, nScheme(4)=24
//        lpszHostName(8)=32, dwHostNameLength(4)=36, nPort(2)=38, pad(2)=40
//        lpszUserName(8)=48, dwUserNameLength(4)=52, pad(4)=56
//        lpszPassword(8)=64, dwPasswordLength(4)=68, pad(4)=72
//        lpszUrlPath(8)=80, dwUrlPathLength(4)=84, pad(4)=88
//        lpszExtraInfo(8)=96, dwExtraInfoLength(4)=100, pad(4)=104
//        Total = 104
// ==========================================================================================================
template <int PtrSize>
struct URL_COMPONENTS_POD;

template <>
struct URL_COMPONENTS_POD<4> {
    uint32_t dwStructSize;        // offset  0
    uint32_t lpszScheme;          // offset  4 (Ptr)
    uint32_t dwSchemeLength;      // offset  8
    uint32_t nScheme;             // offset 12
    uint32_t lpszHostName;        // offset 16 (Ptr)
    uint32_t dwHostNameLength;    // offset 20
    uint16_t nPort;               // offset 24
    // padding not needed: next is u32, at 26 which is not 4-aligned
    // But actually, lpszUserName is next at offset 26.
    // In packed mode, it would be at 26. In natural alignment, uint32 needs 4-byte alignment.
    // Let me re-check. In the Python, fields are:
    // dwStructSize(u32)+lpszScheme(Ptr)+dwSchemeLength(u32)+nScheme(u32)+
    // lpszHostName(Ptr)+dwHostNameLength(u32)+nPort(u16)+
    // lpszUserName(Ptr)+...
    // After nPort(u16) at 24+2=26, next is lpszUserName(Ptr,4 bytes on x86).
    // 26 is not 4-aligned, so pad(2)=28.
    uint8_t  pad1[2];             // offset 26 → align next Ptr to 4
    uint32_t lpszUserName;        // offset 28 (Ptr)
    uint32_t dwUserNameLength;    // offset 32
    uint32_t lpszPassword;        // offset 36 (Ptr)
    uint32_t dwPasswordLength;    // offset 40
    uint32_t lpszUrlPath;         // offset 44 (Ptr)
    uint32_t dwUrlPathLength;     // offset 48
    uint32_t lpszExtraInfo;       // offset 52 (Ptr)
    uint32_t dwExtraInfoLength;   // offset 56
    // total = 60
};

// Let me re-verify x86:
// dwStructSize(4)@0
// lpszScheme(4)@4
// dwSchemeLength(4)@8
// nScheme(4)@12
// lpszHostName(4)@16
// dwHostNameLength(4)@20
// nPort(2)@24
// pad1(2)@26
// lpszUserName(4)@28
// dwUserNameLength(4)@32
// lpszPassword(4)@36
// dwPasswordLength(4)@40
// lpszUrlPath(4)@44
// dwUrlPathLength(4)@48
// lpszExtraInfo(4)@52
// dwExtraInfoLength(4)@56
// total = 60

template <>
struct URL_COMPONENTS_POD<8> {
    uint32_t dwStructSize;        // offset   0
    uint32_t pad1;                // offset   4
    uint64_t lpszScheme;          // offset   8 (Ptr)
    uint32_t dwSchemeLength;      // offset  16
    uint32_t nScheme;             // offset  20
    uint64_t lpszHostName;        // offset  24 (Ptr) — 24 is 8-byte aligned
    uint32_t dwHostNameLength;    // offset  32
    uint16_t nPort;               // offset  36
    uint8_t  pad2[2];             // offset  38 → align to 40 (for next Ptr)
    uint64_t lpszUserName;        // offset  40 (Ptr)
    uint32_t dwUserNameLength;    // offset  48
    uint32_t pad3;                // offset  52 → align next Ptr to 8 (52+4=56)
    uint64_t lpszPassword;        // offset  56 (Ptr)
    uint32_t dwPasswordLength;    // offset  64
    uint32_t pad4;                // offset  68 → align next Ptr to 8 (68+4=72)
    uint64_t lpszUrlPath;         // offset  72 (Ptr)
    uint32_t dwUrlPathLength;     // offset  80
    uint32_t pad5;                // offset  84 → align next Ptr to 8 (84+4=88)
    uint64_t lpszExtraInfo;       // offset  88 (Ptr)
    uint32_t dwExtraInfoLength;   // offset  96
    uint32_t pad6;                // offset 100 → natural alignment to 8 (100+4=104)
    // total = 104
};

// Let me verify x64:
// dwStructSize(4)+pad1(4)=8, lpszScheme(8)=16, dwSchemeLength(4)=20, nScheme(4)=24
// lpszHostName(8)=32, dwHostNameLength(4)=36, nPort(2)=38, pad2(2)=40
// lpszUserName(8)=48, dwUserNameLength(4)=52, pad3(4)=56
// lpszPassword(8)=64, dwPasswordLength(4)=68, pad4(4)=72
// lpszUrlPath(8)=80, dwUrlPathLength(4)=84, pad5(4)=88
// lpszExtraInfo(8)=96, dwExtraInfoLength(4)=100, pad6(4)=104
// Total = 104 ✓

template <int PtrSize>
struct URL_COMPONENTS : public EmuStructHelper<URL_COMPONENTS<PtrSize>>,
                        public URL_COMPONENTS_POD<PtrSize> {
    std::string get_mem_tag() const override { return "url_components"; }
};

// ==========================================================================================================
// WinHTTP constants
// ==========================================================================================================
constexpr uint32_t kWinHttpAddreqIndexMask          = 0x0000FFFF;
constexpr uint32_t kWinHttpAddreqFlagsMask          = 0xFFFF0000;
constexpr uint32_t kWinHttpAddreqFlagAddIfNew       = 0x10000000;
constexpr uint32_t kWinHttpAddreqFlagAdd            = 0x20000000;
constexpr uint32_t kWinHttpAddreqFlagCoalesceWithComma    = 0x40000000;
constexpr uint32_t kWinHttpAddreqFlagCoalesceWithSemicolon = 0x01000000;

constexpr int kWinHttpQueryMimeVersion          = 0;
constexpr int kWinHttpQueryContentType           = 1;
constexpr int kWinHttpQueryContentTransferEncoding = 2;
constexpr int kWinHttpQueryContentId             = 3;
constexpr int kWinHttpQueryContentDescription    = 4;
constexpr int kWinHttpQueryContentLength         = 5;
constexpr int kWinHttpQueryContentLanguage       = 6;
constexpr int kWinHttpQueryAllow                 = 7;
constexpr int kWinHttpQueryPublic                = 8;
constexpr int kWinHttpQueryDate                  = 9;
constexpr int kWinHttpQueryExpires               = 10;
constexpr int kWinHttpQueryLastModified          = 11;
constexpr int kWinHttpQueryMessageId             = 12;
constexpr int kWinHttpQueryUri                   = 13;
constexpr int kWinHttpQueryDerivedFrom           = 14;
constexpr int kWinHttpQueryCost                  = 15;
constexpr int kWinHttpQueryLink                  = 16;
constexpr int kWinHttpQueryPragma                = 17;
constexpr int kWinHttpQueryVersion               = 18;
constexpr int kWinHttpQueryStatusCode            = 19;
constexpr int kWinHttpQueryStatusText            = 20;
constexpr int kWinHttpQueryRawHeaders            = 21;
constexpr int kWinHttpQueryRawHeadersCrlf        = 22;
constexpr int kWinHttpQueryConnection            = 23;
constexpr int kWinHttpQueryAccept                = 24;
constexpr int kWinHttpQueryAcceptCharset         = 25;
constexpr int kWinHttpQueryAcceptEncoding        = 26;
constexpr int kWinHttpQueryAcceptLanguage        = 27;
constexpr int kWinHttpQueryAuthorization         = 28;
constexpr int kWinHttpQueryContentEncoding       = 29;
constexpr int kWinHttpQueryForwarded             = 30;
constexpr int kWinHttpQueryFrom                  = 31;
constexpr int kWinHttpQueryIfModifiedSince       = 32;
constexpr int kWinHttpQueryLocation              = 33;
constexpr int kWinHttpQueryOrigUri               = 34;
constexpr int kWinHttpQueryReferer               = 35;
constexpr int kWinHttpQueryRetryAfter            = 36;
constexpr int kWinHttpQueryServer                = 37;
constexpr int kWinHttpQueryTitle                 = 38;
constexpr int kWinHttpQueryUserAgent             = 39;
constexpr int kWinHttpQueryWwwAuthenticate        = 40;
constexpr int kWinHttpQueryProxyAuthenticate      = 41;
constexpr int kWinHttpQueryAcceptRanges          = 42;
constexpr int kWinHttpQuerySetCookie             = 43;
constexpr int kWinHttpQueryCookie                = 44;
constexpr int kWinHttpQueryRequestMethod         = 45;
constexpr int kWinHttpQueryRefresh               = 46;
constexpr int kWinHttpQueryContentDisposition    = 47;
constexpr int kWinHttpQueryAge                   = 48;
constexpr int kWinHttpQueryCacheControl          = 49;
constexpr int kWinHttpQueryContentBase           = 50;
constexpr int kWinHttpQueryContentLocation       = 51;
constexpr int kWinHttpQueryContentMd5            = 52;
constexpr int kWinHttpQueryContentRange          = 53;
constexpr int kWinHttpQueryEtag                  = 54;
constexpr int kWinHttpQueryHost                  = 55;
constexpr int kWinHttpQueryIfMatch               = 56;
constexpr int kWinHttpQueryIfNoneMatch           = 57;
constexpr int kWinHttpQueryIfRange               = 58;
constexpr int kWinHttpQueryIfUnmodifiedSince     = 59;
constexpr int kWinHttpQueryMaxForwards           = 60;
constexpr int kWinHttpQueryProxyAuthorization    = 61;
constexpr int kWinHttpQueryRange                 = 62;
constexpr int kWinHttpQueryTransferEncoding      = 63;
constexpr int kWinHttpQueryUpgrade               = 64;
constexpr int kWinHttpQueryVary                  = 65;
constexpr int kWinHttpQueryVia                   = 66;
constexpr int kWinHttpQueryWarning               = 67;
constexpr int kWinHttpQueryExpect                = 68;
constexpr int kWinHttpQueryProxyConnection       = 69;
constexpr int kWinHttpQueryUnlessModifiedSince   = 70;
constexpr int kWinHttpQueryProxySupport          = 75;
constexpr int kWinHttpQueryAuthenticationInfo    = 76;
constexpr int kWinHttpQueryPassportUrls          = 77;
constexpr int kWinHttpQueryPassportConfig        = 78;
constexpr int kWinHttpQueryMax                   = 78;

constexpr int kInternetOptionSecurityFlags = 31;
constexpr int kSecurityFlagSecure          = 1;
constexpr int kErrorInsufficientBuffer     = 122;

#pragma pack(pop)

} // namespace deffs
} // namespace speakeasy

#endif // SPEAKEASY_DEFS_NEW_WININET_H
