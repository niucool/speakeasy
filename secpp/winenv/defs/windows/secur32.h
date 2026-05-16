// secur32.h — Windows Security Support Provider Interface types
//
// Maps to: speakeasy/winenv/defs/windows/secur32.py
//
// EXTENDED_NAME_FORMAT constants and security structures for
// secur32 API handlers.

#ifndef SPEAKEASY_DEFS_WINDOWS_SECUR32_H
#define SPEAKEASY_DEFS_WINDOWS_SECUR32_H

#include <cstdint>
#include <vector>
#include "windef.h"
#include "../../../struct.h"

namespace speakeasy { namespace defs { namespace windows {

// ── EXTENDED_NAME_FORMAT ──────────────────────────────────────

constexpr uint32_t NameUnknown          = 0;
constexpr uint32_t NameFullyQualifiedDN = 1;
constexpr uint32_t NameSamCompatible    = 2;
constexpr uint32_t NameDisplay          = 3;
constexpr uint32_t NameUniqueId         = 6;
constexpr uint32_t NameCanonical        = 7;
constexpr uint32_t NameUserPrincipal    = 8;
constexpr uint32_t NameCanonicalEx      = 9;
constexpr uint32_t NameServicePrincipal = 0xA;
constexpr uint32_t NameDnsDomain        = 0xC;
constexpr uint32_t NameGivenName        = 0xD;
constexpr uint32_t NameSurname          = 0xE;

// ── SECURITY error codes ──────────────────────────────────────

constexpr int32_t SEC_E_INVALID_HANDLE  = 0x80090301;
constexpr int32_t SEC_E_OK              = 0;
constexpr int32_t SEC_E_INsufficientMemory = 0x80090300;
constexpr int32_t SEC_E_TARGET_UNKNOWN  = 0x80090303;
constexpr int32_t SEC_E_INTERNAL_ERROR  = 0x80090304;
constexpr int32_t SEC_E_SECPKG_NOT_FOUND = 0x80090305;
constexpr int32_t SEC_E_NOT_OWNER       = 0x80090306;
constexpr int32_t SEC_E_UNKNOWN_CREDENTIALS = 0x8009030D;
constexpr int32_t SEC_E_NO_CREDENTIALS  = 0x8009030E;
constexpr int32_t SEC_E_LOGON_DENIED    = 0x8009030C;
constexpr int32_t SEC_E_BUFFER_TOO_SMALL = 0x80090321;

// ── SecBuffer type flags ──────────────────────────────────────

constexpr uint32_t SECBUFFER_VERSION   = 0;
constexpr uint32_t SECBUFFER_EMPTY     = 0;
constexpr uint32_t SECBUFFER_DATA      = 1;
constexpr uint32_t SECBUFFER_TOKEN     = 2;
constexpr uint32_t SECBUFFER_PKG_PARAMS = 3;
constexpr uint32_t SECBUFFER_MISSING   = 4;
constexpr uint32_t SECBUFFER_EXTRA     = 5;
constexpr uint32_t SECBUFFER_STREAM_TRAILER = 6;
constexpr uint32_t SECBUFFER_STREAM_HEADER  = 7;
constexpr uint32_t SECBUFFER_NEGOTIATION_INFO = 8;
constexpr uint32_t SECBUFFER_PADDING    = 9;
constexpr uint32_t SECBUFFER_STREAM     = 10;

// ── Security package flags ────────────────────────────────────

constexpr uint32_t SECPKG_FLAG_INTEGRITY      = 0x1;
constexpr uint32_t SECPKG_FLAG_PRIVACY        = 0x2;
constexpr uint32_t SECPKG_FLAG_TOKEN_ONLY     = 0x4;
constexpr uint32_t SECPKG_FLAG_DATAGRAM       = 0x8;
constexpr uint32_t SECPKG_FLAG_CONNECTION     = 0x10;
constexpr uint32_t SECPKG_FLAG_MULTI_REQUIRED = 0x20;

// ── SecBuffer ─────────────────────────────────────────────────

struct SecBuffer : speakeasy::EmuStruct {
    uint32_t cbBuffer   = 0;  // Size of buffer
    uint32_t BufferType = 0;  // Type of buffer (SECBUFFER_*)
    uint64_t pvBuffer   = 0;  // Pointer to buffer data

    size_t sizeof_obj() const override {
        return (sizeof(uint64_t) == 8) ? 16 : 12;
    }
    std::vector<uint8_t> get_bytes() const override {
        size_t sz = sizeof_obj();
        std::vector<uint8_t> b(sz, 0);
        speakeasy::write_le(b, 0, cbBuffer, 4);
        speakeasy::write_le(b, 4, BufferType, 4);
        if (sz == 16) {
            speakeasy::write_le(b, 8, pvBuffer, 8);
        } else {
            speakeasy::write_le(b, 8, pvBuffer, 4);
        }
        return b;
    }
};

// ── SecBufferDesc ──────────────────────────────────────────────

struct SecBufferDesc : speakeasy::EmuStruct {
    uint32_t ulVersion   = SECBUFFER_VERSION;
    uint32_t cBuffers    = 0;   // Number of buffers
    uint64_t pBuffers    = 0;   // Pointer to SecBuffer array

    size_t sizeof_obj() const override {
        return (sizeof(uint64_t) == 8) ? 16 : 12;
    }
    std::vector<uint8_t> get_bytes() const override {
        size_t sz = sizeof_obj();
        std::vector<uint8_t> b(sz, 0);
        speakeasy::write_le(b, 0, ulVersion, 4);
        speakeasy::write_le(b, 4, cBuffers, 4);
        if (sz == 16) {
            speakeasy::write_le(b, 8, pBuffers, 8);
        } else {
            speakeasy::write_le(b, 8, pBuffers, 4);
        }
        return b;
    }
};

// ── SecPkgInfo ────────────────────────────────────────────────

struct SecPkgInfo : speakeasy::EmuStruct {
    uint32_t fCapabilities = 0;  // SECPKG_FLAG_*
    uint16_t wVersion      = 0;
    uint16_t wRPCID        = 0;
    uint32_t cbMaxToken    = 0;
    uint64_t Name          = 0;  // wchar_t*
    uint64_t Comment       = 0;  // wchar_t*

    size_t sizeof_obj() const override {
        return (sizeof(uint64_t) == 8) ? 32 : 20;
    }
    std::vector<uint8_t> get_bytes() const override {
        size_t sz = sizeof_obj();
        std::vector<uint8_t> b(sz, 0);
        speakeasy::write_le(b, 0, fCapabilities, 4);
        speakeasy::write_le(b, 4, wVersion, 2);
        speakeasy::write_le(b, 6, wRPCID, 2);
        speakeasy::write_le(b, 8, cbMaxToken, 4);
        if (sz == 32) {
            speakeasy::write_le(b, 12, 0, 4);  // padding
            speakeasy::write_le(b, 16, Name, 8);
            speakeasy::write_le(b, 24, Comment, 8);
        } else {
            speakeasy::write_le(b, 12, Name, 4);
            speakeasy::write_le(b, 16, Comment, 4);
        }
        return b;
    }
};

}}} // namespaces

#endif // SPEAKEASY_DEFS_WINDOWS_SECUR32_H
