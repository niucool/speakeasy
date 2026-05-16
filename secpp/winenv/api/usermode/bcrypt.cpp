// bcrypt.cpp — bcrypt.dll API handler (stubs)
#include "bcrypt.h"

namespace speakeasy { namespace api {

// NTSTATUS constants
static constexpr uint32_t STATUS_SUCCESS = 0x00000000;
static constexpr uint32_t STATUS_INVALID_HANDLE = 0xC0000008;

#define BCRYPT_STUB(n) STUB(Bcrypt, n)

BCRYPT_STUB(BCryptOpenAlgorithmProvider)
BCRYPT_STUB(BCryptImportKeyPair)
BCRYPT_STUB(BCryptCloseAlgorithmProvider)
BCRYPT_STUB(BCryptGetProperty)
BCRYPT_STUB(BCryptDestroyKey)

Bcrypt::Bcrypt() {
    INIT_API_TABLE(Bcrypt)
    REG(Bcrypt, BCryptOpenAlgorithmProvider, 4)
    REG(Bcrypt, BCryptImportKeyPair, 7)
    REG(Bcrypt, BCryptCloseAlgorithmProvider, 2)
    REG(Bcrypt, BCryptGetProperty, 6)
    REG(Bcrypt, BCryptDestroyKey, 1)
    END_API_TABLE
}

}} // namespaces
