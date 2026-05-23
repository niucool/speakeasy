// bcrypt.h — bcrypt.dll API handler (v2 — macro-based registration)
//
// Maps to: speakeasy/winenv/api/usermode/bcrypt.py

#ifndef SPEAKEASY_BCRYPT_H
#define SPEAKEASY_BCRYPT_H

#include <string>
#include <vector>
#include "../api.h"

namespace speakeasy { namespace api {

class Bcrypt : public ApiHandler {
    API_LIST_BEGIN
    API_ENTRY(BCryptOpenAlgorithmProvider, 4)
    API_ENTRY(BCryptImportKeyPair, 7)
    API_ENTRY(BCryptCloseAlgorithmProvider, 2)
    API_ENTRY(BCryptGetProperty, 6)
    API_ENTRY(BCryptDestroyKey, 1)
    API_LIST_END

public:
    Bcrypt(void* emu);
    std::string get_name() const override { return "bcrypt"; }
    const std::vector<ApiEntry>& get_apis() const override { return apis_; }
};

}} // namespaces
#endif
