// ncrypt.h — ncrypt.dll API handler (v2 — macro-based registration)
#ifndef SPEAKEASY_NCRYPT_H
#define SPEAKEASY_NCRYPT_H
#include <string>
#include <vector>
#include "api_handler_base.h"

namespace speakeasy { namespace api {

class Ncrypt : public ApiHandler {
    API_LIST_BEGIN
    API_ENTRY(NCryptOpenStorageProvider, 3)  API_ENTRY(NCryptImportKey, 8)
    API_ENTRY(NCryptDeleteKey, 2)            API_ENTRY(NCryptFreeObject, 1)
    API_LIST_END

public:
    Ncrypt();
    std::string get_name() const override { return "ncrypt"; }
    const std::vector<ApiEntry>& get_apis() const override { return apis_; }
};

}} // namespaces
#endif
