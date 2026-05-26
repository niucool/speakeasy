// urlmon.h  urlmon.dll API handler (v2  macro-based registration)
#ifndef SPEAKEASY_URLMON_H
#define SPEAKEASY_URLMON_H
#include <string>
#include <vector>
#include "../api.h"

namespace speakeasy { namespace api {

class Urlmon : public ApiHandler {
    API_LIST_BEGIN
    API_ENTRY(URLDownloadToFile, 5)       API_ENTRY(URLDownloadToCacheFile, 6)
    API_LIST_END

public:
    Urlmon(void* emu);
    std::string get_name() const override { return "urlmon"; }
    const std::vector<ApiEntry>& get_apis() const override { return apis_; }
};

}} // namespaces
#endif
