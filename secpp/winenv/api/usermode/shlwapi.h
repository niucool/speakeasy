// shlwapi.h — shlwapi.dll API handler (v2 — macro-based registration)
#ifndef SPEAKEASY_SHLWAPI_H
#define SPEAKEASY_SHLWAPI_H
#include <string>
#include <vector>
#include "api_handler_base.h"

namespace speakeasy { namespace api {

class Shlwapi : public ApiHandler {
    API_LIST_BEGIN
    API_ENTRY(PathIsRelative, 1)      API_ENTRY(StrStr, 2)
    API_ENTRY(StrStrI, 2)             API_ENTRY(PathFindExtension, 1)
    API_ENTRY(StrCmpI, 2)             API_ENTRY(PathFindFileName, 1)
    API_ENTRY(PathRemoveExtension, 1) API_ENTRY(PathStripPath, 1)
    API_ENTRY(wvnsprintfA, 4)         API_ENTRY(wnsprintf, 4)
    API_ENTRY(PathAppend, 2)          API_ENTRY(PathCanonicalize, 2)
    API_ENTRY(PathRemoveFileSpec, 1)  API_ENTRY(PathAddBackslash, 1)
    API_ENTRY(PathRenameExtension, 2)
    API_LIST_END

public:
    Shlwapi();
    std::string get_name() const override { return "shlwapi"; }
    const std::vector<ApiEntry>& get_apis() const override { return apis_; }
};

}} // namespaces
#endif
