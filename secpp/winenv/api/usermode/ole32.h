// ole32.h  ole32.dll API handler (v2  macro-based registration)
#ifndef SPEAKEASY_OLE32_H
#define SPEAKEASY_OLE32_H
#include <string>
#include <vector>
#include "../api.h"

namespace speakeasy { namespace api {

class Ole32 : public ApiHandler {
    API_LIST_BEGIN
    API_ENTRY(CoInitialize, 1)          API_ENTRY(CoUninitialize, 0)
    API_ENTRY(CoCreateInstance, 5)      API_ENTRY(CoGetClassObject, 4)
    API_ENTRY(CoTaskMemAlloc, 1)        API_ENTRY(CoTaskMemFree, 1)
    API_ENTRY(CLSIDFromString, 2)       API_ENTRY(StringFromGUID2, 3)
    API_ENTRY(ProgIDFromCLSID, 2)       API_ENTRY(CLSIDFromProgID, 2)
    API_ENTRY(OleInitialize, 1)         API_ENTRY(OleUninitialize, 0)
    API_ENTRY(OleSetClipboard, 1)       API_ENTRY(OleGetClipboard, 1)
    API_ENTRY(OleFlushClipboard, 0)     API_ENTRY(OleIsCurrentClipboard, 1)
    API_ENTRY(CreateBindCtx, 2)         API_ENTRY(BindMoniker, 4)
    API_ENTRY(MkParseDisplayName, 4)
    API_LIST_END

public:
    Ole32(void* emu);
    std::string get_name() const override { return "ole32"; }
    const std::vector<ApiEntry>& get_apis() const override { return apis_; }
};

}} // namespaces
#endif
