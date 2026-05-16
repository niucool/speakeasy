// gdi32.h — gdi32.dll API handler (v2 — macro-based registration)
#ifndef SPEAKEASY_GDI32_H
#define SPEAKEASY_GDI32_H
#include <string>
#include <vector>
#include "api_handler_base.h"

namespace speakeasy { namespace api {

class GDI32 : public ApiHandler {
    API_LIST_BEGIN
    API_ENTRY(CreateBitmap, 5)        API_ENTRY(MoveToEx, 1)
    API_ENTRY(LineTo, 1)              API_ENTRY(GetStockObject, 1)
    API_ENTRY(GetMapMode, 1)          API_ENTRY(GetDeviceCaps, 2)
    API_ENTRY(GdiSetBatchLimit, 1)    API_ENTRY(MaskBlt, 12)
    API_ENTRY(BitBlt, 9)              API_ENTRY(DeleteDC, 1)
    API_ENTRY(SelectObject, 2)        API_ENTRY(DeleteObject, 1)
    API_ENTRY(CreateCompatibleBitmap, 3) API_ENTRY(CreateCompatibleDC, 1)
    API_ENTRY(GetDIBits, 7)           API_ENTRY(CreateDIBSection, 6)
    API_ENTRY(CreateDCA, 4)           API_ENTRY(GetTextCharacterExtra, 1)
    API_ENTRY(StretchBlt, 11)         API_ENTRY(CreateFontIndirectA, 1)
    API_ENTRY(GetObjectA, 3)          API_ENTRY(WidenPath, 1)
    API_LIST_END

public:
    GDI32();
    std::string get_name() const override { return "gdi32"; }
    const std::vector<ApiEntry>& get_apis() const override { return apis_; }
};

}} // namespaces
#endif
