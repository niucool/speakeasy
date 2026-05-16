// gdi32.cpp — gdi32.dll handler (~22 APIs, macro-driven stubs)
#include "gdi32.h"

namespace speakeasy { namespace api {

GDI32::GDI32() {
    INIT_API_TABLE(GDI32)
    REG(GDI32, CreateBitmap, 5)          REG(GDI32, MoveToEx, 1)
    REG(GDI32, LineTo, 1)                REG(GDI32, GetStockObject, 1)
    REG(GDI32, GetMapMode, 1)            REG(GDI32, GetDeviceCaps, 2)
    REG(GDI32, GdiSetBatchLimit, 1)      REG(GDI32, MaskBlt, 12)
    REG(GDI32, BitBlt, 9)                REG(GDI32, DeleteDC, 1)
    REG(GDI32, SelectObject, 2)          REG(GDI32, DeleteObject, 1)
    REG(GDI32, CreateCompatibleBitmap, 3) REG(GDI32, CreateCompatibleDC, 1)
    REG(GDI32, GetDIBits, 7)             REG(GDI32, CreateDIBSection, 6)
    REG(GDI32, CreateDCA, 4)             REG(GDI32, GetTextCharacterExtra, 1)
    REG(GDI32, StretchBlt, 11)           REG(GDI32, CreateFontIndirectA, 1)
    REG(GDI32, GetObjectA, 3)            REG(GDI32, WidenPath, 1)
    END_API_TABLE
}

// ── Bulk stubs ──────────────────────────────────────────────

#define GDI32_STUB(n) STUB(GDI32, n)

GDI32_STUB(CreateBitmap) GDI32_STUB(MoveToEx) GDI32_STUB(LineTo)
GDI32_STUB(GetStockObject) GDI32_STUB(GetMapMode) GDI32_STUB(GetDeviceCaps)
GDI32_STUB(GdiSetBatchLimit) GDI32_STUB(MaskBlt) GDI32_STUB(BitBlt)
GDI32_STUB(DeleteDC) GDI32_STUB(SelectObject) GDI32_STUB(DeleteObject)
GDI32_STUB(CreateCompatibleBitmap) GDI32_STUB(CreateCompatibleDC)
GDI32_STUB(GetDIBits) GDI32_STUB(CreateDIBSection) GDI32_STUB(CreateDCA)
GDI32_STUB(GetTextCharacterExtra) GDI32_STUB(StretchBlt)
GDI32_STUB(CreateFontIndirectA) GDI32_STUB(GetObjectA) GDI32_STUB(WidenPath)

}} // namespaces
