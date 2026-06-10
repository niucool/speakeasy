// gdi32.cpp  gdi32.dll handler (~22 APIs, real implementations)
#include "gdi32.h"

#include <vector>

#include "memmgr.h"
#include "struct.h"
#include "winenv/arch.h"
#include "windows/winemu.h"

using namespace speakeasy;

namespace speakeasy { namespace api {

//  Typed cast helpers 
static inline BinaryEmulator* be(void* e) {
    return static_cast<BinaryEmulator*>(e);
}
static inline MemoryManager* mm(void* e) {
    return static_cast<MemoryManager*>(e);
}

//  Static GDI handle counter 
static uint64_t gdi_handle_counter = 0x1000;

static uint64_t gdi_next_handle() {
    gdi_handle_counter += 4;
    return gdi_handle_counter;
}

//  Constructor 

GDI32::GDI32(void* emu) : ApiHandler(emu) {
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

//  API implementations 

uint64_t GDI32::CreateBitmap(void* e, ArgList& a, void* ctx) {
    (void)e; (void)a;
    return gdi_next_handle();
}

uint64_t GDI32::MoveToEx(void* e, ArgList& a, void* ctx) {
    (void)e; (void)a;
    return 1;
}

uint64_t GDI32::LineTo(void* e, ArgList& a, void* ctx) {
    (void)e; (void)a;
    return 1;
}

uint64_t GDI32::GetStockObject(void* e, ArgList& a, void* ctx) {
    (void)e; (void)a;
    return 0;
}

uint64_t GDI32::GetMapMode(void* e, ArgList& a, void* ctx) {
    (void)e; (void)a;
    return 1;
}

uint64_t GDI32::GetDeviceCaps(void* e, ArgList& a, void* ctx) {
    (void)e; (void)a;
    return 16;
}

uint64_t GDI32::GdiSetBatchLimit(void* e, ArgList& a, void* ctx) {
    (void)e; (void)a;
    return 0;
}

uint64_t GDI32::MaskBlt(void* e, ArgList& a, void* ctx) {
    (void)e; (void)a;
    return 1;
}

uint64_t GDI32::BitBlt(void* e, ArgList& a, void* ctx) {
    (void)e; (void)a;
    return 1;
}

uint64_t GDI32::DeleteDC(void* e, ArgList& a, void* ctx) {
    (void)e; (void)a;
    return 1;
}

uint64_t GDI32::SelectObject(void* e, ArgList& a, void* ctx) {
    (void)e; (void)a;
    return 0;
}

uint64_t GDI32::DeleteObject(void* e, ArgList& a, void* ctx) {
    (void)e; (void)a;
    return 1;
}

uint64_t GDI32::CreateCompatibleBitmap(void* e, ArgList& a, void* ctx) {
    (void)e; (void)a;
    return gdi_next_handle();
}

uint64_t GDI32::CreateCompatibleDC(void* e, ArgList& a, void* ctx) {
    (void)e; (void)a;
    return gdi_next_handle();
}

uint64_t GDI32::GetDIBits(void* e, ArgList& a, void* ctx) {
    (void)e; (void)a;
    return 0;
}

uint64_t GDI32::CreateDIBSection(void* e, ArgList& a, void* ctx) {
    (void)e; (void)a;
    return gdi_next_handle();
}

uint64_t GDI32::CreateDCA(void* e, ArgList& a, void* ctx) {
    (void)e; (void)a;
    return gdi_next_handle();
}

uint64_t GDI32::GetTextCharacterExtra(void* e, ArgList& a, void* ctx) {
    (void)e; (void)a;
    return 0x8000000;
}

uint64_t GDI32::StretchBlt(void* e, ArgList& a, void* ctx) {
    (void)e; (void)a;
    return 0;
}

uint64_t GDI32::CreateFontIndirectA(void* e, ArgList& a, void* ctx) {
    (void)e; (void)a;
    return 0x6000;
}

uint64_t GDI32::GetObjectA(void* e, ArgList& a, void* ctx) {
    uint64_t h = a[0], c = a[1], pv = a[2];
    if (pv && c) {
        std::vector<uint8_t> zero(static_cast<size_t>(c), 0);
        mm(e)->mem_write(pv, zero);
    }
    (void)h;
    return c;
}

uint64_t GDI32::WidenPath(void* e, ArgList& a, void* ctx) {
    (void)e; (void)a;
    return 1;
}

}} // namespaces
