// msvfw32.cpp — msvfw32.dll handler (real implementations)
#include "msvfw32.h"
#include <cstdint>
#include <string>
#include <vector>
#include "windows/winemu.h"
#include "struct.h"

using namespace speakeasy;

namespace speakeasy { namespace api {

static inline WindowsEmulator* we(void* e) { return static_cast<WindowsEmulator*>(e); }
static inline BinaryEmulator* be(void* e) { return static_cast<BinaryEmulator*>(e); }

// Next handle generator
static uint64_t msvfw_next_handle = 0x7000;

static uint64_t msvfw_get_handle() {
    uint64_t h = msvfw_next_handle;
    msvfw_next_handle += 4;
    return h;
}

// ═══════════════════════════════════════════════════════════════
//  ICOpen
// ═══════════════════════════════════════════════════════════════
uint64_t Msvfw32::ICOpen(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    (void)e; (void)a;
    return msvfw_get_handle();
}

// ═══════════════════════════════════════════════════════════════
//  ICSendMessage
// ═══════════════════════════════════════════════════════════════
uint64_t Msvfw32::ICSendMessage(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    (void)e; (void)a;
    return 1;
}

// ═══════════════════════════════════════════════════════════════
//  ICClose
// ═══════════════════════════════════════════════════════════════
uint64_t Msvfw32::ICClose(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    (void)e; (void)a;
    return 1;
}

// ── Constructor ─────────────────────────────────────────────────
Msvfw32::Msvfw32(void* emu) : ApiHandler(emu) {
    INIT_API_TABLE(Msvfw32)
    REG(Msvfw32, ICOpen, 3)
    REG(Msvfw32, ICSendMessage, 4)
    REG(Msvfw32, ICClose, 1)
    END_API_TABLE
}

}} // namespaces
