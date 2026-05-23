// msimg32.cpp — msimg32.dll handler (real implementations)
#include "msimg32.h"
#include <cstdint>
#include <string>
#include <vector>
#include "windows/winemu.h"
#include "struct.h"

using namespace speakeasy;

namespace speakeasy { namespace api {

static inline WindowsEmulator* we(void* e) { return static_cast<WindowsEmulator*>(e); }
static inline BinaryEmulator* be(void* e) { return static_cast<BinaryEmulator*>(e); }

// ═══════════════════════════════════════════════════════════════
//  TransparentBlt
// ═══════════════════════════════════════════════════════════════
uint64_t Msimg32::TransparentBlt(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    (void)e; (void)a;
    return 1;  // TRUE
}

// ── Constructor ─────────────────────────────────────────────────
Msimg32::Msimg32(void* emu) : ApiHandler(emu) {
    INIT_API_TABLE(Msimg32)
    REG(Msimg32, TransparentBlt, 11)
    END_API_TABLE
}

}} // namespaces
