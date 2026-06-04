// msi32.cpp  msi32.dll handler (real implementations)
#include "msi32.h"
#include <cstdint>
#include <string>
#include <vector>
#include "windows/winemu.h"
#include "struct.h"

using namespace speakeasy;

namespace speakeasy { namespace api {

static inline WindowsEmulator* we(void* e) { return static_cast<WindowsEmulator*>(e); }
static inline BinaryEmulator* be(void* e) { return static_cast<BinaryEmulator*>(e); }

// 
//  MsiDatabaseMergeA
// 
uint64_t Msi32::MsiDatabaseMergeA(void* e, const std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a;
    return 0;  // ERROR_SUCCESS
}

//  Constructor 
Msi32::Msi32(void* emu) : ApiHandler(emu) {
    INIT_API_TABLE(Msi32)
    REG(Msi32, MsiDatabaseMergeA, 3)
    END_API_TABLE
}

}} // namespaces
