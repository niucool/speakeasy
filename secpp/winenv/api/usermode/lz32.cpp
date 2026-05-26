// lz32.cpp  lz32.dll handler (real implementations)
#include "lz32.h"
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
//  LZSeek
// 
uint64_t Lz32::LZSeek(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    (void)e; (void)a;
    return static_cast<uint64_t>(-1);  // LZ_ERROR
}

//  Constructor 
Lz32::Lz32(void* emu) : ApiHandler(emu) {
    INIT_API_TABLE(Lz32)
    REG(Lz32, LZSeek, 3)
    END_API_TABLE
}

}} // namespaces
