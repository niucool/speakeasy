// bcryptprimitives.cpp  bcryptprimitives.dll handler (real implementations)
#include "bcryptprimitives.h"
#include <cstdint>
#include <cstdlib>
#include <string>
#include <vector>
#include "windows/winemu.h"
#include "struct.h"

using namespace speakeasy;

namespace speakeasy { namespace api {

static inline WindowsEmulator* we(void* e) { return static_cast<WindowsEmulator*>(e); }
static inline BinaryEmulator* be(void* e) { return static_cast<BinaryEmulator*>(e); }

// 
//  ProcessPrng
// 
uint64_t Bcryptprimitives::ProcessPrng(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    if (a.size() < 2) return 0;
    uint64_t pbData = a[0];
    uint64_t cbData = a[1];

    if (!pbData || cbData == 0) return 1;

    std::vector<uint8_t> buf(static_cast<size_t>(cbData));
    for (size_t i = 0; i < static_cast<size_t>(cbData); i++) {
        buf[i] = static_cast<uint8_t>(rand() & 0xFF);
    }
    we(e)->mem_write(pbData, buf);
    return 1;  // TRUE
}

//  Constructor 
Bcryptprimitives::Bcryptprimitives(void* emu) : ApiHandler(emu) {
    INIT_API_TABLE(Bcryptprimitives)
    REG(Bcryptprimitives, ProcessPrng, 2)
    END_API_TABLE
}

}} // namespaces
