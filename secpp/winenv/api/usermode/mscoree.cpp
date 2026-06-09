// mscoree.cpp  mscoree.dll handler (real implementations)
#include "mscoree.h"
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
//  CorExitProcess
// 
uint64_t Mscoree::CorExitProcess(void* e, std::vector<uint64_t>& a, void* ctx) {
    (void)e; (void)a;
    return 0;
}

//  Constructor 
Mscoree::Mscoree(void* emu) : ApiHandler(emu) {
    INIT_API_TABLE(Mscoree)
    REG(Mscoree, CorExitProcess, 1)
    END_API_TABLE
}

}} // namespaces
