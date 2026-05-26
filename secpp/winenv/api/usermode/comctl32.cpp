// comctl32.cpp  comctl32.dll handler (real implementations)
#include "comctl32.h"
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
//  InitCommonControlsEx
// 
uint64_t Comctl32::InitCommonControlsEx(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    (void)e; (void)a;
    return 1;  // TRUE
}

// 
//  InitCommonControls
// 
uint64_t Comctl32::InitCommonControls(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    (void)e; (void)a;
    return 0;  // void, returns nothing
}

//  Constructor 
Comctl32::Comctl32(void* emu) : ApiHandler(emu) {
    INIT_API_TABLE(Comctl32)
    REG(Comctl32, InitCommonControlsEx, 1)
    REG(Comctl32, InitCommonControls, 0)
    END_API_TABLE
}

}} // namespaces
