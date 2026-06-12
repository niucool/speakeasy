// msimg32.cpp  msimg32.dll handler (real implementations)
#include "msimg32.h"
#include <cstdint>
#include <string>
#include <vector>
#include "windows/winemu.h"
#include "struct.h"

using namespace speakeasy;

namespace speakeasy { namespace api {


// 
//  TransparentBlt
// 
uint64_t Msimg32::TransparentBlt(void* e, ArgList& a, void* ctx) {
    (void)e; (void)a;
    return 1;  // TRUE
}

//  Constructor 
Msimg32::Msimg32(void* emu) : ApiHandler(emu) {
    INIT_API_TABLE(Msimg32)
    REG(Msimg32, TransparentBlt, 11)
    END_API_TABLE
}

}} // namespaces
