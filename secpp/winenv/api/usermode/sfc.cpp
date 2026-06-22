// sfc.cpp  sfc.dll handler (real implementations)
#include "sfc.h"
#include <cstdint>
#include <string>
#include <vector>
#include "windows/winemu.h"
#include "struct.h"

using namespace speakeasy;

namespace speakeasy { namespace api {


// 
//  SfcIsFileProtected
// 
uint64_t Sfc::SfcIsFileProtected(void* e, ArgList& a, void* ctx) {
    (void)e; (void)a;
    return 0;  // FALSE - file is not protected
}

// 
//  SfcTerminateWatcherThread
// 
uint64_t Sfc::SfcTerminateWatcherThread(void* e, ArgList& a, void* ctx) {
    (void)e; (void)a;
    return 0;  // TRUE (non-zero success)
}

//  Constructor 
Sfc::Sfc(void* emu) : ApiHandler(emu) {
    INIT_API_TABLE(Sfc)
    REG(Sfc, SfcIsFileProtected, 2)
    REGX(Sfc, SfcTerminateWatcherThread, 0, 2)
    END_API_TABLE
}

}} // namespaces
