// advpack.cpp  advpack.dll handler (real implementations)
#include "advpack.h"
#include <cstdint>
#include <string>
#include <vector>
#include <map>
#include "windows/winemu.h"
#include "struct.h"

using namespace speakeasy;

namespace speakeasy { namespace api {

static inline WindowsEmulator* we(void* e) { return static_cast<WindowsEmulator*>(e); }
static inline BinaryEmulator* be(void* e) { return static_cast<BinaryEmulator*>(e); }

// 
//  IsNTAdmin
// 
uint64_t Advpack::IsNTAdmin(void* e, const std::string&, int, const std::vector<uint64_t>& a) {
    (void)a;
    std::map<std::string, std::string> user = be(e)->get_user();
    auto it = user.find("is_admin");
    if (it != user.end() && it->second == "true") {
        return 1;  // TRUE
    }
    return 0;  // FALSE
}

//  Constructor 
Advpack::Advpack(void* emu) : ApiHandler(emu) {
    INIT_API_TABLE(Advpack)
    REG(Advpack, IsNTAdmin, 2)
    END_API_TABLE
}

}} // namespaces
