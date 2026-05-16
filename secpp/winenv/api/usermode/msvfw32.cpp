// msvfw32.cpp — msvfw32.dll handler (stubs)
#include "msvfw32.h"

namespace speakeasy { namespace api {

Msvfw32::Msvfw32() {
    INIT_API_TABLE(Msvfw32)
    REG(Msvfw32, ICOpen, 3)
    REG(Msvfw32, ICSendMessage, 4)
    REG(Msvfw32, ICClose, 1)
    END_API_TABLE
}

#define STUB_MSVFW(n) STUB(Msvfw32, n)

STUB_MSVFW(ICOpen)
STUB_MSVFW(ICSendMessage)
STUB_MSVFW(ICClose)

}} // namespaces
