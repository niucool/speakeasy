// oleaut32.cpp — oleaut32.dll handler (stubs)
#include "oleaut32.h"

namespace speakeasy { namespace api {

Oleaut32::Oleaut32() {
    INIT_API_TABLE(Oleaut32)
    REG(Oleaut32, SysAllocString, 1)
    REG(Oleaut32, SysAllocStringLen, 2)
    REG(Oleaut32, SysFreeString, 1)
    REG(Oleaut32, VariantInit, 1)
    END_API_TABLE
}

#define STUB_OLE(n) STUB(Oleaut32, n)

STUB_OLE(SysAllocString)
STUB_OLE(SysAllocStringLen)
STUB_OLE(SysFreeString)
STUB_OLE(VariantInit)

}} // namespaces
