// usbd.cpp — USB Driver handler (STUB)
#include "usbd.h"

namespace speakeasy { namespace api { namespace kernelmode {

Usbd::Usbd() {
    INIT_API_TABLE(Usbd)
    REG(Usbd, USBD_ValidateConfigurationDescriptor, 5)
    END_API_TABLE
}

#define U_STUB(n) KERNEL_STUB(Usbd, n)
U_STUB(USBD_ValidateConfigurationDescriptor)

}}} // namespaces
