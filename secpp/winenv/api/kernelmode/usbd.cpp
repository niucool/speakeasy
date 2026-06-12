// usbd.cpp  USB Driver handler (implemented)
#include "usbd.h"

#include <cstdint>
#include <vector>
#include <string>

#include "memmgr.h"
#include "struct.h"
#include "winenv/arch.h"
#include "windows/winemu.h"

using namespace speakeasy;

namespace speakeasy { namespace api { namespace kernelmode {

//  Typed cast helpers 

Usbd::Usbd(void* emu) : ApiHandler(emu) {
    INIT_API_TABLE(Usbd)
    REG(Usbd, USBD_ValidateConfigurationDescriptor, 5)
    END_API_TABLE
}

//  Implementations 

uint64_t Usbd::USBD_ValidateConfigurationDescriptor(void* e, ArgList& a, void* ctx) {
    // NTSTATUS USBD_ValidateConfigurationDescriptor(
    //     PUSB_CONFIGURATION_DESCRIPTOR ConfigurationDescriptor,
    //     ULONG BufferLength,
    //     USBD_PIPE_HANDLE *UsbdHandle,
    //     USBD_HANDLE USBDHandle,
    //     PULONG Offset);
    // Returns STATUS_SUCCESS
    (void)e; (void)a;
    return 0; // STATUS_SUCCESS
}

}}} // namespaces
