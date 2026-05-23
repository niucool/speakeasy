// wdfldr.h — Windows Driver Framework Loader API handler (STUB)
#ifndef SPEAKEASY_KERNELMODE_WDFLDR_H
#define SPEAKEASY_KERNELMODE_WDFLDR_H
#include <string>
#include <vector>
#include "../api.h"

namespace speakeasy { namespace api { namespace kernelmode {

class Wdfldr : public ApiHandler {
    API_LIST_BEGIN
    API_ENTRY(WdfVersionBind, 4)
    API_ENTRY(WdfDriverCreate, 6)
    API_ENTRY(WdfDeviceInitSetPnpPowerEventCallbacks, 3)
    API_ENTRY(WdfDeviceInitSetRequestAttributes, 3)
    API_ENTRY(WdfDeviceInitSetFileObjectConfig, 4)
    API_ENTRY(WdfDeviceInitSetIoType, 3)
    API_ENTRY(WdfDeviceCreate, 4)
    API_ENTRY(WdfObjectGetTypedContextWorker, 3)
    API_ENTRY(WdfDriverOpenParametersRegistryKey, 5)
    API_ENTRY(WdfRegistryQueryULong, 4)
    API_ENTRY(WdfRegistryClose, 2)
    API_ENTRY(WdfDeviceSetPnpCapabilities, 3)
    API_ENTRY(WdfIoQueueReadyNotify, 4)
    API_ENTRY(WdfDeviceCreateDeviceInterface, 4)
    API_ENTRY(WdfIoQueueCreate, 5)
    API_ENTRY(WdfDeviceWdmGetAttachedDevice, 2)
    API_ENTRY(WdfDeviceWdmGetDeviceObject, 2)
    API_ENTRY(WdfUsbTargetDeviceCreateWithParameters, 5)
    API_ENTRY(WdfUsbTargetDeviceGetDeviceDescriptor, 3)
    API_ENTRY(WdfMemoryCreate, 7)
    API_ENTRY(WdfUsbTargetDeviceSelectConfig, 4)
    API_ENTRY(WdfUsbTargetDeviceRetrieveConfigDescriptor, 4)
    API_ENTRY(WdfUsbInterfaceSelectSetting, 4)
    API_ENTRY(WdfUsbTargetDeviceGetNumInterfaces, 2)
    API_ENTRY(WdfUsbInterfaceGetNumConfiguredPipes, 2)
    API_ENTRY(WdfUsbInterfaceGetNumSettings, 2)
    API_ENTRY(WdfUsbTargetDeviceRetrieveInformation, 3)
    API_ENTRY(WdfUsbInterfaceGetConfiguredPipe, 4)
    API_ENTRY(WdfUsbTargetPipeGetInformation, 3)
    API_ENTRY(WdfUsbInterfaceGetInterfaceNumber, 2)
    API_LIST_END
public:
    Wdfldr(void* emu);
    std::string get_name() const override { return "wdfldr"; }
    const std::vector<ApiEntry>& get_apis() const override { return apis_; }
};

}}} // namespaces
#endif
