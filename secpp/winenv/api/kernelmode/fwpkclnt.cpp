// fwpkclnt.cpp — Windows Filtering Platform handler (STUB)
#include "fwpkclnt.h"

namespace speakeasy { namespace api { namespace kernelmode {

Fwpkclnt::Fwpkclnt() {
    INIT_API_TABLE(Fwpkclnt)
    REG(Fwpkclnt, FwpmEngineOpen0, 5)
    REG(Fwpkclnt, FwpmEngineClose0, 1)
    REG(Fwpkclnt, FwpmSubLayerAdd0, 3)
    REG(Fwpkclnt, FwpmSubLayerDeleteByKey0, 2)
    REG(Fwpkclnt, FwpmCalloutAdd0, 4)
    REG(Fwpkclnt, FwpmCalloutDeleteById0, 2)
    REG(Fwpkclnt, FwpmFilterAdd0, 4)
    REG(Fwpkclnt, FwpmFilterDeleteById0, 2)
    REG(Fwpkclnt, FwpsCalloutRegister1, 3)
    REG(Fwpkclnt, FwpsCalloutUnregisterById0, 1)
    REG(Fwpkclnt, FwpsInjectionHandleCreate0, 3)
    REG(Fwpkclnt, FwpsInjectionHandleDestroy0, 1)
    END_API_TABLE
}

#define FK_STUB(n) KERNEL_STUB(Fwpkclnt, n)
FK_STUB(FwpmEngineOpen0)       FK_STUB(FwpmEngineClose0)
FK_STUB(FwpmSubLayerAdd0)      FK_STUB(FwpmSubLayerDeleteByKey0)
FK_STUB(FwpmCalloutAdd0)       FK_STUB(FwpmCalloutDeleteById0)
FK_STUB(FwpmFilterAdd0)        FK_STUB(FwpmFilterDeleteById0)
FK_STUB(FwpsCalloutRegister1)  FK_STUB(FwpsCalloutUnregisterById0)
FK_STUB(FwpsInjectionHandleCreate0) FK_STUB(FwpsInjectionHandleDestroy0)

}}} // namespaces
