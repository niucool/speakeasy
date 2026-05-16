// ntoskrnl.h — Windows NT Kernel API handler (STUB)
// ~154 APIs from Python reference: speakeasy/winenv/api/kernelmode/ntoskrnl.py
#ifndef SPEAKEASY_KERNELMODE_NTOSKRNL_H
#define SPEAKEASY_KERNELMODE_NTOSKRNL_H
#include <string>
#include <vector>
#include "../usermode/api_handler_base.h"

namespace speakeasy { namespace api { namespace kernelmode {

class Ntoskrnl : public ApiHandler {
    API_LIST_BEGIN
    // Object/Reference
    API_ENTRY(ObfDereferenceObject, 1)    API_ENTRY(ObfReferenceObject, 1)
    API_ENTRY(ZwClose, 1)                  API_ENTRY(ObOpenObjectByPointer, 7)
    API_ENTRY(ObReferenceObjectByName, 8)  API_ENTRY(ObReferenceObjectByHandle, 6)
    API_ENTRY(ObMakeTemporaryObject, 1)    API_ENTRY(ObGetFilterVersion, 0)
    API_ENTRY(ObRegisterCallbacks, 2)      API_ENTRY(ObSetSecurityObjectByPointer, 3)
    // Debug/Print
    API_ENTRY(DbgPrint, 0)                 API_ENTRY(DbgPrintEx, 0)
    // String/Format
    API_ENTRY(_vsnprintf, 4)               API_ENTRY(vsprintf_s, 4)
    API_ENTRY(_snwprintf, 0)               API_ENTRY(sprintf, 0)
    API_ENTRY(_snprintf, 0)
    // Rtl string
    API_ENTRY(RtlAnsiStringToUnicodeString, 3) API_ENTRY(RtlInitAnsiString, 2)
    API_ENTRY(RtlInitUnicodeString, 2)     API_ENTRY(RtlFreeUnicodeString, 1)
    API_ENTRY(RtlCopyUnicodeString, 2)     API_ENTRY(RtlEqualUnicodeString, 3)
    API_ENTRY(RtlGetVersion, 1)            API_ENTRY(RtlCompareMemory, 3)
    API_ENTRY(RtlMoveMemory, 3)
    // Memory/Pool
    API_ENTRY(ExAllocatePoolWithTag, 3)    API_ENTRY(ExFreePoolWithTag, 2)
    API_ENTRY(ExAllocatePool, 2)           API_ENTRY(ExFreePool, 1)
    API_ENTRY(FsRtlAllocatePool, 2)        API_ENTRY(RtlAllocateHeap, 3)
    API_ENTRY(RtlFreeHeap, 3)              API_ENTRY(MmAllocateContiguousMemory, 2)
    API_ENTRY(MmFreeContiguousMemory, 1)   API_ENTRY(MmIsAddressValid, 1)
    API_ENTRY(MmMapLockedPagesSpecifyCache, 6) API_ENTRY(MmUnlockPages, 1)
    API_ENTRY(MmGetSystemRoutineAddress, 1) API_ENTRY(MmIsDriverVerifying, 1)
    // memcpy/memset/etc
    API_ENTRY(memmove, 3)                  API_ENTRY(memcpy, 3)
    API_ENTRY(memset, 3)
    // Wide char string
    API_ENTRY(wcscpy, 2)                   API_ENTRY(wcsncpy, 3)
    API_ENTRY(wcslen, 1)                   API_ENTRY(wcschr, 2)
    API_ENTRY(wcscat, 2)                   API_ENTRY(wcsnlen, 2)
    API_ENTRY(strrchr, 2)                  API_ENTRY(strchr, 2)
    API_ENTRY(_wcsnicmp, 3)                API_ENTRY(_stricmp, 2)
    API_ENTRY(_wcsicmp, 2)                 API_ENTRY(mbstowcs, 3)
    // I/O
    API_ENTRY(IoDeleteDriver, 1)           API_ENTRY(IoCreateDevice, 7)
    API_ENTRY(IoCreateDeviceSecure, 9)     API_ENTRY(IoCreateSymbolicLink, 2)
    API_ENTRY(IofCompleteRequest, 2)       API_ENTRY(IoDeleteSymbolicLink, 1)
    API_ENTRY(IoDeleteDevice, 1)           API_ENTRY(IoCreateSynchronizationEvent, 2)
    API_ENTRY(IoAllocateIrp, 2)            API_ENTRY(IoFreeIrp, 1)
    API_ENTRY(IoReuseIrp, 2)               API_ENTRY(IoAllocateMdl, 5)
    API_ENTRY(IoFreeMdl, 1)                API_ENTRY(IofCallDriver, 2)
    API_ENTRY(IoSetCompletionRoutineEx, 7) API_ENTRY(IoGetDeviceObjectPointer, 4)
    API_ENTRY(IoGetCurrentProcess, 0)      API_ENTRY(IoWMIRegistrationControl, 2)
    API_ENTRY(IoRegisterBootDriverReinitialization, 3)
    API_ENTRY(IoRegisterShutdownNotification, 1)
    API_ENTRY(IoUnregisterShutdownNotification, 1)
    // Ke (Kernel)
    API_ENTRY(KeInitializeMutex, 2)        API_ENTRY(KeSetEvent, 3)
    API_ENTRY(KeInitializeEvent, 3)        API_ENTRY(KeResetEvent, 1)
    API_ENTRY(KeClearEvent, 1)             API_ENTRY(KeInitializeTimer, 1)
    API_ENTRY(KeSetTimer, 3)               API_ENTRY(KeCancelTimer, 1)
    API_ENTRY(KeDelayExecutionThread, 3)   API_ENTRY(KeWaitForSingleObject, 5)
    API_ENTRY(KeInitializeApc, 8)          API_ENTRY(KeInsertQueueApc, 4)
    API_ENTRY(KeInitializeDpc, 3)          API_ENTRY(KeStackAttachProcess, 2)
    API_ENTRY(KeUnstackDetachProcess, 1)   API_ENTRY(KeQuerySystemTime, 1)
    API_ENTRY(KeAcquireSpinLockRaiseToDpc, 1)
    API_ENTRY(KeEnterCriticalRegion, 0)    API_ENTRY(KeLeaveCriticalRegion, 0)
    // Ps (Process)
    API_ENTRY(PsCreateSystemThread, 7)     API_ENTRY(PsLookupProcessByProcessId, 2)
    API_ENTRY(PsLookupThreadByThreadId, 2) API_ENTRY(PsGetProcessPeb, 1)
    API_ENTRY(PsTerminateSystemThread, 1)  API_ENTRY(PsGetVersion, 4)
    API_ENTRY(PsSetCreateProcessNotifyRoutineEx, 2)
    API_ENTRY(PsSetLoadImageNotifyRoutine, 1)
    API_ENTRY(PsRemoveLoadImageNotifyRoutine, 1)
    API_ENTRY(PsSetCreateThreadNotifyRoutine, 1)
    API_ENTRY(PsRemoveCreateThreadNotifyRoutine, 1)
    // Zw/Nt system calls
    API_ENTRY(ZwQuerySystemInformation, 4) API_ENTRY(ZwProtectVirtualMemory, 5)
    API_ENTRY(ZwWriteVirtualMemory, 5)     API_ENTRY(ZwAllocateVirtualMemory, 6)
    API_ENTRY(ZwOpenEvent, 3)              API_ENTRY(ZwCreateEvent, 5)
    API_ENTRY(ZwDeviceIoControlFile, 10)   API_ENTRY(ZwDeleteKey, 1)
    API_ENTRY(ZwQueryInformationProcess, 5) API_ENTRY(ZwOpenKey, 3)
    API_ENTRY(ZwQueryValueKey, 6)          API_ENTRY(ZwCreateFile, 11)
    API_ENTRY(ZwOpenFile, 6)               API_ENTRY(ZwQueryInformationFile, 5)
    API_ENTRY(ZwWriteFile, 9)              API_ENTRY(ZwReadFile, 9)
    API_ENTRY(ZwCreateSection, 7)          API_ENTRY(ZwUnmapViewOfSection, 2)
    API_ENTRY(ZwMapViewOfSection, 10)      API_ENTRY(ZwGetContextThread, 2)
    API_ENTRY(ZwSetContextThread, 2)       API_ENTRY(NtSetInformationThread, 4)
    // Mm (Memory Management)
    API_ENTRY(MmProbeAndLockPages, 3)
    // Ex (Executive)
    API_ENTRY(ExInitializeResourceLite, 1) API_ENTRY(ExAcquireResourceExclusiveLite, 2)
    API_ENTRY(ExAcquireResourceSharedLite, 2) API_ENTRY(ExReleaseResourceLite, 1)
    API_ENTRY(ExAcquireFastMutex, 1)       API_ENTRY(ExReleaseFastMutex, 1)
    API_ENTRY(ExQueueWorkItem, 2)          API_ENTRY(ExSystemTimeToLocalTime, 2)
    // Security
    API_ENTRY(RtlLengthRequiredSid, 1)     API_ENTRY(RtlInitializeSid, 3)
    API_ENTRY(RtlSubAuthoritySid, 2)       API_ENTRY(RtlCreateAcl, 3)
    API_ENTRY(RtlSetDaclSecurityDescriptor, 4) API_ENTRY(RtlCreateSecurityDescriptor, 2)
    API_ENTRY(RtlAddAccessAllowedAce, 4)
    // Registry
    API_ENTRY(RtlQueryRegistryValuesEx, 5)
    // Timer/Power
    API_ENTRY(PoDeletePowerRequest, 1)
    // Kd
    API_ENTRY(KdDisableDebugger, 0)        API_ENTRY(KdChangeOption, 0)
    // Cm (Configuration Manager)
    API_ENTRY(CmRegisterCallbackEx, 6)     API_ENTRY(CmRegisterCallback, 3)
    API_ENTRY(CmUnRegisterCallback, 1)
    // Etw
    API_ENTRY(EtwRegister, 4)
    // Image
    API_ENTRY(RtlImageDirectoryEntryToData, 4)
    // Compression
    API_ENTRY(RtlGetCompressionWorkSpaceSize, 3) API_ENTRY(RtlDecompressBuffer, 6)
    // Misc
    API_ENTRY(RtlTimeToTimeFields, 2)
    API_ENTRY(_allshl, 2)
    API_LIST_END
public:
    Ntoskrnl();
    std::string get_name() const override { return "ntoskrnl"; }
    const std::vector<ApiEntry>& get_apis() const override { return apis_; }
};

}}} // namespaces
#endif
