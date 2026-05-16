// ntoskrnl.cpp — Windows NT Kernel handler (STUB, ~154 APIs)
#include "ntoskrnl.h"

namespace speakeasy { namespace api { namespace kernelmode {

Ntoskrnl::Ntoskrnl() {
    INIT_API_TABLE(Ntoskrnl)
    // Object/Reference
    REG(Ntoskrnl, ObfDereferenceObject, 1)        REG(Ntoskrnl, ObfReferenceObject, 1)
    REG(Ntoskrnl, ZwClose, 1)                      REG(Ntoskrnl, ObOpenObjectByPointer, 7)
    REG(Ntoskrnl, ObReferenceObjectByName, 8)      REG(Ntoskrnl, ObReferenceObjectByHandle, 6)
    REG(Ntoskrnl, ObMakeTemporaryObject, 1)        REG(Ntoskrnl, ObGetFilterVersion, 0)
    REG(Ntoskrnl, ObRegisterCallbacks, 2)          REG(Ntoskrnl, ObSetSecurityObjectByPointer, 3)
    // Debug/Print
    REG(Ntoskrnl, DbgPrint, 0)                     REG(Ntoskrnl, DbgPrintEx, 0)
    // String/Format
    REG(Ntoskrnl, _vsnprintf, 4)                   REG(Ntoskrnl, vsprintf_s, 4)
    REG(Ntoskrnl, _snwprintf, 0)                   REG(Ntoskrnl, sprintf, 0)
    REG(Ntoskrnl, _snprintf, 0)
    // Rtl string
    REG(Ntoskrnl, RtlAnsiStringToUnicodeString, 3) REG(Ntoskrnl, RtlInitAnsiString, 2)
    REG(Ntoskrnl, RtlInitUnicodeString, 2)         REG(Ntoskrnl, RtlFreeUnicodeString, 1)
    REG(Ntoskrnl, RtlCopyUnicodeString, 2)         REG(Ntoskrnl, RtlEqualUnicodeString, 3)
    REG(Ntoskrnl, RtlGetVersion, 1)                REG(Ntoskrnl, RtlCompareMemory, 3)
    REG(Ntoskrnl, RtlMoveMemory, 3)
    // Memory/Pool
    REG(Ntoskrnl, ExAllocatePoolWithTag, 3)        REG(Ntoskrnl, ExFreePoolWithTag, 2)
    REG(Ntoskrnl, ExAllocatePool, 2)               REG(Ntoskrnl, ExFreePool, 1)
    REG(Ntoskrnl, FsRtlAllocatePool, 2)            REG(Ntoskrnl, RtlAllocateHeap, 3)
    REG(Ntoskrnl, RtlFreeHeap, 3)                  REG(Ntoskrnl, MmAllocateContiguousMemory, 2)
    REG(Ntoskrnl, MmFreeContiguousMemory, 1)       REG(Ntoskrnl, MmIsAddressValid, 1)
    REG(Ntoskrnl, MmMapLockedPagesSpecifyCache, 6) REG(Ntoskrnl, MmUnlockPages, 1)
    REG(Ntoskrnl, MmGetSystemRoutineAddress, 1)    REG(Ntoskrnl, MmIsDriverVerifying, 1)
    // memcpy/memset/etc
    REG(Ntoskrnl, memmove, 3)                      REG(Ntoskrnl, memcpy, 3)
    REG(Ntoskrnl, memset, 3)
    // Wide char string
    REG(Ntoskrnl, wcscpy, 2)                       REG(Ntoskrnl, wcsncpy, 3)
    REG(Ntoskrnl, wcslen, 1)                       REG(Ntoskrnl, wcschr, 2)
    REG(Ntoskrnl, wcscat, 2)                       REG(Ntoskrnl, wcsnlen, 2)
    REG(Ntoskrnl, strrchr, 2)                      REG(Ntoskrnl, strchr, 2)
    REG(Ntoskrnl, _wcsnicmp, 3)                    REG(Ntoskrnl, _stricmp, 2)
    REG(Ntoskrnl, _wcsicmp, 2)                     REG(Ntoskrnl, mbstowcs, 3)
    // I/O
    REG(Ntoskrnl, IoDeleteDriver, 1)               REG(Ntoskrnl, IoCreateDevice, 7)
    REG(Ntoskrnl, IoCreateDeviceSecure, 9)         REG(Ntoskrnl, IoCreateSymbolicLink, 2)
    REG(Ntoskrnl, IofCompleteRequest, 2)           REG(Ntoskrnl, IoDeleteSymbolicLink, 1)
    REG(Ntoskrnl, IoDeleteDevice, 1)               REG(Ntoskrnl, IoCreateSynchronizationEvent, 2)
    REG(Ntoskrnl, IoAllocateIrp, 2)                REG(Ntoskrnl, IoFreeIrp, 1)
    REG(Ntoskrnl, IoReuseIrp, 2)                   REG(Ntoskrnl, IoAllocateMdl, 5)
    REG(Ntoskrnl, IoFreeMdl, 1)                    REG(Ntoskrnl, IofCallDriver, 2)
    REG(Ntoskrnl, IoSetCompletionRoutineEx, 7)     REG(Ntoskrnl, IoGetDeviceObjectPointer, 4)
    REG(Ntoskrnl, IoGetCurrentProcess, 0)          REG(Ntoskrnl, IoWMIRegistrationControl, 2)
    REG(Ntoskrnl, IoRegisterBootDriverReinitialization, 3)
    REG(Ntoskrnl, IoRegisterShutdownNotification, 1)
    REG(Ntoskrnl, IoUnregisterShutdownNotification, 1)
    // Ke (Kernel)
    REG(Ntoskrnl, KeInitializeMutex, 2)            REG(Ntoskrnl, KeSetEvent, 3)
    REG(Ntoskrnl, KeInitializeEvent, 3)            REG(Ntoskrnl, KeResetEvent, 1)
    REG(Ntoskrnl, KeClearEvent, 1)                 REG(Ntoskrnl, KeInitializeTimer, 1)
    REG(Ntoskrnl, KeSetTimer, 3)                   REG(Ntoskrnl, KeCancelTimer, 1)
    REG(Ntoskrnl, KeDelayExecutionThread, 3)       REG(Ntoskrnl, KeWaitForSingleObject, 5)
    REG(Ntoskrnl, KeInitializeApc, 8)              REG(Ntoskrnl, KeInsertQueueApc, 4)
    REG(Ntoskrnl, KeInitializeDpc, 3)              REG(Ntoskrnl, KeStackAttachProcess, 2)
    REG(Ntoskrnl, KeUnstackDetachProcess, 1)       REG(Ntoskrnl, KeQuerySystemTime, 1)
    REG(Ntoskrnl, KeAcquireSpinLockRaiseToDpc, 1)
    REG(Ntoskrnl, KeEnterCriticalRegion, 0)        REG(Ntoskrnl, KeLeaveCriticalRegion, 0)
    // Ps (Process)
    REG(Ntoskrnl, PsCreateSystemThread, 7)         REG(Ntoskrnl, PsLookupProcessByProcessId, 2)
    REG(Ntoskrnl, PsLookupThreadByThreadId, 2)     REG(Ntoskrnl, PsGetProcessPeb, 1)
    REG(Ntoskrnl, PsTerminateSystemThread, 1)      REG(Ntoskrnl, PsGetVersion, 4)
    REG(Ntoskrnl, PsSetCreateProcessNotifyRoutineEx, 2)
    REG(Ntoskrnl, PsSetLoadImageNotifyRoutine, 1)
    REG(Ntoskrnl, PsRemoveLoadImageNotifyRoutine, 1)
    REG(Ntoskrnl, PsSetCreateThreadNotifyRoutine, 1)
    REG(Ntoskrnl, PsRemoveCreateThreadNotifyRoutine, 1)
    // Zw/Nt system calls
    REG(Ntoskrnl, ZwQuerySystemInformation, 4)     REG(Ntoskrnl, ZwProtectVirtualMemory, 5)
    REG(Ntoskrnl, ZwWriteVirtualMemory, 5)         REG(Ntoskrnl, ZwAllocateVirtualMemory, 6)
    REG(Ntoskrnl, ZwOpenEvent, 3)                  REG(Ntoskrnl, ZwCreateEvent, 5)
    REG(Ntoskrnl, ZwDeviceIoControlFile, 10)       REG(Ntoskrnl, ZwDeleteKey, 1)
    REG(Ntoskrnl, ZwQueryInformationProcess, 5)    REG(Ntoskrnl, ZwOpenKey, 3)
    REG(Ntoskrnl, ZwQueryValueKey, 6)              REG(Ntoskrnl, ZwCreateFile, 11)
    REG(Ntoskrnl, ZwOpenFile, 6)                   REG(Ntoskrnl, ZwQueryInformationFile, 5)
    REG(Ntoskrnl, ZwWriteFile, 9)                  REG(Ntoskrnl, ZwReadFile, 9)
    REG(Ntoskrnl, ZwCreateSection, 7)              REG(Ntoskrnl, ZwUnmapViewOfSection, 2)
    REG(Ntoskrnl, ZwMapViewOfSection, 10)          REG(Ntoskrnl, ZwGetContextThread, 2)
    REG(Ntoskrnl, ZwSetContextThread, 2)           REG(Ntoskrnl, NtSetInformationThread, 4)
    // Mm (Memory Management)
    REG(Ntoskrnl, MmProbeAndLockPages, 3)
    // Ex (Executive)
    REG(Ntoskrnl, ExInitializeResourceLite, 1)     REG(Ntoskrnl, ExAcquireResourceExclusiveLite, 2)
    REG(Ntoskrnl, ExAcquireResourceSharedLite, 2)  REG(Ntoskrnl, ExReleaseResourceLite, 1)
    REG(Ntoskrnl, ExAcquireFastMutex, 1)           REG(Ntoskrnl, ExReleaseFastMutex, 1)
    REG(Ntoskrnl, ExQueueWorkItem, 2)              REG(Ntoskrnl, ExSystemTimeToLocalTime, 2)
    // Security
    REG(Ntoskrnl, RtlLengthRequiredSid, 1)         REG(Ntoskrnl, RtlInitializeSid, 3)
    REG(Ntoskrnl, RtlSubAuthoritySid, 2)           REG(Ntoskrnl, RtlCreateAcl, 3)
    REG(Ntoskrnl, RtlSetDaclSecurityDescriptor, 4) REG(Ntoskrnl, RtlCreateSecurityDescriptor, 2)
    REG(Ntoskrnl, RtlAddAccessAllowedAce, 4)
    // Registry
    REG(Ntoskrnl, RtlQueryRegistryValuesEx, 5)
    // Timer/Power
    REG(Ntoskrnl, PoDeletePowerRequest, 1)
    // Kd
    REG(Ntoskrnl, KdDisableDebugger, 0)            REG(Ntoskrnl, KdChangeOption, 0)
    // Cm (Configuration Manager)
    REG(Ntoskrnl, CmRegisterCallbackEx, 6)         REG(Ntoskrnl, CmRegisterCallback, 3)
    REG(Ntoskrnl, CmUnRegisterCallback, 1)
    // Etw
    REG(Ntoskrnl, EtwRegister, 4)
    // Image
    REG(Ntoskrnl, RtlImageDirectoryEntryToData, 4)
    // Compression
    REG(Ntoskrnl, RtlGetCompressionWorkSpaceSize, 3) REG(Ntoskrnl, RtlDecompressBuffer, 6)
    // Misc
    REG(Ntoskrnl, RtlTimeToTimeFields, 2)
    REG(Ntoskrnl, _allshl, 2)
    END_API_TABLE
}

#define NK_STUB(n) KERNEL_STUB(Ntoskrnl, n)

// Object/Reference
NK_STUB(ObfDereferenceObject)     NK_STUB(ObfReferenceObject)
NK_STUB(ZwClose)                   NK_STUB(ObOpenObjectByPointer)
NK_STUB(ObReferenceObjectByName)  NK_STUB(ObReferenceObjectByHandle)
NK_STUB(ObMakeTemporaryObject)    NK_STUB(ObGetFilterVersion)
NK_STUB(ObRegisterCallbacks)      NK_STUB(ObSetSecurityObjectByPointer)
// Debug/Print
NK_STUB(DbgPrint)                  NK_STUB(DbgPrintEx)
// String/Format
NK_STUB(_vsnprintf)               NK_STUB(vsprintf_s)
NK_STUB(_snwprintf)               NK_STUB(sprintf)
NK_STUB(_snprintf)
// Rtl string
NK_STUB(RtlAnsiStringToUnicodeString) NK_STUB(RtlInitAnsiString)
NK_STUB(RtlInitUnicodeString)     NK_STUB(RtlFreeUnicodeString)
NK_STUB(RtlCopyUnicodeString)     NK_STUB(RtlEqualUnicodeString)
NK_STUB(RtlGetVersion)            NK_STUB(RtlCompareMemory)
NK_STUB(RtlMoveMemory)
// Memory/Pool
NK_STUB(ExAllocatePoolWithTag)    NK_STUB(ExFreePoolWithTag)
NK_STUB(ExAllocatePool)           NK_STUB(ExFreePool)
NK_STUB(FsRtlAllocatePool)        NK_STUB(RtlAllocateHeap)
NK_STUB(RtlFreeHeap)              NK_STUB(MmAllocateContiguousMemory)
NK_STUB(MmFreeContiguousMemory)   NK_STUB(MmIsAddressValid)
NK_STUB(MmMapLockedPagesSpecifyCache) NK_STUB(MmUnlockPages)
NK_STUB(MmGetSystemRoutineAddress) NK_STUB(MmIsDriverVerifying)
// memcpy/memset
NK_STUB(memmove)                  NK_STUB(memcpy)
NK_STUB(memset)
// Wide char
NK_STUB(wcscpy)                   NK_STUB(wcsncpy)
NK_STUB(wcslen)                   NK_STUB(wcschr)
NK_STUB(wcscat)                   NK_STUB(wcsnlen)
NK_STUB(strrchr)                  NK_STUB(strchr)
NK_STUB(_wcsnicmp)                NK_STUB(_stricmp)
NK_STUB(_wcsicmp)                 NK_STUB(mbstowcs)
// I/O
NK_STUB(IoDeleteDriver)           NK_STUB(IoCreateDevice)
NK_STUB(IoCreateDeviceSecure)     NK_STUB(IoCreateSymbolicLink)
NK_STUB(IofCompleteRequest)       NK_STUB(IoDeleteSymbolicLink)
NK_STUB(IoDeleteDevice)           NK_STUB(IoCreateSynchronizationEvent)
NK_STUB(IoAllocateIrp)            NK_STUB(IoFreeIrp)
NK_STUB(IoReuseIrp)               NK_STUB(IoAllocateMdl)
NK_STUB(IoFreeMdl)                NK_STUB(IofCallDriver)
NK_STUB(IoSetCompletionRoutineEx) NK_STUB(IoGetDeviceObjectPointer)
NK_STUB(IoGetCurrentProcess)      NK_STUB(IoWMIRegistrationControl)
NK_STUB(IoRegisterBootDriverReinitialization)
NK_STUB(IoRegisterShutdownNotification)
NK_STUB(IoUnregisterShutdownNotification)
// Ke (Kernel)
NK_STUB(KeInitializeMutex)        NK_STUB(KeSetEvent)
NK_STUB(KeInitializeEvent)        NK_STUB(KeResetEvent)
NK_STUB(KeClearEvent)             NK_STUB(KeInitializeTimer)
NK_STUB(KeSetTimer)               NK_STUB(KeCancelTimer)
NK_STUB(KeDelayExecutionThread)   NK_STUB(KeWaitForSingleObject)
NK_STUB(KeInitializeApc)          NK_STUB(KeInsertQueueApc)
NK_STUB(KeInitializeDpc)          NK_STUB(KeStackAttachProcess)
NK_STUB(KeUnstackDetachProcess)   NK_STUB(KeQuerySystemTime)
NK_STUB(KeAcquireSpinLockRaiseToDpc)
NK_STUB(KeEnterCriticalRegion)    NK_STUB(KeLeaveCriticalRegion)
// Ps
NK_STUB(PsCreateSystemThread)     NK_STUB(PsLookupProcessByProcessId)
NK_STUB(PsLookupThreadByThreadId) NK_STUB(PsGetProcessPeb)
NK_STUB(PsTerminateSystemThread)  NK_STUB(PsGetVersion)
NK_STUB(PsSetCreateProcessNotifyRoutineEx)
NK_STUB(PsSetLoadImageNotifyRoutine)
NK_STUB(PsRemoveLoadImageNotifyRoutine)
NK_STUB(PsSetCreateThreadNotifyRoutine)
NK_STUB(PsRemoveCreateThreadNotifyRoutine)
// Zw/Nt
NK_STUB(ZwQuerySystemInformation) NK_STUB(ZwProtectVirtualMemory)
NK_STUB(ZwWriteVirtualMemory)     NK_STUB(ZwAllocateVirtualMemory)
NK_STUB(ZwOpenEvent)              NK_STUB(ZwCreateEvent)
NK_STUB(ZwDeviceIoControlFile)    NK_STUB(ZwDeleteKey)
NK_STUB(ZwQueryInformationProcess) NK_STUB(ZwOpenKey)
NK_STUB(ZwQueryValueKey)          NK_STUB(ZwCreateFile)
NK_STUB(ZwOpenFile)               NK_STUB(ZwQueryInformationFile)
NK_STUB(ZwWriteFile)              NK_STUB(ZwReadFile)
NK_STUB(ZwCreateSection)          NK_STUB(ZwUnmapViewOfSection)
NK_STUB(ZwMapViewOfSection)       NK_STUB(ZwGetContextThread)
NK_STUB(ZwSetContextThread)       NK_STUB(NtSetInformationThread)
// Mm
NK_STUB(MmProbeAndLockPages)
// Ex
NK_STUB(ExInitializeResourceLite) NK_STUB(ExAcquireResourceExclusiveLite)
NK_STUB(ExAcquireResourceSharedLite) NK_STUB(ExReleaseResourceLite)
NK_STUB(ExAcquireFastMutex)       NK_STUB(ExReleaseFastMutex)
NK_STUB(ExQueueWorkItem)          NK_STUB(ExSystemTimeToLocalTime)
// Security
NK_STUB(RtlLengthRequiredSid)     NK_STUB(RtlInitializeSid)
NK_STUB(RtlSubAuthoritySid)       NK_STUB(RtlCreateAcl)
NK_STUB(RtlSetDaclSecurityDescriptor) NK_STUB(RtlCreateSecurityDescriptor)
NK_STUB(RtlAddAccessAllowedAce)
// Registry
NK_STUB(RtlQueryRegistryValuesEx)
// Timer/Power
NK_STUB(PoDeletePowerRequest)
// Kd
NK_STUB(KdDisableDebugger)        NK_STUB(KdChangeOption)
// Cm
NK_STUB(CmRegisterCallbackEx)     NK_STUB(CmRegisterCallback)
NK_STUB(CmUnRegisterCallback)
// Etw
NK_STUB(EtwRegister)
// Image
NK_STUB(RtlImageDirectoryEntryToData)
// Compression
NK_STUB(RtlGetCompressionWorkSpaceSize) NK_STUB(RtlDecompressBuffer)
// Misc
NK_STUB(RtlTimeToTimeFields)      NK_STUB(_allshl)

}}} // namespaces
