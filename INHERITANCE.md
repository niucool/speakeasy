# Python Class Inheritance Relationships

This document catalogs all class inheritance relationships in the Speakeasy project.

## Base Class Categories

### 1. EmuStruct (struct.py)
Core structure base class for Windows API structures.

| Class | Source File |
|-------|-------------|
| `_DnsRecord` | dnsapi.py |
| `_InterfaceDescriptor` | wdf.py |
| `addrinfo` | ws2_32.py |
| `CLIENT_ID` | ntoskrnl.py |
| `CONTEXT` | windows.py |
| `CONTEXT64` | windows.py |
| `CURDIR` | ntoskrnl.py |
| `DESCRIPTOR_TABLE` | ntoskrnl.py |
| `Descriptor` | wdf.py |
| `DEVICE_OBJECT` | ntoskrnl.py |
| `DeviceIoControl` | ntoskrnl.py |
| `DISK_EXTENT` | volmgr.py |
| `DNS_TXT_DATA` | dnsapi.py |
| `DRIVER_OBJECT` | ntoskrnl.py |
| `EH4_SCOPETABLE` | windows.py |
| `EH4_SCOPETABLE_RECORD` | windows.py |
| `EPROCESS` | ntoskrnl.py |
| `ETHREAD` | ntoskrnl.py |
| `EXCEPTION_POINTERS` | windows.py |
| `EXCEPTION_RECORD` | windows.py |
| `EXCEPTION_REGISTRATION` | windows.py |
| `FILE_OBJECT` | ntoskrnl.py |
| `FILE_STANDARD_INFORMATION` | ntoskrnl.py |
| `FILETIME` | kernel32.py |
| `FLOATING_SAVE_AREA` | windows.py |
| `FWP_BYTE_BLOB` | fwpmtypes.py |
| `FWP_VALUE0` | fwpmtypes.py |
| `FWPM_ACTION0` | fwpmtypes.py |
| `FWPM_CALLOUT0` | fwpmtypes.py |
| `FWPM_DISPLAY_DATA0` | fwpmtypes.py |
| `FWPM_FILTER_CONDITION0` | fwpmtypes.py |
| `FWPM_FILTER0` | fwpmtypes.py |
| `FWPM_SUBLAYER0` | fwpmtypes.py |
| `FWPS_CALLOUT1` | fwpmtypes.py |
| `GUID` | windows.py, fwpmtypes.py |
| `HCRYPTKEY` | advapi32.py |
| `hostent` | ws2_32.py |
| `IDT` | ntoskrnl.py |
| `IMalloc` | com.py |
| `Interface` | wdf.py |
| `InterfaceUrb` | wdf.py |
| `IO_STACK_LOCATION` | ntoskrnl.py |
| `IO_STATUS_BLOCK` | ntoskrnl.py |
| `IP_ADAPTER_INFO` | iphlpapi.py |
| `IP_ADDR_STRING` | iphlpapi.py |
| `IRP` | ntoskrnl.py |
| `IRP_OVERLAY` | ntoskrnl.py |
| `IRP_TAIL` | ntoskrnl.py |
| `IUnknown` | com.py |
| `IWbemContext` | com.py |
| `IWbemLocator` | com.py |
| `IWbemServices` | com.py |
| `KAPC` | ntoskrnl.py |
| `KBDLLHOOKSTRUCT` | user32.py |
| `KDEVICE_QUEUE` | ntoskrnl.py |
| `KDEVICE_QUEUE_ENTRY` | ntoskrnl.py |
| `KDPC` | ntoskrnl.py |
| `KEVENT` | ntoskrnl.py |
| `KEY_VALUE_BASIC_INFORMATION` | reg.py |
| `KEY_VALUE_FULL_INFORMATION` | reg.py |
| `KEY_VALUE_PARTIAL_INFORMATION` | reg.py |
| `KIDTENTRY` | ntoskrnl.py |
| `KIDTENTRY64` | ntoskrnl.py |
| `KSYSTEM_TIME` | ntoskrnl.py, windows.py |
| `LARGE_INTEGER` | ntoskrnl.py |
| `LDR_DATA_TABLE_ENTRY` | ntoskrnl.py |
| `LIST_ENTRY` | ntoskrnl.py |
| `M128A` | windows.py |
| `MDL` | ntoskrnl.py |
| `MEMORY_BASIC_INFORMATION` | kernel32.py |
| `MODULEENTRY32` | kernel32.py |
| `MONITORINFO` | windef.py |
| `MSG` | user32.py |
| `MultiInterface` | wdf.py |
| `MUTANT` | ntoskrnl.py |
| `NDIS_GENERIC_OBJECT` | ndis.py |
| `NDIS_OBJECT_HEADER` | ndis.py |
| `NET_BUFFER` | ndis.py |
| `NET_BUFFER_DATA` | ndis.py |
| `NET_BUFFER_HEADER` | ndis.py |
| `NET_BUFFER_LIST` | ndis.py |
| `NET_BUFFER_LIST_POOL_PARAMETERS` | ndis.py |
| `NT_TIB` | ntoskrnl.py |
| `OBJECT_ATTRIBUTES` | ntoskrnl.py |
| `OSVERSIONINFO` | kernel32.py |
| `OSVERSIONINFOEX` | kernel32.py |
| `PEB` | ntoskrnl.py |
| `PEB_LDR_DATA` | ntoskrnl.py |
| `POINT` | windef.py |
| `PROCESS_INFORMATION` | kernel32.py |
| `PROCESSENTRY32` | kernel32.py |
| `RECT` | windef.py |
| `RTL_OSVERSIONINFOEXW` | ntoskrnl.py |
| `RTL_OSVERSIONINFOW` | ntoskrnl.py |
| `RTL_USER_PROCESS_PARAMETERS` | ntoskrnl.py |
| `SERVICE_TABLE_ENTRY` | advapi32.py |
| `SHELLEXECUTEINFOA` | shell32.py |
| `SID` | windows.py |
| `SingleInterface` | wdf.py |
| `sockaddr` | ws2_32.py |
| `sockaddr_in` | ws2_32.py |
| `SSDT` | ntoskrnl.py |
| `STARTUPINFO` | kernel32.py |
| `STRING` | ntoskrnl.py |
| `SYSTEM_INFO` | kernel32.py |
| `SYSTEM_MODULE` | ntoskrnl.py |
| `SYSTEM_PROCESS_INFORMATION` | ntoskrnl.py |
| `SYSTEM_THREAD_INFORMATION` | ntoskrnl.py |
| `SYSTEM_TIMEOFDAY_INFORMATION` | ntoskrnl.py |
| `SYSTEMTIME` | kernel32.py |
| `TAIL_OVERLAY` | ntoskrnl.py |
| `TEB` | ntoskrnl.py |
| `THREADENTRY32` | kernel32.py |
| `UNICODE_STRING` | ntoskrnl.py, windows.py |
| `Urb` | wdf.py |
| `URL_COMPONENTS` | wininet.py |
| `USB_CONFIGURATION_DESCRIPTOR` | usb.py |
| `USB_DEVICE_DESCRIPTOR` | usb.py |
| `USB_ENDPOINT_DESCRIPTOR` | usb.py |
| `USB_INTERFACE_DESCRIPTOR` | usb.py |
| `USBD_VERSION_INFORMATION` | usb.py |
| `USEROBJECTFLAGS` | user32.py |
| `VOLUME_DISK_EXTENTS` | volmgr.py |
| `WDF_BIND_INFO` | wdf.py |
| `WDF_COMPONENT_GLOBALS` | wdf.py |
| `WDF_DRIVER_CONFIG` | wdf.py |
| `WDF_IO_QUEUE_CONFIG` | wdf.py |
| `WDF_PNPPOWER_EVENT_CALLBACKS` | wdf.py |
| `WDF_TYPED_CONTEXT_WORKER` | wdf.py |
| `WDF_USB_DEVICE_INFORMATION` | wdf.py |
| `WDF_USB_DEVICE_SELECT_CONFIG_PARAMS` | wdf.py |
| `WDF_USB_INTERFACE_SELECT_SETTING_PARAMS` | wdf.py |
| `WDF_USB_PIPE_INFORMATION` | wdf.py |
| `WDF_VERSION` | wdf.py |
| `WDFFUNCTIONS` | wdf.py |
| `WIN32_FILE_ATTRIBUTE_DATA` | kernel32.py |
| `WIN32_FIND_DATA` | kernel32.py |
| `WNDCLASSEX` | user32.py |
| `WSAData` | ws2_32.py |
| `WSK_CLIENT_DISPATCH` | wsk.py |
| `WSK_CLIENT_NPI` | wsk.py |
| `WSK_PROVIDER_BASIC_DISPATCH` | wsk.py |
| `WSK_PROVIDER_DATAGRAM_DISPATCH` | wsk.py |
| `WSK_PROVIDER_DISPATCH` | wsk.py |
| `WSK_PROVIDER_NPI` | wsk.py |
| `WTS_SESSION_INFO` | wtsapi32.py |
| `WKSTA_INFO_100` | netapi32.py |
| `WKSTA_INFO_101` | netapi32.py |
| `WKSTA_INFO_102` | netapi32.py |

### 2. EmuUnion (struct.py)
Union base class.

| Class | Source File |
|-------|-------------|
| `InterfaceTypes` | wdf.py |
| `IO_PARAMETERS` | ntoskrnl.py |
| `Types` | wdf.py |

### 3. ApiHandler (api.py)
Base class for API handlers.

| Class | Source File |
|-------|-------------|
| `AdvApi32` | advapi32.py |
| `Advpack` | advpack.py |
| `Bcrypt` | bcrypt.py |
| `Bcryptprimitives` | bcryptprimitives.py |
| `ComApi` | com_api.py |
| `Comctl32` | comctl32.py |
| `Crypt32` | crypt32.py |
| `DnsApi` | dnsapi.py |
| `Fwpkclnt` | fwpkclnt.py |
| `GDI32` | gdi32.py |
| `Hal` | hal.py |
| `Iphlpapi` | iphlpapi.py |
| `Kernel32` | kernel32.py |
| `Lz32` | lz32.py |
| `Mpr` | mpr.py |
| `Mscoree` | mscoree.py |
| `Msi32` | msi32.py |
| `Msimg32` | msimg32.py |
| `Msvcrt` | msvcrt.py |
| `Msvfw32` | msvfw32.py |
| `Ncrypt` | ncrypt.py |
| `Ndis` | ndis.py |
| `NetApi32` | netapi32.py |
| `NetUtils` | netutils.py |
| `Netio` | netio.py |
| `Ntdll` | ntdll.py |
| `Ntoskrnl` | ntoskrnl.py |
| `Ole32` | ole32.py |
| `OleAut32` | oleaut32.py |
| `Psapi` | psapi.py |
| `Rpcrt4` | rpcrt4.py |
| `Secur32` | secur32.py |
| `sfc` | sfc.py |
| `Shell32` | shell32.py |
| `Shlwapi` | shlwapi.py |
| `Urlmon` | urlmon.py |
| `User32` | user32.py |
| `Usbd` | usbd.py |
| `Wdfldr` | wdfldr.py |
| `WinHttp` | winhttp.py |
| `Wininet` | wininet.py |
| `Winmm` | winmm.py |
| `Wkscli` | wkscli.py |
| `Ws2_32` | ws2_32.py |
| `WtsApi32` | wtsapi32.py |

### 4. Hook (common.py)
Base class for emulation hooks.

| Class | Source File |
|-------|-------------|
| `ApiHook` | common.py |
| `CodeHook` | common.py |
| `DynCodeHook` | common.py |
| `InstructionHook` | common.py |
| `InterruptHook` | common.py |
| `InvalidInstructionHook` | common.py |
| `InvalidMemHook` | common.py |
| `MapMemHook` | common.py |
| `ReadMemHook` | common.py |
| `WriteMemHook` | common.py |

### 5. KernelObject (objman.py)
Base class for kernel objects.

| Class | Source File |
|-------|-------------|
| `Device` | objman.py |
| `Driver` | objman.py |
| `Event` | objman.py |
| `FileObject` | objman.py |
| `IoStackLocation` | objman.py |
| `Irp` | objman.py |
| `LdrDataTableEntry` | objman.py |
| `Mutant` | objman.py |
| `PEB` | objman.py |
| `PebLdrData` | objman.py |
| `Process` | objman.py |
| `RTL_USER_PROCESS_PARAMETERS` | objman.py |
| `TEB` | objman.py |
| `Thread` | objman.py |
| `Token` | objman.py |
| `WskSocket` | netio.py |

### 6. BaseModel (Pydantic)
Configuration and report models.

| Class | Source File |
|-------|-------------|
| `AnalysisConfig` | config.py |
| `ApiHammeringConfig` | config.py |
| `ByteFillConfig` | config.py |
| `DataArtifact` | report.py |
| `DeviceConfig` | config.py |
| `DnsConfig` | config.py |
| `DnsTxtConfig` | config.py |
| `DriveConfig` | config.py |
| `DroppedFile` | report.py |
| `DynamicCodeSegment` | report.py |
| `EntryPoint` | report.py |
| `ErrorInfo` | report.py |
| `Event` | profiler_events.py |
| `ExceptionsConfig` | config.py |
| `FileEntryByExt` | config.py |
| `FileEntryDefault` | config.py |
| `FileEntryFullPath` | config.py |
| `FileManifestEntry` | report.py |
| `FilesystemConfig` | config.py |
| `HttpConfig` | config.py |
| `HttpResponseConfig` | config.py |
| `LoadedModule` | report.py |
| `MemoryAccesses` | report.py |
| `MemoryBlock` | report.py |
| `MemoryLayout` | report.py |
| `MemoryRegion` | report.py |
| `ModuleImageConfig` | config.py |
| `ModuleSegment` | report.py |
| `ModulesConfig` | config.py |
| `NetworkAdapterConfig` | config.py |
| `NetworkConfig` | config.py |
| `OsVersionConfig` | config.py |
| `ProcessConfig` | config.py |
| `ProcessMemoryManifest` | report.py |
| `RegionInfo` | report.py |
| `RegistryConfig` | config.py |
| `RegistryKeyConfig` | config.py |
| `RegistryValueConfig` | config.py |
| `Report` | report.py |
| `SpeakeasyConfig` | config.py |
| `StringCollection` | report.py |
| `StringsReport` | report.py |
| `SymAccessReport` | report.py |
| `SymlinkConfig` | config.py |
| `SystemModuleConfig` | config.py |
| `UserConfig` | config.py |
| `UserModuleConfig` | config.py |
| `WinsockConfig` | config.py |

### 7. SpeakeasyError (errors.py)
Error hierarchy.

| Class | Source File |
|-------|-------------|
| `ApiEmuError` | usbd.py |
| `ConfigError` | config.py |
| `EmuEngineError` | errors.py |
| `EmuException` | errors.py |
| `FileSystemEmuError` | errors.py |
| `KernelEmuError` | errors.py |
| `NetworkEmuError` | errors.py |
| `NotSupportedError` | errors.py |
| `RegistryEmuError` | errors.py |
| `Win32EmuError` | errors.py |
| `WindowsEmuError` | errors.py |

### 8. Event (profiler_events.py)
Profiler event types.

| Class | Source File |
|-------|-------------|
| `ApiEvent` | profiler_events.py |
| `ExceptionEvent` | profiler_events.py |
| `FileCreateEvent` | profiler_events.py |
| `FileOpenEvent` | profiler_events.py |
| `FileReadEvent` | profiler_events.py |
| `FileWriteEvent` | profiler_events.py |
| `MemAllocEvent` | profiler_events.py |
| `MemFreeEvent` | profiler_events.py |
| `MemProtectEvent` | profiler_events.py |
| `MemReadEvent` | profiler_events.py |
| `MemWriteEvent` | profiler_events.py |
| `ModuleLoadEvent` | profiler_events.py |
| `NetDnsEvent` | profiler_events.py |
| `NetHttpEvent` | profiler_events.py |
| `NetTrafficEvent` | profiler_events.py |
| `ProcessCreateEvent` | profiler_events.py |
| `RegCreateKeyEvent` | profiler_events.py |
| `RegListSubkeysEvent` | profiler_events.py |
| `RegOpenKeyEvent` | profiler_events.py |
| `RegReadValueEvent` | profiler_events.py |
| `RegWriteValueEvent` | profiler_events.py |
| `ThreadCreateEvent` | profiler_events.py |
| `ThreadInjectEvent` | profiler_events.py |

### 9. WindowsEmulator (winemu.py)
Emulator hierarchy.

| Class | Source File |
|-------|-------------|
| `Win32Emulator` | win32.py |
| `WinKernelEmulator` | kernel.py |

### 10. BinaryEmulator (binemu.py)
Base emulator class.

| Class | Source File |
|-------|-------------|
| `WindowsEmulator` | winemu.py |

### 11. Other Classes

| Class | Base | Source File |
|-------|------|-------------|
| `_PeParser` | pefile.PE | common.py |
| `CMeta` | type | struct.py |
| `Desktop` | GuiObject | sessman.py |
| `DriverModule` | km.KernelModule | volmgr.py |
| `FilteredStruct` | ct.Structure | struct.py |
| `FilteredStruct` | ct.Union | struct.py |
| `ImageSectionCharacteristics` | IntFlag | common.py |
| `Loader` | Protocol | loaders.py |
| `Pipe` | File | fileman.py |
| `ProfileError` | Exception | profiler.py |
| `Ptr` | metaclass=PtrMeta | struct.py |
| `PtrMeta` | type | struct.py |
| `Session` | GuiObject | sessman.py |
| `sfc_os` | sfc | sfc_os.py |
| `Station` | GuiObject | sessman.py |
| `Window` | GuiObject | sessman.py |
| `WindowClass` | GuiObject | sessman.py |
| `WininetInstance` | WininetComponent | netman.py |
| `WininetRequest` | WininetComponent | netman.py |
| `WininetSession` | WininetComponent | netman.py |
| `WSKSocket` | Socket | netman.py |
| `BootstrapPhase` | IntEnum | winemu.py |

---


Python files without internal dependencies (can be ported first):
File	Notes
speakeasy/common.py	Hook types, hash utils
speakeasy/config.py	Pydantic config models
speakeasy/errors.py	Error classes
speakeasy/profiler_events.py	Event types
speakeasy/struct.py	EmuStruct, EmuUnion
speakeasy/volumes.py	Volume handling
speakeasy/windows/cryptman.py	Crypto manager
speakeasy/windows/kernel_mods/__init__.py	Kernel modules
speakeasy/windows/kernel_mods/kernel_mod.py	Kernel module base
speakeasy/windows/sessman.py	Session manager
speakeasy/winenv/arch.py	Architecture defs
speakeasy/winenv/api/usermode/advpack.py	API handler
speakeasy/winenv/api/usermode/bcryptprimitives.py	API handler
speakeasy/winenv/api/usermode/comctl32.py	API handler
speakeasy/winenv/api/usermode/crypt32.py	API handler
speakeasy/winenv/api/usermode/gdi32.py	API handler
speakeasy/winenv/api/usermode/mscoree.py	API handler
speakeasy/winenv/api/usermode/msimg32.py	API handler
speakeasy/winenv/api/usermode/oleaut32.py	API handler
speakeasy/winenv/api/usermode/psapi.py	API handler
speakeasy/winenv/api/usermode/winmm.py	API handler
speakeasy/winenv/defs/windows/mpr.py	Struct defs
speakeasy/winenv/defs/windows/secur32.py	Struct defs
speakeasy/winenv/defs/winsock/winsock.py	Struct defs

*Generated: 2026-04-03*
