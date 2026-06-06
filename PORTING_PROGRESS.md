# PORTING PROGRESS — Speakeasy Python → C++ (secpp/)

## 2026-06-05: kPtrSize 运行时修复

修复了 `kPtrSize = sizeof(void*)`（编译期宿主指针大小）与运行时 `ptr_sz = get_ptr_size()`（仿真目标指针大小）不匹配的问题。在 64-bit 宿主上仿真 32-bit PE 时，`kPtrSize == 8` 但 `ptr_sz == 4`，导致：

- 受影响的 `KernelObject` 子类（PEB/TEB/PEB_LDR_DATA/LDR_DATA_TABLE_ENTRY/RTL_USER_PROCESS_PARAMETERS/IDT）的 `object_` 创建了错误的模板类型
- 后续 `static_cast` 类型不匹配 → 未定义行为

**修复方案：** 方案 A（运行时 if/else + 模板体提取）

| 文件 | 变更 |
|------|------|
| `secpp/windows/objman.cpp` | 6 个构造函数 + 4 个简单方法 + 2 个自由函数模板 (`add_module_to_peb_impl`, `populate_runtime_params_impl`) + 显式实例化；移除 `kPtrSize` |
| `secpp/windows/win32.cpp` | `alloc_peb` 中 1 处 if/else 分支；移除未使用的 `kPtrSize` |
| `secpp/winenv/api/usermode/com_api.cpp` | 2 处 if/else 分支（`IWbemServices` + `ComInterface`） |
| `secpp/winenv/api/usermode/netapi32.cpp` | 4 处 if/else 分支（`WKSTA_INFO_100/101/102` + `SERVER_INFO_101`） |
| `tests/test_porting_winemu.cpp` | 4 处 `static_cast` → if/else |
| `tests/smoke_test.cpp` | `kPtrSize` → 显式 `<4>` + `<8>` 双架构测试 |
| `tests/test_porting_ntdefs.cpp` | `kPtrSize` → 显式 `<4>` + `<8>` 双架构测试 |

**零头文件变更**（所有变更在 `.cpp` 文件内）。

---

## Phase: defs 结构体移植 — 基本完成 ✅

### 目录结构

```
secpp/winenv/
  ├── defs/            ← 旧 C++ 头文件（objman.cpp/win32.cpp 仍依赖）
  │   ├── nt/ntoskrnl.h    (speakeasy::defs::nt 命名空间)
  │   ├── nt/ddk.h         (speakeasy::defs::nt 命名空间, IRP_MJ_* 常量等)
  │   ├── windows/*.h      (speakeasy::defs::windows 命名空间)
  │   ├── ndis/ndis.h
  │   ├── registry/reg.h
  │   ├── wfp/fwpmtypes.h
  │   ├── winsock/ws2_32.h
  │   └── ...              (所有 29 个 .py 已删除,
  │                          emu_structs_new.h 已删除,
  │                          windows/wininet.h 已删除)
  ├── deffs/           ← 新 CRTP 头文件（测试 + 已迁移文件使用）
  │   ├── nt/ntoskrnl.h    (speakeasy::defs::new_structs 命名空间)
  │   │   └── 持有: LIST_ENTRY, UNICODE_STRING, STRING, OBJECT_ATTRIBUTES,
  │   │            IO_STATUS_BLOCK, LARGE_INTEGER, KSYSTEM_TIME,
  │   │            SYSTEM_TIMEOFDAY_INFORMATION, DISK_EXTENT,
  │   │            VOLUME_DISK_EXTENTS, NT_TIB, CLIENT_ID, TEB, PEB,
  │   │            ETHREAD, EPROCESS, IRP, DEVICE_OBJECT, DRIVER_OBJECT,
  │   │            FILE_OBJECT, KEVENT, MDL, KAPC, KDPC, KDEVICE_QUEUE,
  │   │            IDT, DESCRIPTOR_TABLE, LDR_DATA_TABLE_ENTRY,
  │   │            PEB_LDR_DATA, RTL_USER_PROCESS_PARAMETERS, + 等
  │   ├── nt/ddk.h         (IRP_MJ_* / STATUS_* 常量)
  │   ├── ndis/ndis.h      (NDIS_OBJECT_HEADER, NET_BUFFER*, 等)
  │   ├── registry/reg.h   (KEY_VALUE_*)
  │   ├── usb.h            (USB_*_DESCRIPTOR, USBD_VERSION_INFORMATION)
  │   ├── wdf.h            (WDF_VERSION, WDF_BIND_INFO, WDFFUNCTIONS, 等)
  │   ├── wsk.h            (WSK_CLIENT/PROVIDER_DISPATCH, 等)
  │   ├── wininet.h        (URL_COMPONENTS)
  │   ├── wfp/fwpmtypes.h  (FWP_*, FWPM_*, FWPS_*)
  │   ├── winsock/ws2_32.h (WSAData, sockaddr_in, hostent, addrinfo)
  │   ├── windows/windef.h (POINT, RECT, MONITORINFO)
  │   ├── windows/windows.h(CONTEXT, CONTEXT64, EXCEPTION_RECORD, GUID, SID, 等)
  │   ├── windows/kernel32.h(FILETIME, PROCESSENTRY32, MEMORY_BASIC_INFORMATION, 等)
  │   ├── windows/user32.h (MSG, WNDCLASSEX, KBDLLHOOKSTRUCT, USEROBJECTFLAGS)
  │   ├── windows/shell32.h(SHELLEXECUTEINFOA)
  │   ├── windows/advapi32.h(SERVICE_TABLE_ENTRY, HCRYPTKEY)
  │   ├── windows/iphlpapi.h(IP_ADAPTER_INFO, IP_ADDR_STRING)
  │   ├── windows/netapi32.h(WKSTA_INFO_100/101/102, SERVER_INFO_101, 常量)
  │   ├── windows/com.h    (IUnknown, IWbemServices, ComInterface)
  │   ├── windows/mpr.h    (ERROR_NO_NETWORK 常量)
  │   ├── windows/secur32.h(占位)
  │   └── winsock/winsock.h(辅助)
  └── struct.h          ← EmuStructHelper<T> CRTP 基类（secpp/ 根目录）
```

### emu_structs_new.h 淘汰

`emu_structs_new.h` 原先定义 14 个共享结构体 + `PointerType<PtrSize>` 辅助模板。已全部分类迁移：

| 结构体 | 迁移目标 | 迁移说明 |
|--------|---------|---------|
| `LIST_ENTRY<PtrSize>` | `deffs/nt/ntoskrnl.h` | 改为显式 `<4>/<8>` 特化 |
| `KSYSTEM_TIME` | `deffs/nt/ntoskrnl.h` | |
| `UNICODE_STRING<PtrSize>` | `deffs/nt/ntoskrnl.h` | |
| `STRING<PtrSize>` | `deffs/nt/ntoskrnl.h` | 继承 `UNICODE_STRING_POD` |
| `OBJECT_ATTRIBUTES<PtrSize>` | `deffs/nt/ntoskrnl.h` | |
| `IO_STATUS_BLOCK<PtrSize>` | `deffs/nt/ntoskrnl.h` | 改为显式 `<4>/<8>` 特化 |
| `LARGE_INTEGER` | `deffs/nt/ntoskrnl.h` | 新增 `LARGE_INTEGER_POD`，拆分为 POD + wrapper |
| `SYSTEM_TIMEOFDAY_INFORMATION` | `deffs/nt/ntoskrnl.h` | |
| `DISK_EXTENT` + `VOLUME_DISK_EXTENTS` | `deffs/nt/ntoskrnl.h` | |
| `NDIS_OBJECT_HEADER` | `deffs/ndis/ndis.h` | |
| `USB_DEVICE_DESCRIPTOR` | `deffs/usb.h` | |
| `KEY_VALUE_PARTIAL_INFORMATION` | `deffs/registry/reg.h` | |
| `WDF_VERSION` | `deffs/wdf.h` | |
| `PointerType<PtrSize>` | **已淘汰** | LIST_ENTRY/IO_STATUS_BLOCK 改为显式特化 |

所有 22 个 `deffs/` 头文件的 include 从 `emu_structs_new.h` 改为直接 `#include "struct.h"`。

### 字段嵌套风格对齐

已验证 deffs 中所有结构体的字段嵌套与 Python `speakeasy/winenv/defs/` 一致：

| 结构体 | 嵌套字段 | 子类型 | 状态 |
|--------|---------|--------|------|
| `TEB` | `NtTib` | `NT_TIB_POD<PtrSize>` | ✅ 已嵌套 |
| `TEB` | `ClientId` | `CLIENT_ID_POD<PtrSize>` | ✅ 已嵌套 |
| `PEB` | `CSDVersion`, `FlsListHead`, `TppWorkerpList` | `UNICODE_STRING_POD`, `LIST_ENTRY_POD` | ✅ 已嵌套 |
| `PEB_LDR_DATA` | `InLoadOrderModuleList`, 等 3 个 | `LIST_ENTRY_POD<PtrSize>` | ✅ 已嵌套 |
| `LDR_DATA_TABLE_ENTRY` | `FullDllName`, `BaseDllName` | `UNICODE_STRING_POD<PtrSize>` | ✅ 已嵌套 |
| `DRIVER_OBJECT` | `DriverName` | `UNICODE_STRING_POD<PtrSize>` | ✅ 已嵌套 |
| `DEVICE_OBJECT` | `Queue`, `DeviceQueue`, `Dpc`, `DeviceLock` | `LIST_ENTRY_POD`, `KDEVICE_QUEUE_POD`, `KDPC_POD`, `KEVENT_POD` | ✅ 已嵌套 |
| `FILE_OBJECT` | `FileName`, `IrpList`, `CurrentByteOffset` | `UNICODE_STRING_POD`, `LIST_ENTRY_POD`, `LARGE_INTEGER_POD` | ✅ 已嵌套 |
| `FILE_STANDARD_INFORMATION` | `AllocationSize`, `EndOfFile` | `LARGE_INTEGER_POD` | ✅ 已嵌套 |
| `IO_STACK_LOCATION` | `Parameters` | `DeviceIoControl_POD<PtrSize>` | ✅ 已嵌套 |
| `WIN32_FIND_DATA` | `ftCreationTime` 等 3 个 | `FILETIME_POD` | ✅ 已嵌套 |
| `WIN32_FILE_ATTRIBUTE_DATA` | `ftCreationTime` 等 3 个 | `FILETIME_POD` | ✅ 已嵌套 |

### 补齐缺失类型到 deffs

从旧 `defs/` 移植到 `deffs/` 的类型：

| 类型 | 目标文件 | 说明 |
|------|---------|------|
| `kNerrSuccess` / `NERR_Success` | `deffs/windows/netapi32.h` | 常量 + 旧名别名 |
| `kNetSetup*` / `NetSetupDomainName` | `deffs/windows/netapi32.h` | 枚举常量 |
| `kErrorNoNetwork` / `ERROR_NO_NETWORK` | `deffs/windows/mpr.h` | + `#pragma push_macro` 防 Windows SDK 冲突 |
| `SERVER_INFO_101<PtrSize>` | `deffs/windows/netapi32.h` | CRTP 结构体 |
| `ComInterface<PtrSize>` | `deffs/windows/com.h` | COM 接口包装器 |
| WKSTA_INFO_100/101/102 字段名 | `deffs/windows/netapi32.h` | `wki101_*` → `wki_*` 统一无后缀命名 |

### 文件迁移状态

| 文件 | 状态 | 迁移内容 | 阻断原因 |
|------|------|---------|---------|
| `api/usermode/mpr.cpp` | ✅ 已迁移 | 常量 `ERROR_NO_NETWORK` | — |
| `api/usermode/netutils.cpp` | ✅ 已迁移 | 常量 `NERR_Success` | — |
| `api/usermode/wkscli.cpp` | ✅ 已迁移 | 常量 `NetSetupDomainName` + `NERR_Success` | — |
| `api/usermode/com_api.cpp` | ✅ 已迁移 | `IWbemServices<sizeof(void*)>` / `ComInterface<sizeof(void*)>` | — |
| `api/usermode/netapi32.cpp` | ✅ 已迁移 | `WKSTA_INFO_10x<sizeof(void*)>` / `SERVER_INFO_101<sizeof(void*)>` | — |
| `windows/win32.cpp` | ❌ 未迁移 | `PEB` 字段访问 | 命名空间 `speakeasy::defs::nt` → `speakeasy::defs::new_structs` + 模板参数 `<sizeof(void*)>` |
| `windows/objman.cpp` | ❌ 未迁移 | `TEB`/`PEB`/`ETHREAD`/`KEVENT`/`IDT` 等 9+ 结构体 | 同上 + 运行时 `ptr_sz` 构造 (`new TEB(ptr_sz)`) 需适配编译期模板参数 |

### 阻断迁移的实际原因

deffs 结构体字段已成嵌套风格（如 `TEB_POD` 已有 `NT_TIB_POD<4> NtTib` 和 `CLIENT_ID_POD<4> ClientId`），与 Python 和旧 defs 一致。实际阻断因素是：

1. **命名空间差异**: `speakeasy::defs::nt::TEB` → `speakeasy::defs::new_structs::TEB<sizeof(void*)>`
2. **模板参数**: 旧 defs 使用运行时 `ptr_sz` 构造 (`new TEB(ptr_sz)`)，deffs 使用编译期模板 (`TEB<4>/TEB<8>`)。适配方案为在 objman.cpp 中使用 `new new_structs::TEB<sizeof(void*)>()` 替代 `new nt::TEB(ptr_sz)`
3. **include 路径**: `defs/nt/ntoskrnl.h` → `deffs/nt/ntoskrnl.h`

以上三项均为机械替换，不涉及字段命名变更。

### 测试状态

```
WinSizeValidation  × 34  (33 pass, IP_ADAPTER_INFO 预存在 708vs704 偏差)
WinSizeAll         × 51  (50 pass, 同上)
EmuStructNewTest   × 14  ✅
OffsetCompare      ×  9  ✅
StructLayoutTest   ×  1  ✅ (排除 PolymorphicStructSerialization 预存在失败)
─────────────────────────
相关测试           108/110 pass ✅
全套测试:          仅 11 个预先存在的失败 (ConfigTest, ObjmanPorting, WindowsEmulator 等)
编译错误:          0
```

### 结构体布局修复记录

在移植过程中发现并修复的 13 个 Windows SDK 长度偏差：

| 结构体 | 修复前 | 修复后 | 根因 |
|--------|--------|--------|------|
| `MEMORY_BASIC_INFORMATION<8>` | 44 | 48 | 缺少尾部 4B 自然对齐 padding |
| `OSVERSIONINFOEX` | 284 | 156 | `szCSDVersion` 用 `uint16_t[128]` 应为 `uint8_t[128]` (ANSI CHAR) |
| `WNDCLASSEX<8>` | 不符 | 修正 | 缺少尾部 4B padding |
| `WSAData<8>` | 400 | 408 | 缺少 `lpVendorInfo` 前 4B 指针对齐 padding |
| `WKSTA_INFO_101<8>` | 44 | 40 | `platform_id`/`ver_major`/`ver_minor` 误用 `uint64_t` (DWORD 应为 `uint32_t`) |
| `WKSTA_INFO_102<8>` | 52 | 48 | 同上 |
| `CLIENT_ID` | 测试预期 8 | 实际 16 (x64) | 测试预期值修正 |
| `CONTEXT` / `CONTEXT64` | — | 204/1144 | 区分 x86/x64 独立检查 |
| `EXCEPTION_RECORD<8>` | 88 | 152 | 布局补齐 (嵌套 union + field reorder) |
| `KBDLLHOOKSTRUCT<8>` | 28 | 24 | 移除不必要的 `pad1` |
| `MODULEENTRY32<8>` | 556 | 568 | `hModule` 是指针应用 `uint64_t` |
| `WIN32_FIND_DATA` | 318 | 320 | 缺少尾部 2B 自然对齐 padding |
| `SID` | 8 | 12 | 缺少最小 `SubAuthority[1]` DWORD |

### 后续步骤

1. **迁移 objman.cpp / win32.cpp** — 将 `defs/nt/` → `deffs/nt/` include 路径、`defs::nt::Type` → `defs::new_structs::Type<sizeof(void*)>` 命名空间、`new TEB(ptr_sz)` → `new TEB<sizeof(void*)>()` 构造方式都改为 deffs 风格
2. **逐步淘汰旧 defs** — 一旦所有生产文件迁移，删除旧 `defs/` 目录
