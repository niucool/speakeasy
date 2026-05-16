# Speakeasy Porting Progress — Python → C++

> 最后更新: 2026-05-16
> 项目根: `/home/jim/projects/speakeasy`
> Python 源: `speakeasy/` → C++ 目标: `secpp/`

## 构建状态

| 指标 | 状态 |
|------|------|
| Linux GCC 编译 | ✅ 0 errors |
| Linux 测试 (CTest) | ✅ 13/13 passed |
| Windows MSVC 兼容 | ✅ 所有 154 个错误已修复 |
| 剩余 TODO (全模块) | **266** |

---

## 完成阶段

| 阶段 | 状态 | 说明 |
|------|------|------|
| Phase 0: 构建基础设施 | ✅ | CMake, vcpkg, smoke test |
| Phase 1: 编译修复 | ✅ | 40+ 处语法/override/类型修正 |
| Phase 2: 核心模块填充 | ✅ | artfacts, config, report, struct, volumes, profiler_events |
| Phase 3: 顶层适配 | ✅ | speakeasy.cpp 49→1 TODO |
| Phase 4: MSVC 兼容 | ✅ | 154 errors → 0 |
| Phase 5: Windows 模块 | 🔶 | 见下方详细 |
| Phase 6: API 处理器 | ❌ | 7/40 已完成 |
| Phase 7: 定义文件 | ❌ | 3/10 已完成 |

---

## 状态图例

| 符号 | 含义 |
|------|------|
| ✅ | 已完成 — 0 TODO, 编译通过 |
| 🔶 | 进行中 — 有 TODO 但核心逻辑就位 |
| ❌ | 未开始 |
| ➖ | 不适用 |

---

## 1. 顶层模块 (`speakeasy/` → `secpp/`)

| Python 源 | C++ 对应 | TODO | 状态 |
|----------|---------|------|------|
| `speakeasy.py` | `speakeasy.h/.cpp` | 1 | ✅ PE 类型检测留待 |
| `binemu.py` | `binemu.h/.cpp` | 2 | ✅ EmuStruct 接口留待 |
| `common.py` | `common.h/.cpp` | 0 | ✅ 全部 Hook 子类就位 |
| `memmgr.py` | `memmgr.h/.cpp` | 0 | ✅ |
| `profiler.py` | `profiler.h/.cpp` | 0 | ✅ |
| `profiler_events.py` | `profiler_events.h` | 0 | ✅ |
| `config.py` | `config.h/.cpp` | 0 | ✅ |
| `cli.py` | `cli.h/.cpp` + `main.cpp` | 0 | ✅ |
| `cli_config.py` | `cli_config.h/.cpp` | 0 | ✅ |
| `errors.py` | `errors.h` | 0 | ✅ |
| `artifacts.py` | `artifacts.h/.cpp` | 2 | ✅ (picosha2) |
| `report.py` | `report.h` | 0 | ✅ |
| `struct.py` | `struct.h` | 0 | ✅ |
| `volumes.py` | `volumes.h/.cpp` | 0 | ✅ |

## 2. 引擎层 (`speakeasy/engines/` → `secpp/engines/`)

| Python 源 | C++ 对应 | TODO | 状态 |
|----------|---------|------|------|
| `unicorn_eng.py` | `unicorn_eng.h/.cpp` | 0 | ✅ |

## 3. Windows 模拟层 (`speakeasy/windows/` → `secpp/windows/`)

| Python 源 | C++ 对应 | TODO | 状态 |
|----------|---------|------|------|
| `winemu.py` | `winemu.h/.cpp` | **0** | ✅ 完整实现, 136/137 方法 |
| `win32.py` | `win32.h/.cpp` | **0** | ✅ 完整实现 |
| `common.py` | `common.h/.cpp` | **2** | ✅ pe-parse 集成, TLS/Rsrc RVA 留待 |
| `kernel.py` | `kernel.h/.cpp` | 9 | 🔶 |
| `loaders.py` | `loaders.h/.cpp` | 0 | ✅ |
| `ioman.py` | `ioman.h/.cpp` | 0 | ✅ |
| `fileman.py` | `fileman.h/.cpp` | **24** | 🔶 文件操作桩 |
| `objman.py` | `objman.h/.cpp` | **39** | 🔶 对象管理桩 |
| `netman.py` | `netman.h/.cpp` | **18** | 🔶 网络操作桩 |
| `regman.py` | `regman.h/.cpp` | 5 | 🔶 |
| `sessman.py` | `sessman.h/.cpp` | 6 | 🔶 |
| `hammer.py` | `hammer.h/.cpp` | 7 | 🔶 |
| `cryptman.py` | `cryptman.h/.cpp` | 0 | ✅ |
| `driveman.py` | `driveman.h/.cpp` | 2 | 🔶 |
| `com.py` | `com.h/.cpp` | 3 | 🔶 |

## 4. Windows 环境定义 (`speakeasy/winenv/` → `secpp/winenv/`)

### 4.1 核心
| Python 源 | C++ 对应 | 状态 |
|----------|---------|------|
| `arch.py` | `arch.h` | ✅ |

### 4.2 API 框架
| Python 源 | C++ 对应 | TODO | 状态 |
|----------|---------|------|------|
| `api.py` | `api.h/.cpp` | **58** | 🔶 大量桩 |
| `winapi.py` | `winapi.h/.cpp` | 9 | 🔶 |

### 4.3 用户态 API — **7/40 ✅, 33 ❌**
| 已移植 | 状态 |
|--------|------|
| kernel32, ntdll, advapi32, ws2_32, user32, crypt32, shell32 | ✅ |
| gdi32, wininet, winhttp, bcrypt, ncrypt, ole32, oleaut32, comctl32, shlwapi, mpr, netapi32, winmm, psapi, msvcrt, rpcrt4, iphlpapi, dnsapi, urlmon, mscoree, secur32, sfc, sfc_os, wtsapi32, advpack, msimg32, msi32, msvfw32, netutils, lz32, com_api, wkscli, bcryptprimitives | ❌ |

### 4.4 内核态 API — **0/8 ❌**
ntoskrnl, hal, ndis, netio, usbd, wdfldr, fwpkclnt

### 4.5 定义文件 — **3/10 ✅**
| 内容 | 状态 |
|------|------|
| `nt/ddk.h` + `nt/ntoskrnl.h` | ✅ NTSTATUS, UNICODE_STRING, IRP |
| `windows/windows.h` | ✅ FILETIME, SYSTEM_INFO |
| ndis, registry, wfp, winsock, usb, wdf, wsk, wininet | ❌ |

---

## TODO 分布总览

| 文件 | TODO | 说明 |
|------|------|------|
| `winenv/api/api.cpp` | 58 | API handler 框架, 注册/分发/内存回调 |
| `windows/objman.cpp` | 39 | 对象管理器桩 |
| `windows/fileman.cpp` | 24 | 文件操作 |
| `windows/netman.cpp` | 18 | 网络操作 |
| `profiler.cpp` | 12 | 事件/报告 |
| `windows/kernel.cpp` | 9 | 内核模拟 |
| `winenv/api/winapi.cpp` | 9 | API 定义 |
| `windows/hammer.cpp` | 7 | 进程注入 |
| `windows/sessman.cpp` | 6 | 会话管理 |
| `windows/regman.cpp` | 5 | 注册表 |
| `windows/com.cpp` | 3 | COM 模拟 |
| `binemu.cpp` | 2 | EmuStruct |
| `windows/common.cpp` | 2 | TLS/资源RVA |
| `windows/driveman.cpp` | 2 | 驱动管理 |
| `speakeasy.cpp` | 1 | PE 类型检测 |
| **总计** | **266** | |

---

## 后续工作优先级

1. **fileman/objman/netman/regman** (86 TODO) — 填充 Windows 管理器实现 (高)
2. **api.cpp/winapi.cpp** (67 TODO) — API 处理器框架 (高)
3. **kernel.cpp** (9 TODO) — 内核模拟器集成 (中)
4. **API 处理器移植** (33 个未开始) — 批量生成模板 (低)
5. **内核 API + 定义文件** (15 个未开始) — 按需移植 (低)

---

> 最后更新: 2026-05-16
> 编译: 0 errors, 13/13 tests passed
