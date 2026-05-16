# Speakeasy Porting Progress — Python → C++

> 最后更新: 2026-05-16
> 项目根: D:\Projects\github\speakeasy

## 构建状态

| 指标 | 状态 |
|------|------|
| Linux GCC 编译 | ✅ **0 errors** |
| Windows MSVC 编译 | ✅ **0 errors**（lib + CLI + tests）|
| 单元测试 | ✅ **62/62 passed**（Google Test）|

## 总体完成情况

| 类别 | Python 文件数 | C++ 已移植 | 完成率 |
|------|-------------|-----------|-------|
| 核心引擎 (core) | 17 | 17 | **100%** ✅ |
| Windows 模拟层 | 14 | 14 | **100%** ✅ |
| API 框架 (winenv/api) | 2 | 2 | **100%** ✅ |
| 用户态 API 处理器 | 40 | 7 | **17%** 🔶 |
| 内核态 API 处理器 | 8 | 0 | **0%** ❌ |
| 定义文件 (defs) | 27 | 10 | **37%** 🔶 |
| 入口点 | 1 | 0 | **0%** ❌ |
| **合计** | **109** | **50** | **46%** |

---

## 已完成模块 (C++ 完整移植, 编译通过)

### 核心引擎 (17/17)
| Python | C++ |
|--------|-----|
| `artifacts.py` | `artifacts.cpp/.h` |
| `binemu.py` | `binemu.cpp/.h` |
| `cli.py` | `cli.cpp/.h` |
| `cli_config.py` | `cli_config.cpp/.h` |
| `common.py` | `common.cpp/.h` |
| `config.py` | `config.cpp/.h` |
| `engines/unicorn_eng.py` | `engines/unicorn_eng.cpp/.h` |
| `errors.py` | `errors.h` |
| `memmgr.py` | `memmgr.cpp/.h` |
| `profiler.py` | `profiler.cpp/.h` |
| `profiler_events.py` | `profiler_events.h` (合并入 const.h) |
| `report.py` | `report.h` |
| `speakeasy.py` | `speakeasy.cpp/.h` |
| `struct.py` | `struct.h` |
| `version.py` | `version.h` |
| `volumes.py` | `volumes.cpp/.h` |
| `winenv/arch.py` | `winenv/arch.h` |

### Windows 模拟层 (14/14)
| Python | C++ |
|--------|-----|
| `windows/com.py` | `windows/com.cpp/.h` |
| `windows/common.py` | `windows/common.cpp/.h` |
| `windows/cryptman.py` | `windows/cryptman.cpp/.h` |
| `windows/driveman.py` | `windows/driveman.cpp/.h` |
| `windows/fileman.py` | `windows/fileman.cpp/.h` |
| `windows/hammer.py` | `windows/hammer.cpp/.h` |
| `windows/ioman.py` | `windows/ioman.cpp/.h` |
| `windows/kernel.py` | `windows/kernel.cpp/.h` |
| `windows/kernel_mods/kernel_mod.py` | `windows/kernel_mods/kernel_mod.h` |
| `windows/kernel_mods/volmgr.py` | `windows/kernel_mods/volmgr.cpp/.h` |
| `windows/loaders.py` | `windows/loaders.cpp/.h` |
| `windows/netman.py` | `windows/netman.cpp/.h` |
| `windows/objman.py` | `windows/objman.cpp/.h` |
| `windows/regman.py` | `windows/regman.cpp/.h` |
| `windows/sessman.py` | `windows/sessman.cpp/.h` |
| `windows/win32.py` | `windows/win32.cpp/.h` |
| `windows/winemu.py` | `windows/winemu.cpp/.h` |

### API 框架 (2/2)
| Python | C++ |
|--------|-----|
| `winenv/api/api.py` | `winenv/api/api.cpp/.h` |
| `winenv/api/winapi.py` | `winenv/api/winapi.cpp/.h` |

### 已移植的 API 处理器 (7/40 用户态)
| Python | C++ | 状态 |
|--------|-----|------|
| `kernel32.py` | `kernel32.cpp/.h` | ✅ 含 110+ API STUB 实现 |
| `ntdll.py` | `ntdll.cpp/.h` | ✅ |
| `advapi32.py` | `advapi32.cpp/.h` | ✅ |
| `ws2_32.py` | `ws2_32.cpp/.h` | ✅ |
| `user32.py` | `user32.cpp/.h` | ✅ |
| `crypt32.py` | `crypt32.cpp/.h` | ✅ |
| `shell32.py` | `shell32.cpp/.h` | ✅ |

### Phase A ✅ 已移植的定义文件 (10/27)

| Python | C++ |
|--------|-----|
| `defs/nt/ddk.py` | `defs/nt/ddk.h` |
| `defs/nt/ntoskrnl.py` | `defs/nt/ntoskrnl.h` |
| `defs/windows/windows.py` | `defs/windows/windows.h` |
| `defs/winsock/winsock.py` | `defs/winsock/winsock.h` |
| `defs/winsock/ws2_32.py` | `defs/winsock/ws2_32.h` |
| `defs/registry/reg.py` | `defs/registry/reg.h` |
| `defs/windows/kernel32.py` | `defs/windows/kernel32.h` |
| `defs/windows/advapi32.py` | `defs/windows/advapi32.h` |
| `defs/windows/user32.py` | `defs/windows/user32.h` |
| `defs/windows/shell32.py` | `defs/windows/shell32.h` |

---

## 待移植模块

### Phase A: 用户态 API 处理器 (40 个, 已完成 7 个)

**已有 .py 副本在 secpp/ 中的 (35 个):**

| 模块 | 优先级 | API 数量 | 复杂度 |
|------|--------|---------|-------|
| `advpack` | 低 | 1 | ★ |
| `bcrypt` | 高 | 30+ | ★★★ |
| `com_api` | 中 | COM 调度 | ★★ |
| `dnsapi` | 高 | 10+ | ★★ |
| `gdi32` | 中 | 20+ | ★★ |
| `iphlpapi` | 中 | 5+ | ★ |
| `lz32` | 低 | 3 | ★ |
| `mpr` | 低 | 5 | ★ |
| `mscoree` | 低 | .NET 宿主 | ★★ |
| `msi32` | 低 | 安装 API | ★★ |
| `msimg32` | 低 | 2 | ★ |
| `msvcrt` | 高 | 50+ | ★★★ |
| `ncrypt` | 中 | 10+ | ★★ |
| `netapi32` | 中 | 10+ | ★★ |
| `netutils` | 低 | 3 | ★ |
| `ole32` | 中 | COM | ★★★ |
| `oleaut32` | 中 | COM | ★★★ |
| `rpcrt4` | 中 | RPC | ★★★ |
| `secur32` | 中 | 安全 | ★★ |
| `sfc` | 低 | 2 | ★ |
| `shlwapi` | 中 | 15+ | ★★ |
| `urlmon` | 中 | URL 处理 | ★★ |
| `winhttp` | 高 | 20+ | ★★★ |
| `wininet` | 中 | HTTP/FTP | ★★★ |
| `winmm` | 低 | 多媒体 | ★★ |
| `wkscli` | 低 | 工作站 | ★ |
| `wtsapi32` | 低 | 终端服务 | ★ |

**仅有 Python 源在 speakeasy/ 中的 (5 个):**
| `bcryptprimitives` | 中 | 10+ | ★★ |
| `comctl32` | 中 | 通用控件 | ★ |
| `msvfw32` | 低 | VFW | ★ |
| `psapi` | 中 | 进程状态 | ★ |
| `sfc_os` | 低 | 系统文件 | ★ |

### Phase B: 内核态 API 处理器 (8 个, 全部未移植)

| 模块 | API 数量 | 复杂度 | 说明 |
|------|---------|-------|------|
| `ntoskrnl` | 100+ | ★★★★ | **最大模块**, 内核主 API |
| `ndis` | 50+ | ★★★ | 网络驱动 |
| `hal` | 20+ | ★★ | 硬件抽象 |
| `fwpkclnt` | 20+ | ★★★ | Windows 过滤平台 |
| `netio` | 20+ | ★★★ | 网络 I/O |
| `usbd` | 10+ | ★★ | USB 驱动 |
| `wdfldr` | 5 | ★ | WDF 加载器 |
| `wsk` | 10+ | ★★ | Winsock 内核 |

### Phase C: 定义文件 (27 个, 已完成 3 个)

**高优先级** （阻塞 API 处理器）:
| 文件 | 说明 |
|------|------|
| `defs/winsock/winsock.h` | WinSock 结构 — 阻塞 ws2_32 |
| `defs/winsock/ws2_32.h` | ws2_32 类型 |
| `defs/windows/kernel32.h` | kernel32 结构 |
| `defs/windows/user32.h` | user32 结构 |
| `defs/windows/advapi32.h` | advapi32 结构 |
| `defs/windows/shell32.h` | shell32 结构 |
| `defs/registry/reg.h` | 注册表类型 — 用于 regman |

**中优先级**:
| `defs/ndis/ndis.h`, `defs/wfp/fwpmtypes.h`, `defs/wsk.h` |
| `defs/windows/com.h`, `defs/windows/iphlpapi.h`, `defs/windows/mpr.h` |
| `defs/windows/netapi32.h`, `defs/windows/secur32.h`, `defs/windows/windef.h` |
| `defs/wininet.h`, `defs/usb.h`, `defs/wdf.h` |

### Phase D: 其他 (1 个)
| `__main__.py` | CLI 入口 | 低优先级 |

---

## 移植路线图

```
Phase A: 定义文件 (高优先级 7 个) ─→ Phase B: 重要 API 处理器 (高优先级 8 个)
                                              │
Phase C: 剩余定义文件 (20 个) ←────────────────┘
        │
        └──→ Phase D: 剩余 API 处理器 (25 个)
                                              │
Phase E: 内核态 API 处理器 (8 个) ←────────────┘
```

### 阶段详情

**Phase A: 关键定义文件 (~7 个, 2-3 天)**
- `winsock/winsock.h` — WinSock 结构定义
- `winsock/ws2_32.h` — ws2_32 类型
- `windows/kernel32.h` — kernel32 结构
- `windows/advapi32.h` — advapi32 结构
- `registry/reg.h` — 注册表常量/类型
- `windows/user32.h` — user32 结构
- `windows/shell32.h` — shell32 结构

**Phase B: 高优先级 API 处理器 (~8 个, 3-4 天)**
- `msvcrt` — C 运行时（高频调用）
- `bcrypt` — 加密服务
- `winhttp` — HTTP 通信
- `dnsapi` — DNS 查询
- `iphlpapi` — 网络配置
- `netapi32` — 网络管理
- `psapi` — 进程状态
- `ole32` — COM 基础

**Phase C: 剩余定义文件 (~20 个, 2-3 天)**

**Phase D: 剩余用户态处理器 (~25 个, 5-7 天)**

**Phase E: 内核态处理器 (~8 个, 5-7 天)**
- `ntoskrnl` — 内核主入口（最大模块）

---

> 总计: **~20-25 天** 完成全部移植
> 当前: 43/109 文件 (39%), **62/62 测试通过**
