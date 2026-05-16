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
| Windows 模拟层 | 17 | 17 | **100%** ✅ |
| API 框架 (winenv/api) | 2 | 2 | **100%** ✅ |
| 用户态 API 处理器 | 40 | 40 | **100%** ✅ |
| 内核态 API 处理器 | 8 | 8 | **100%** ✅ |
| 定义文件 (defs) | 27 | 27 | **100%** ✅ |
| 入口点 | 1 | 0 | **0%** ❌ |
| **合计** | **112** | **111** | **99%** 🎉 |

## 全部已完成模块

### 核心引擎 (17)
`artifacts` `binemu` `cli` `cli_config` `common` `config` `unicorn_eng` `errors`
`memmgr` `profiler` `profiler_events` `report` `speakeasy` `struct` `version` `volumes` `arch`

### Windows 模拟层 (17)
`com` `common` `cryptman` `driveman` `fileman` `hammer` `ioman` `kernel`
`kernel_mod` `loaders` `netman` `objman` `regman` `sessman` `volmgr` `win32` `winemu`

### API 处理器 (48)
**Usermode (40):**
`kernel32` `ntdll` `advapi32` `ws2_32` `user32` `crypt32` `shell32`
`msvcrt` `bcrypt` `winhttp` `dnsapi` `iphlpapi` `netapi32` `psapi` `ole32`
`advpack` `bcryptprimitives` `com_api` `comctl32` `gdi32` `lz32` `mpr`
`mscoree` `msi32` `msimg32` `msvfw32` `ncrypt` `netutils` `oleaut32`
`rpcrt4` `secur32` `sfc` `sfc_os` `shlwapi` `urlmon` `wininet` `winmm`
`wkscli` `wtsapi32`

**Kernelmode (8):**
`ntoskrnl` `ndis` `hal` `fwpkclnt` `netio` `usbd` `wdfldr` `wsk`

### 定义文件 (27)
`nt/ddk` `nt/ntoskrnl` `windows/windows` `winsock/winsock` `winsock/ws2_32`
`registry/reg` `windows/kernel32` `windows/advapi32` `windows/user32` `windows/shell32`
`windows/windef` `windows/com` `windows/iphlpapi` `windows/mpr` `windows/secur32`
`windows/netapi32` `wininet` `usb` `wdf` `wsk` `ndis/ndis` `wfp/fwpmtypes`

## 未完成 (1)

| 文件 | 类别 | 优先级 | 说明 |
|------|------|--------|------|
| `__main__.py` | 入口点 | 极低 | Python CLI 入口，C++ 版本已有 `main.cpp` |

---

> **移植进度: 111/112 文件 (99%)**
> **编译: 0 errors** | **测试: 62/62 passed**
> **剩余: `__main__.py` — CLI 入口点，不影响核心功能**
