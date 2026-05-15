# Speakeasy Porting Progress — Python → C++

> 最后更新: 2026-05-15
> 项目根: `/home/jim/projects/speakeasy`
> Python 源: `speakeasy/` → C++ 目标: `secpp/`

## Phase 0 — 构建基础设施 ✅ 完成

| 交付物 | 文件 | 状态 |
|--------|------|------|
| CMake 构建配置 | `CMakeLists.txt` | ✅ C++17, vcpkg 集成, 跨平台标志 |
| Smoke test | `tests/smoke_test.cpp` | ✅ 4 库全部验证通过 |
| Porting 计划 | `PORTING_PLAN.md` | ✅ 7 阶段, 14-20 周预估 |
| 依赖安装 | vcpkg | ✅ nlohmann-json 3.12, plog 1.1.11, unicorn 2.1.4, pe-parse |
| CMake 配置 | `cmake -B build` | ✅ 通过 |
| CTest | `ctest` | ✅ 1/1 Passed |

**当前阶段: Phase 2 — 配置与结构体** (实现缺失核心模块)

### Phase 1 进展 — 编译修复

| 类别 | 修复数 | 说明 |
|------|--------|------|
| include 路径修复 | 6 处 | `binemu.h`, `profiler.h`, `unicorn_eng.h` 等 |
| C++ 语法错误 | 3 处 | `WILDCARD_FLAG`, `sizeof` 关键字, `reg_read` 参数 |
| virtual/override 不匹配 | 12 处 | PeFile, KernelObject, File, WindowsEmulator 等 |
| private/protected 访问 | 8 处 | MemMap, FileMap, KernelObject, GuiObject 等 |
| 类型/构造函数 | 5 处 | 初始化列表, tuple 元素, Thread/Token 默认构造 |
| enable_shared_from_this | 2 处 | WininetSession, WininetInstance |

**编译状态**: 15/20 个 `.cpp` 文件通过编译，34 个剩余错误集中在 `win32.cpp`（基类前向声明问题，Phase 4 解决）

---

## 状态图例

| 符号 | 含义 |
|------|------|
| ✅ | 已完成 — 实现完整、无 TODO/stub |
| 🔶 | 进行中 / 部分实现 — 框架存在但含 TODO 或占位代码 |
| ❌ | 未开始 — 尚无 C++ 对应文件 |
| ➖ | 不适用 — 无需移植（如 `__init__.py`） |

---

## 1. 顶层模块 (`speakeasy/` → `secpp/`)

| Python 源文件 | C++ 对应文件 | 状态 | 备注 |
|--------------|-------------|------|------|
| `speakeasy.py` | `speakeasy.h` / `speakeasy.cpp` | 🔶 | API 接口完整 (372+666 行)，但 `_init_emulator` 等核心方法含 TODO |
| `binemu.py` | `binemu.h` / `binemu.cpp` | 🔶 | 类框架完整 (216+337 行)，部分引擎方法含占位 |
| `common.py` | `common.h` / `common.cpp` | 🔶 | Hook 体系定义完整 (312+335 行)，回调包装器有占位 |
| `memmgr.py` | `memmgr.h` / `memmgr.cpp` | 🔶 | MemMap + MemoryManager 类完整 (240+511 行)，底层引擎交互有占位 |
| `profiler.py` | `profiler.h` / `profiler.cpp` | 🔶 | Run/Profiler 类定义 (201+206 行)，JSON 输出含 TODO |
| `profiler_events.py` | `profiler_events.h` | ✅ | 事件类型常量 + 23 个 event struct，含 JSON 序列化 |
| `config.py` | `config.h` / `config.cpp` | ✅ | EmuConfig 结构体 + JSON 加载/验证 |
| `cli.py` | — | ❌ | CLI 入口，待移植 |
| `cli_config.py` | — | ❌ | CLI 配置辅助，待移植 |
| `errors.py` | `errors.h` | ✅ | 完整异常类层次结构 |
| `version.py` | `version.h` | ✅ | 版本常量 (`1.6.1`) |
| `artifacts.py` | — | ❌ | 产物存储，待移植 |
| `report.py` | — | ❌ | 报告生成，待移植 |
| `struct.py` | `struct.h` | ✅ | EmuStruct 基类 + EmuEnum + EmuPtr + 字节读写辅助 |
| `volumes.py` | — | ❌ | 卷挂载，待移植 |
| — | `const.h` | ✅ | 日志常量 (PROC_CREATE 等)，C++ 新增 |
| `__init__.py` | — | ➖ | |
| `__main__.py` | — | ➖ | 由 `main()` 替代 |
| `py.typed` | — | ➖ | |

---

## 2. 引擎层 (`speakeasy/engines/` → `secpp/engines/`)

| Python 源文件 | C++ 对应文件 | 状态 | 备注 |
|--------------|-------------|------|------|
| `unicorn_eng.py` | `unicorn_eng.h` / `unicorn_eng.cpp` | 🔶 | Unicorn 引擎封装，含 ToggleableHook 等 |
| `__init__.py` | — | ➖ | |

---

## 3. Windows 模拟层 (`speakeasy/windows/` → `secpp/windows/`)

| Python 源文件 | C++ 对应文件 | 状态 | 备注 |
|--------------|-------------|------|------|
| `winemu.py` | `winemu.h` / `winemu.cpp` | 🔶 | 主 Windows 模拟器，323 行头文件 |
| `win32.py` | `win32.h` / `win32.cpp` | 🔶 | Win32 用户态模拟器 |
| `com.py` | `com.h` / `com.cpp` | 🔶 | COM 模拟 |
| `common.py` | `common.h` / `common.cpp` | 🔶 | Windows 通用工具 |
| `cryptman.py` | `cryptman.h` / `cryptman.cpp` | 🔶 | 加密管理器 |
| `driveman.py` | `driveman.h` / `driveman.cpp` | 🔶 | 驱动管理器 |
| `fileman.py` | `fileman.h` / `fileman.cpp` | 🔶 | 文件系统管理器 (178 行头文件) |
| `hammer.py` | `hammer.h` / `hammer.cpp` | 🔶 | 进程注入/挖空 |
| `netman.py` | `netman.h` / `netman.cpp` | 🔶 | 网络管理器 |
| `objman.py` | `objman.h` / `objman.cpp` | 🔶 | 对象管理器 |
| `regman.py` | `regman.h` / `regman.cpp` | 🔶 | 注册表管理器 |
| `sessman.py` | `sessman.h` / `sessman.cpp` | 🔶 | 会话管理器 |
| `kernel.py` | — | ❌ | **内核模拟器入口，尚未移植** |
| `loaders.py` | — | ❌ | **PE 加载器，尚未移植** |
| `ioman.py` | — | ❌ | **I/O 管理器，尚未移植** |
| `kernel_mods/__init__.py` | — | ❌ | |
| `kernel_mods/kernel_mod.py` | — | ❌ | **内核模块基类，尚未移植** |
| `kernel_mods/volmgr.py` | — | ❌ | **卷管理器内核模块，尚未移植** |
| `__init__.py` | — | ➖ | |

---

## 4. Windows 环境定义 (`speakeasy/winenv/` → `secpp/winenv/`)

### 4.1 核心

| Python 源文件 | C++ 对应文件 | 状态 | 备注 |
|--------------|-------------|------|------|
| `arch.py` | `arch.h` | ✅ | 架构常量、寄存器定义完整 (128 行) |
| `__init__.py` | — | ➖ | |

### 4.2 API 框架 (`winenv/api/`)

| Python 源文件 | C++ 对应文件 | 状态 | 备注 |
|--------------|-------------|------|------|
| `api.py` | `api.h` / `api.cpp` | 🔶 | API hook 框架 (175 行头文件) |
| `winapi.py` | `winapi.h` / `winapi.cpp` | 🔶 | Windows API 定义 |
| — | `api_handler_registry.h` | 🔶 | Handler 注册表 (C++ 新增模式) |
| `__init__.py` | — | ➖ | |

### 4.3 用户态 API 处理器 (`winenv/api/usermode/`) — **40 个文件，全部未移植**

| Python 源文件 | C++ 对应文件 | 状态 | 备注 |
|--------------|-------------|------|------|
| `kernel32.py` | — | ❌ | 核心 kernel32 API 处理器 |
| `ntdll.py` | — | ❌ | ntdll API 处理器 |
| `advapi32.py` | — | ❌ | |
| `shell32.py` | — | ❌ | |
| `user32.py` | — | ❌ | |
| `gdi32.py` | — | ❌ | |
| `ws2_32.py` | — | ❌ | Winsock |
| `wininet.py` | — | ❌ | |
| `winhttp.py` | — | ❌ | |
| `crypt32.py` | — | ❌ | |
| `bcrypt.py` | — | ❌ | |
| `ncrypt.py` | — | ❌ | |
| `bcryptprimitives.py` | — | ❌ | |
| `ole32.py` | — | ❌ | |
| `oleaut32.py` | — | ❌ | |
| `comctl32.py` | — | ❌ | |
| `shlwapi.py` | — | ❌ | |
| `mpr.py` | — | ❌ | |
| `netapi32.py` | — | ❌ | |
| `winmm.py` | — | ❌ | |
| `psapi.py` | — | ❌ | |
| `msvcrt.py` | — | ❌ | |
| `rpcrt4.py` | — | ❌ | |
| `iphlpapi.py` | — | ❌ | |
| `dnsapi.py` | — | ❌ | |
| `urlmon.py` | — | ❌ | |
| `mscoree.py` | — | ❌ | |
| `secur32.py` | — | ❌ | |
| `sfc.py` | — | ❌ | |
| `sfc_os.py` | — | ❌ | |
| `wtsapi32.py` | — | ❌ | |
| `advpack.py` | — | ❌ | |
| `msimg32.py` | — | ❌ | |
| `msi32.py` | — | ❌ | |
| `msvfw32.py` | — | ❌ | |
| `netutils.py` | — | ❌ | |
| `lz32.py` | — | ❌ | |
| `com_api.py` | — | ❌ | |
| `wkscli.py` | — | ❌ | |
| `__init__.py` | — | ➖ | |

### 4.4 内核态 API 处理器 (`winenv/api/kernelmode/`) — **全部未移植**

| Python 源文件 | C++ 对应文件 | 状态 | 备注 |
|--------------|-------------|------|------|
| `ntoskrnl.py` | — | ❌ | **核心内核 API 处理器** |
| `hal.py` | — | ❌ | |
| `ndis.py` | — | ❌ | |
| `netio.py` | — | ❌ | |
| `usbd.py` | — | ❌ | |
| `wdfldr.py` | — | ❌ | |
| `fwpkclnt.py` | — | ❌ | |
| `__init__.py` | — | ➖ | |

### 4.5 定义文件 (`winenv/defs/`)

| Python 源目录/文件 | C++ 对应 | 状态 | 备注 |
|-------------------|---------|------|------|
| `__init__.py` | 仍为 Python | ❌ | |
| `ndis/` | 仍为 Python | ❌ | NDIS 定义 |
| `nt/` | 仍为 Python | ❌ | NT 内核定义 |
| `registry/` | 仍为 Python | ❌ | 注册表定义 |
| `wfp/` | 仍为 Python | ❌ | WFP 定义 |
| `windows/` | 仍为 Python | ❌ | Windows 通用定义 |
| `winsock/` | 仍为 Python | ❌ | Winsock 定义 |
| `usb.py` | 仍为 Python | ❌ | |
| `wdf.py` | 仍为 Python | ❌ | |
| `wsk.py` | 仍为 Python | ❌ | |
| `wininet.py` | 仍为 Python | ❌ | |

> **注意**: `secpp/winenv/defs/` 目录目前是 Python 文件的副本。这些定义文件包含大量结构体/常量定义，需要评估是直接移植为 C++ 头文件还是作为数据沿用。

### 4.6 Decoys (`winenv/decoys/`)

| 内容 | 状态 | 备注 |
|------|------|------|
| `amd64/manifest.json`, `default_*.exe/sys` | ✅ | 二进制数据已镜像 |
| `x86/` (空或类似) | ✅ | 已镜像 |

---

## 5. 资源文件 (`resources/`)

| 内容 | 状态 | 备注 |
|------|------|------|
| `files/default.bin` | ✅ | 已镜像至 `secpp/resources/` |
| `web/default.bin`, `stager.bin` | ✅ | 已镜像 |

---

## 6. 配置文件 (`configs/`)

| 文件 | 状态 | 备注 |
|------|------|------|
| `default.json` | ✅ | 已镜像 |
| `win10_basic_analysis.json` | ✅ | 已镜像 |
| `win10_full_analysis.json` | ✅ | 已镜像 |
| `win7_full_analysis.json` | ✅ | 已镜像 |

---

## 汇总

| 分类 | 已完成 | 部分实现 | 未开始 | 合计 |
|------|--------|---------|--------|------|
| 顶层模块 | 7 | 5 | 5 | 17 |
| 引擎层 | 0 | 1 | 0 | 1 |
| Windows 模拟层 | 0 | 12 | 5 | 17 |
| WinEnv 核心 | 1 | 3 | 0 | 4 |
| 用户态 API | 0 | 0 | 40 | 40 |
| 内核态 API | 0 | 0 | 8 | 8 |
| 定义文件 | 0 | 0 | 10 | 10 |
| **总计** | **8** | **21** | **68** | **97** |

**整体完成度: ~8% 完全完成, ~30% 部分实现**

---

> 最后更新: 2026-05-15
> 此文件应在每个 porting 里程碑后更新。
