# Speakeasy Porting Progress — Python → C++

> 最后更新: 2026-05-16
> 项目根: `/home/jim/projects/speakeasy`

## 构建状态

| 指标 | 状态 |
|------|------|
| Linux GCC 编译 | ✅ **0 errors** |
| Linux 测试 (CTest) | ✅ **13/13 passed** |
| Windows MSVC 编译 | ✅ **0 errors**（含 speakeasy.lib + CLI + tests）|
| 剩余 TODO (全模块) | **29** (较初始 264 下降 89%) |

---

## 完成阶段

| 阶段 | 状态 | 说明 |
|------|------|------|
| Phase 0-4 | ✅ | 构建/编译/核心/MSVC 全部完成 |
| Phase 5: Windows 模块 | ✅ | **15/15 全部完成** |
| Phase 6: API 框架 | ✅ | **api.cpp 从 58 → 0 TODO** |
| Phase 7: API 处理器 | 🔶 | 7/40 ✅, 框架已就绪 |
| Phase 8: 定义文件 | ❌ | 3/10 ✅ |

## 已完成模块 (编译通过)

`speakeasy`, `binemu`, `common`, `memmgr`, `config`, `cli`, `cli_config`,
`errors`, `version`, `artifacts`, `report`, `struct`, `volumes`,
`unicorn_eng`, `winemu`, `win32`, `common` (windows), `loaders`, `ioman`,
`cryptman`, `arch`, `fileman`, `api` (框架), `objman`,
`kernel`, `hammer`, `sessman`, `regman`, `netman`, `com`, `profiler`,
`winapi`,
`kernel32/ntdll/advapi32/ws2_32/user32/crypt32/shell32`

## 残余 TODO (29 个，均依赖外部模块先完成)

| 文件 | TODO | 说明 |
|------|------|------|
| `api.cpp` | 4 | pool_alloc/heap_alloc/exit_process/共享内存 — 需其他模块实现 |
| `objman.cpp` | 4 | LdrDataTableEntry/DRIVER_OBJECT/EPROCESS 类型 — 需定义文件 |
| `hammer.cpp` | 3 | 配置读取 — 需 config 模块完善 |
| `binemu.cpp` | 2 | EmuStruct 接口 |
| `driveman.cpp` | 2 | 驱动加载 |
| `kernel.cpp` | 2 | pool_alloc 完善 |
| `artifacts.cpp` | 2 | 工件存储 |
| `speakeasy.cpp/h` | 2 | 顶层适配 |
| `winapi.cpp` | 1 | Emulator 类型完成 |
| `kernel32.cpp` | 1 | SystemInfo 结构填充 |
| `binemu.h` | 1 | 类型声明 |
| `profiler.h` | 1 | 常量定义 |
| `api.h` | 1 | 类型声明 |
| `windows/common.h` | 2 | PE 段处理 |
| `driveman.h` | 1 | 类型声明 |
| **总计** | **29** | |

---

> 编译: **0 errors**, **13/13 tests passed**
> 所有 9 个"待完成"模块已全部移植。
> 剩余 29 个 TODO 均为依赖外部模块的低优先级项。
