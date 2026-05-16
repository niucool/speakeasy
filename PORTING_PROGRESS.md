# Speakeasy Porting Progress — Python → C++

> 最后更新: 2026-05-16
> 项目根: `/home/jim/projects/speakeasy`
> Python 源: `speakeasy/` → C++ 目标: `secpp/`

## 构建状态

| 指标 | 状态 |
|------|------|
| Linux GCC 编译 | ✅ **0 errors** |
| Linux 测试 (CTest) | ✅ **13/13 passed** |
| Windows MSVC 兼容 | ✅ 已修复 (154 errors → 0) |
| 剩余 TODO (全模块) | **264** |

---

## 完成阶段

| 阶段 | 状态 |
|------|------|
| Phase 0: 构建基础设施 | ✅ |
| Phase 1: 编译修复 | ✅ |
| Phase 2: 核心模块填充 | ✅ |
| Phase 3: 顶层适配 | ✅ |
| Phase 4: MSVC 兼容 | ✅ |
| Phase 5: Windows 模块实现 | 🔶 见下 |
| Phase 6: API 处理器移植 | 🔶 7/40 |
| Phase 7: 定义文件 | ❌ 3/10 |

---

## 模块状态

### 已完成 — 0 TODO, 编译通过

`speakeasy.h/.cpp`, `common.h/.cpp`, `memmgr.h/.cpp`, `config.h/.cpp`,
`cli.h/.cpp`, `cli_config.h/.cpp`, `errors.h`, `version.h`,
`artifacts.h/.cpp`, `report.h`, `struct.h`, `volumes.h/.cpp`,
`profiler_events.h`, `const.h`,
`engines/unicorn_eng.h/.cpp`,
`windows/winemu.h/.cpp`, `windows/win32.h/.cpp`,
`windows/loaders.h/.cpp`, `windows/ioman.h/.cpp`,
`windows/common.h/.cpp`, `windows/cryptman.h/.cpp`,
`arch.h`,
`kernel32/ntdll/advapi32/ws2_32/user32/crypt32/shell32` (API handlers)

### 进行中 — 有 TODO

| 文件 | TODO | 说明 |
|------|------|------|
| `winenv/api/api.cpp` | 58 | API 框架 — emu→xxx() 委托 + EmuStruct |
| `windows/objman.cpp` | 39 | 对象管理器 — 进程/线程/句柄表 |
| `windows/objman.h` | 30 | 头文件 TODO |
| `windows/fileman.cpp` | 24 | 文件操作 — create/open/read/write |
| `windows/fileman.h` | 12 | 头文件 TODO |
| `windows/netman.cpp` | 18 | 网络操作 — socket/bind/connect |
| `profiler.cpp` | 12 | 事件记录 |
| `windows/kernel.cpp` | 9 | 内核模拟 — pool_alloc/driver |
| `winenv/api/winapi.cpp` | 9 | API 定义 — 调用约定 |
| `windows/hammer.cpp` | 7 | 进程注入 |
| `windows/netman.h` | 7 | 头文件 TODO |
| `windows/sessman.cpp` | 6 | 会话管理 |
| `windows/regman.cpp` | 5 | 注册表 |
| `windows/com.cpp` | 3 | COM 模拟 |
| `binemu.cpp` | 2 | EmuStruct 接口 |
| `windows/driveman.cpp` | 2 | 驱动加载 |
| **总计** | **264** | |

### 未开始

- 33 个用户态 API 处理器
- 8 个内核态 API 处理器
- 7 个定义文件 (ndis, registry, wfp, winsock, usb, wdf, wsk)

---

## 后续建议

1. **api.cpp** (58 TODO) — 最大模块，阻塞 API 处理器工作流
2. **objman.cpp** (39+30) — 核心对象管理，被多模块依赖
3. **fileman.cpp / netman.cpp** (24+18) — 文件/网络 I/O
4. 其余小模块 — 平均 <10 TODO，可快速逐个处理

---

> 最后更新: 2026-05-16
> 编译: **0 errors**, **13/13 tests passed**
