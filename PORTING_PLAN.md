# Speakeasy C++ Porting Plan

> 生成时间: 2026-05-15
> 配合文件: `PORTING_PROGRESS.md`（进度追踪）
> 构建系统: `CMakeLists.txt`

---

## 1. 总体策略

Porting 按**依赖分层**自底向上推进。每层完成后验证编译通过且 smoke test 不受影响。低层模块稳定后再向上构建。

### 1.1 分层总览

```
Layer 7   CLI / 报告 / 产物
Layer 6   API 处理器 (48 个 DLL handler)
Layer 5   顶层 Speakeasy 入口
Layer 4   模拟器核心 (WinEmu, Win32, Kernel, Loaders)
Layer 3   Windows 环境管理器 (File, Reg, Net, Crypto...)
Layer 2   配置 / 结构体 / 事件
Layer 1   基础设施 (Common, MemMgr, Profiler, BinEmu, Engine)
Layer 0   常量 / 错误 / 架构 (✅ 已完成)
```

### 1.2 工作原则

- **优先消除 TODO/stub**：现有 C++ 文件框架已存在，先补全实现再新建文件。
- **增量验证**：每完成一个文件，更新 `PORTING_PROGRESS.md`。
- **API handler 批处理**：48 个 handler 按功能域分组（文件 I/O、网络、加密等），每组一起移植。
- **defs/ 按需移植**：不一次性移植全部定义文件，随 API handler 移植增量添加所需结构体。

---

## 2. Phase 0 — 构建验证（当前阶段）

**目标**: 项目能通过 CMake 配置，smoke test 编译并链接所有依赖库。

### 2.1 动作项

| 步骤 | 内容 | 状态 |
|------|------|------|
| CMakeLists.txt | 顶层构建文件，vcpkg 集成 | ✅ |
| smoke_test.cpp | 验证 nlohmann_json, plog, unicorn, pe-parse 可用 | ✅ |
| vcpkg manifest | 可选 `vcpkg.json` 声明依赖版本 | 📄 待定 |
| 初编验证 | 尝试 `cmake -B build` 配置，修复 include 路径问题 | ⏳ |
| CI 骨架 | `.github/workflows/build.yml` C++ CI | 📄 待定 |

**完成标准**: `cmake --build build --target smoke_test && ./build/smoke_test` 输出全部 OK。

---

## 3. Phase 1 — 基础设施补全（Layer 1）

**目标**: 消除现有部分实现文件中的 TODO/stub，让核心引擎可编译运行。

**复杂度**: 中 | **风险**: 中 | **预估**: 2-3 周

### 3.1 模块清单

| 优先级 | 模块 | 当前状态 | 工作内容 |
|--------|------|---------|---------|
| P0 | `common.h/.cpp` | 🔶 Hook 体系有占位 | 补全 `_wrap_code_cb` 等回调包装器，接入 unicorn_eng |
| P0 | `memmgr.h/.cpp` | 🔶 底层引擎交互占位 | 完成 `mem_map`/`mem_write`/`mem_read` 的 unicorn 调用 |
| P1 | `engines/unicorn_eng.h/.cpp` | 🔶 | 验证 Unicorn C API 绑定完整性，测试 x86/x64 上下文切换 |
| P1 | `binemu.h/.cpp` | 🔶 部分方法占位 | 补全 `_parse_config`、disasm 引擎初始化、stack 分配 |
| P2 | `profiler.h/.cpp` | 🔶 JSON 输出占位 | 完成 `get_report()` JSON 序列化 |

### 3.2 关键技术点

- **Hook 分发**: Python 版使用 `weakref` + 动态 dispatch；C++ 版用 `std::function` + 注册表。需确保 hook 生命周期管理正确（RAII）。
- **内存管理**: `MemoryManager` 继承自 `BinaryEmulator`？当前 `binemu.h` 中 `BinaryEmulator : public MemoryManager`。需要确认这符合设计意图（Python 版是组合关系）。
- **Unicorn 映射**: `mem_map` / `mem_unmap` 直接调用 `uc_mem_map` / `uc_mem_unmap`。注意 `block_base`/`block_size` 的 OS 页粒度对齐。

### 3.3 风险

- Unicorn 版本兼容性：Python 版用 unicorn >= 2.1.4，C 接口可能略有差异。
- 内存地址冲突：Python 版用 Python int 无上限；C++ 用 `uint64_t`，需注意 32-bit 截断。

---

## 4. Phase 2 — 配置与结构体（Layer 2）

**目标**: 移植配置解析和 Windows 结构体定义，为 Windows 环境模拟提供基础。

**复杂度**: 低-中 | **风险**: 低 | **预估**: 1 周

### 4.1 模块清单

| 优先级 | 模块 | 工作内容 |
|--------|------|---------|
| P0 | `config.h/.cpp` | 从 `speakeasy/config.py` 移植。JSON schema 验证（复用 nlohmann_json）。加载 `configs/default.json`。 |
| P0 | `struct.h/.cpp` | 从 `speakeasy/struct.py` 移植。模拟 Windows 结构体（UNICODE_STRING, LIST_ENTRY 等）。用 POD struct + 辅助方法。 |
| P1 | `profiler_events.h` | 从 `speakeasy/profiler_events.py` 移植。事件类型枚举（header-only）。 |

### 4.2 关键技术点

- **配置验证**: Python 版用 pydantic；C++ 版用 JSON Schema 或手动 `validate_config()` 函数。
- **模拟结构体**: Python 版用 `EmuStruct` 基类 + 动态属性。C++ 版用模板或宏生成序列化/反序列化代码。

---

## 5. Phase 3 — Windows 环境管理器（Layer 3）

**目标**: 补全 12 个 Windows 环境管理器模块，消除 TODO。

**复杂度**: 高 | **风险**: 中高 | **预估**: 3-4 周

### 5.1 模块清单（按依赖顺序）

| 顺序 | 模块 | 当前状态 | 说明 |
|------|------|---------|------|
| 1 | `windows/common.h/.cpp` | 🔶 | Windows 通用工具（handle 管理、路径规范化）。被所有其他管理器依赖。 |
| 2 | `windows/objman.h/.cpp` | 🔶 | 内核对象管理器（目录、符号链接、设备对象）。 |
| 3 | `windows/fileman.h/.cpp` | 🔶 | 文件系统模拟。依赖 `objman`、`config`。 |
| 4 | `windows/regman.h/.cpp` | 🔶 | 注册表模拟。依赖 `objman`、`fileman`。 |
| 5 | `windows/cryptman.h/.cpp` | 🔶 | 加密管理器（hash/encrypt/decrypt）。较独立。 |
| 6 | `windows/netman.h/.cpp` | 🔶 | 网络管理器（socket 模拟）。 |
| 7 | `windows/driveman.h/.cpp` | 🔶 | 驱动管理器。依赖 `objman`、`fileman`。 |
| 8 | `windows/sessman.h/.cpp` | 🔶 | 会话管理器。 |
| 9 | `windows/com.h/.cpp` | 🔶 | COM 模拟（Linux 下可能需要 stub）。 |
| 10 | `windows/hammer.h/.cpp` | 🔶 | 进程挖空/注入。依赖 `objman`、`fileman`。 |

### 5.2 关键技术点

- **Handle 系统**: Python 版用 Python dict 做 handle → object 映射；C++ 版用 `std::unordered_map<uint32_t, shared_ptr<T>>`。
- **文件 I/O 模拟**: 虚拟文件系统 + 可选的 host volume 映射（`volumes.py`）。
- **注册表**: 树状结构，从 `defs/registry/` 加载初始 hive。

### 5.3 风险

- **线程安全**: 多个模拟线程可能并发访问管理器。当前设计似乎不涉及真正的多线程，但需要确认。
- **COM 跨平台**: COM 是 Windows 专属，Linux 下需要 stub 实现（抛出 `NotSupportedError`）。

---

## 6. Phase 4 — 模拟器核心（Layer 4）

**目标**: 完成主模拟器入口和 PE 加载器。

**复杂度**: 高 | **风险**: 高 | **预估**: 2-3 周

### 6.1 模块清单

| 优先级 | 模块 | 当前状态 | 说明 |
|--------|------|---------|------|
| P0 | `windows/winemu.h/.cpp` | 🔶 | **主 Windows 模拟器**（用户态 + 内核态基类）。消除 TODO，完成 `load_module`/`run_module`。 |
| P0 | `windows/loaders.h/.cpp` | ❌ | **PE 加载器**。映射 PE 到内存、处理导入表、设置 TLS 回调。依赖 `pe-parse`。 |
| P1 | `windows/win32.h/.cpp` | 🔶 | Win32 用户态模拟器。依赖 `winemu` + 用户态 API handler。 |
| P1 | `windows/kernel.h/.cpp` | ❌ | **内核模拟器**。依赖 `winemu` + `ioman` + 内核态 API handler。 |
| P2 | `windows/ioman.h/.cpp` | ❌ | I/O 管理器（IRP 分发）。依赖 `objman`。 |
| P2 | `windows/kernel_mods/` | ❌ | 内核模块（`.sys` 加载支持）。 |

### 6.2 关键技术点

- **PE 加载**: `pe-parse` 库解析 PE header，`MemoryManager::mem_map` 映射节区，处理重定位和导入表。
- **入口点调度**: DLL 多入口点（DllMain + 导出函数），EXE 单入口点，Shellcode 直接跳转。
- **TLS 回调**: 在入口点之前执行，常见于加壳样本。

### 6.3 风险

- **PE 格式边缘情况**: 加壳样本、损坏 PE、非标准 section 对齐。
- **内核模拟复杂度**: IRP 分发、驱动对象、设备栈。可能需要参考 WDM 规范。
- **重定位/导入**: 跨架构重定位类型不同（x86 vs amd64）。

---

## 7. Phase 5 — 顶层入口（Layer 5）

**目标**: 完成 `speakeasy.h/.cpp`，消除所有 TODO。

**复杂度**: 中 | **风险**: 中 | **预估**: 1 周

### 7.1 工作内容

- `_init_emulator`: 根据 PE 元数据选择 Win32Emulator 或 WinKernelEmulator。
- `_init_config`: 加载 `default.json` 配置文件。
- `add_*_hook` 系列方法：将 hook 注册请求转发到 `BinaryEmulator`。
- `get_report` / `get_json_report`: 调用 Profiler 序列化。

---

## 8. Phase 6 — API 处理器（Layer 6）

**目标**: 移植 48 个 API handler 文件。

**复杂度**: 高 | **风险**: 中 | **预估**: 4-6 周

### 8.1 分组策略

按功能域分 5 批：

| 批次 | 域 | 文件数 | 说明 |
|------|---|--------|------|
| A | 核心系统 | 6 | `kernel32`, `ntdll`, `advapi32`, `shell32`, `user32`, `gdi32` |
| B | 文件/注册表/进程 | 6 | `shlwapi`, `psapi`, `msvcrt`, `sfc`, `sfc_os`, `wtsapi32` |
| C | 网络 | 8 | `ws2_32`, `wininet`, `winhttp`, `dnsapi`, `iphlpapi`, `urlmon`, `mpr`, `netapi32` |
| D | 加密/安全 | 7 | `crypt32`, `bcrypt`, `ncrypt`, `bcryptprimitives`, `secur32`, `mscoree`, `advpack` |
| E | COM/OLE/杂项 | 13 | `ole32`, `oleaut32`, `comctl32`, `rpcrt4`, `winmm`, `msimg32`, `msi32`, `msvfw32`, `netutils`, `lz32`, `com_api`, `wkscli`, `wkscli` |
| 内核 | 内核态 | 8 | `ntoskrnl`, `hal`, `ndis`, `netio`, `usbd`, `wdfldr`, `fwpkclnt` + 1 |

### 8.2 移植模式

每个 Python API handler 的结构:

```python
class Kernel32:
    def __init__(self, emu):
        self.emu = emu
    
    @api_handler("CreateFileW")
    def CreateFileW(self, ...):
        # 模拟逻辑
```

对应 C++:

```cpp
// kernel32.h
class Kernel32 {
public:
    explicit Kernel32(Emulator* emu);
    
    // API handler methods
    uint64_t CreateFileW(uint64_t lpFileName, uint64_t dwDesiredAccess, ...);
};

// kernel32.cpp — 注册
void register_kernel32_handlers(ApiRegistry& reg) {
    reg.add("kernel32.dll", "CreateFileW", &Kernel32::CreateFileW);
}
```

### 8.3 关键技术点

- **Handler 注册**: 用 `api_handler_registry.h` 中的注册表模式，替代 Python 的装饰器。
- **参数解析**: 从模拟栈/寄存器读取参数（Unicorn API `uc_reg_read`）。
- **返回值**: 写入 `eax`/`rax`，设置 `STATUS_SUCCESS` 或错误码。

### 8.4 风险

- **API 数量大**: 48 个文件 × 平均 20 个 API = ~1000 个函数。优先保高频 API（导入表中出现频率最高的）。
- **defs/ 依赖**: 每个 handler 需要特定结构体定义，需提前从 `defs/` 移植。

---

## 9. Phase 7 — 输出与工具（Layer 7）

**目标**: 完成报告生成、CLI、产物存储。

**复杂度**: 中 | **风险**: 低 | **预估**: 1-2 周

| 模块 | 工作内容 |
|------|---------|
| `report.h/.cpp` | JSON 报告格式化，匹配 Python 版输出 schema |
| `artifacts.h/.cpp` | 内存 dump、网络流量等产物存储 |
| `cli.h/.cpp` | CLI 参数解析（argparse → CLI11 或手工解析） |
| `cli_config.h/.cpp` | CLI 配置覆盖逻辑 |
| `volumes.h/.cpp` | Host 目录挂载到虚拟文件系统 |

---

## 10. defs/ 移植策略

`speakeasy/winenv/defs/` 包含大量 Windows 类型定义（Python ctypes）。

### 10.1 方法

**推荐**: 按需增量移植。

1. 当 API handler 需要某个结构体时，从 Python defs 中提取定义。
2. 翻译为 C++ POD `struct`，保持字段名和偏移量一致。
3. 放入 `secpp/winenv/defs/` 对应子目录的 `.h` 文件。
4. 提供 `to_json()` / `from_json()` 序列化辅助（用于报告输出）。

### 10.2 自动化辅助

考虑编写一个 Python 脚本（`tools/gen_defs.py`），从 Python ctypes 定义自动生成 C++ struct。减少手工翻译错误。

---

## 11. 风险总览

| 风险 | 等级 | 缓解措施 |
|------|------|---------|
| API handler 移植量大（~1000 函数） | 🔴 高 | 分批进行，优先高频 API；用脚本辅助生成 stub |
| PE 加载器边缘情况 | 🟡 中 | 用 `pe-parse` 库减少手工解析；多测试样本 |
| 内核模拟复杂度 | 🟡 中 | 先完成用户态，内核态后续迭代 |
| Unicorn C API 兼容性 | 🟢 低 | API 稳定，Python 版已验证引擎行为 |
| 跨平台 Windows API | 🟡 中 | Linux 下 COM/UI API 返回 stub/error |
| 现有 C++ 代码架构偏差 | 🟡 中 | Phase 1 重构中修复继承/组合关系 |

---

## 12. 时间线估算

| Phase | 内容 | 预估工时 |
|-------|------|---------|
| 0 | 构建验证 | 已基本完成 |
| 1 | 基础设施补全 | 2-3 周 |
| 2 | 配置与结构体 | 1 周 |
| 3 | Windows 环境管理器 | 3-4 周 |
| 4 | 模拟器核心 + Loader | 2-3 周 |
| 5 | 顶层入口 | 1 周 |
| 6 | API 处理器 (48 文件) | 4-6 周 |
| 7 | 输出与 CLI | 1-2 周 |
| **合计** | | **14-20 周** |

---

## 13. 下一步行动

1. **立即可做**: 安装 vcpkg 依赖，运行 `cmake -B build` 验证构建配置。
2. **Phase 1 启动**: 从 `common.cpp` 的 Hook 包装器开始，补全 `_wrap_code_cb` 实现。
3. **并行工作**: 如果有多人，Layer 3 的管理器模块（FileMan, RegMan 等）可以各自独立推进。

---

> 本计划为初始草案，随着 porting 进展持续更新。
> 每个 Phase 结束后更新 `PORTING_PROGRESS.md` 中的状态。
