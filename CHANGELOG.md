# Changelog

> 所有对本项目的显著修改均记录在此文件中。
> 格式基于 [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)。

## [Unreleased]

### 2026-06-02

#### Added

- **secpp**: 补全了 Windows 模拟器中关于 Hook 初始化、API 模块导入回退以及数据导入的全部移植细节：
  - **Hook 机制与 SEH 辅助**：完整实现了 `WindowsEmulator::set_hooks`，自动初始化基类仿真 Hook 挂载，配置了未映射内存恢复与系统中断的回调跳板（`mem_unmapped_trampoline`, `intr_trampoline`）。
  - **API 查找回退规范化**：移植了 `WindowsEmulator::normalize_import_miss`，当遇到找不到的 API 导入函数时，自动计算并折叠 Zw/Nt 命名空间前缀、ANSI/Unicode 字符尾随（A/W 替换）以及转发库名称，实现高拟真的 API 发现流程。
  - **数据导入动态解析**：在 `WindowsEmulator::load_image` 中实现了 Python 侧对数据导入（如 `KeTickCount`）的解析机制，支持在遇到数据属性导出时，动态通过 `mem_map` 分配对齐的宿主端表示并在全局 `global_data` 进行跟踪写入。
- **build**: 重构了单元测试模块的 GoogleTest 依赖方案：
  - **GTest 静态构建 FetchContent**：弃用了 vcpkg 的动态 GTest 模块，改为使用 CMake `FetchContent` 直接拉取 release-1.12.1 源码并在项目内部编译为静态库（强制 `gtest_force_shared_crt OFF`），完全消除了测试套件在 Windows 平台执行时依赖 `gtest.dll` 与 `gtest_main.dll` 动态库加载的问题。
  - **头文件查找防御**：调整测试目标的 include directories 查找顺序（`BEFORE`），优先强制使用静态 GTest 的同源头文件，彻底消除了由于 vcpkg 头文件混淆导致的 `MakeAndRegisterTestInfo` 链接冲突。


- **secpp**: 彻底补全并实现了 177 个遗漏的 `kernel32` DLL 用户态 API 的 C++ 移植，并解决了高频发生的 Windows SDK 内置宏污染命名冲突：
  - **防宏污染宏定义隔离**：针对 MSVC/Windows SDK 环境中 `<windows.h>` 的内置 A/W 映射宏对 API 接口名称的侵入，在 `kernel32.h` 和 `kernel32.cpp` 顶部引入了包含 50 余项核心 API（如 `GetStartupInfo`, `GetSystemDirectory`, `lstrcmpi`, `lstrcpyn`, `InterlockedIncrement` 等）的 `#undef` 防治块，消消除因底层 API 被宏展开为 ANSI/Unicode 变体而产生的 duplicate definition 极其隐蔽的编译冲突。
  - **TLS & FLS 高仿真模拟**：完全实现了线程局部存储与纤程局部存储 API（`TlsAlloc`, `TlsFree`, `TlsGetValue`, `TlsSetValue`, `FlsAlloc`, `FlsFree`, `FlsGetValue`, `FlsSetValue`），直接与运行线程 `Thread` 类的 `tls_` 和 `fls_` 向量进行类型转换同步，实现高保真度仿真。
  - **原子 Interlocked 操作**：完全实现了 32-bit 原子算术与交换指令（`InterlockedIncrement`, `InterlockedDecrement`, `InterlockedExchange`, `InterlockedCompareExchange`），通过原生读写内存字节流，在小端序布局下原子模拟访客机数值的自增自减与条件置换行为。
  - **标准句柄与文件类型**：实现了 `GetStdHandle` 自动映射获取当前宿主进程中的 `stdin_handle`, `stdout_handle` 与 `stderr_handle` 的标准句柄引用，并补全 `GetFileType` 默认返回磁盘文件类型 `FILE_TYPE_DISK` (1)。
  - **高精度系统时间**：完全实现了 `GetSystemTimeAsFileTime`，通过 `std::chrono::system_clock` 精准读取当前 system 时间戳，并换算至 Windows 专用的 100 纳秒间隔 FILETIME 格式输出至访客内存。
  - **宽度敏感型字符串实用工具**：实现了 `lstrcmpi`, `lstrcmpiA`, `lstrcmpiW`, `lstrcpyn`, `lstrcpynA`, `lstrcpynW` 的内存级宽/窄字符转换、大小写折叠判定与带截断截尾控制的文本安全拷贝。
  - **162 项健壮空 Stub 注册**：对其余 162 个暂非必须的辅助、权限或同步 API 进行了全面的空 `STUB` 注册（默认 BOOL 成功返回 1），并挂载至 `Kernel32` 初始化映射表中，消除了因缺少导入函数映射在动态加载时引起的崩溃。
- **secpp**: 移除了所有第三方库在 Windows 环境下的 DLL 运行时依赖，实现了完全独立、无需 `vcruntime140.dll`/`msvcp140.dll` 即可独立运行 of 静态 standalone 编译构建：
  - **Unicorn & Miniz 静态 fetch 编译**：改用 CMake FetchContent 在构建时拉取 Unicorn 2.0.1 和 Miniz 3.0.2 源码并直接编译为静态链接库，全面避免了原有 Dynamic/DLL 模式的多余组件分发问题。
  - **/MT 静态 CRT 编译开关**：在全局 MSVC 条件下开启 `/MT` 与 `/MTd` 编译选项，并通过在引入 Unicorn 前后安全隔离 CMAKE_MSVC_RUNTIME_LIBRARY 的缓存黑客机制，绕过了 Unicorn 自定义 CMake 对静态运行库锁死报错的物理局限。
  - **GDT/IDT 段描述符写入奔溃修复**：定位并修复了 Unicorn 静态库模式下进行 `REG_GDTR` 写操作时因传递 64 位裸指针而非 24 字节 `uc_x86_mmr` 寄存器结构体导致的 unmapped memory 致命奔溃（新增 `reg_write_gdt_idt` 专属写入层），完全与 Python 模型段寄存器 31 entries limit 属性对齐。


### 2026-05-31

#### Changed

- **secpp**: 补全并重构了 Win32 仿真器中 Shellcode 加载 (`load_shellcode`) 与执行 (`run_shellcode`) 的移植实现，并将 `Thread` 类栈基址与提交大小字段全部重构为 `uint64_t` 以防止在 x64 平台下发生截断：
  - **Thread 栈地址类型提升**：在 `objman.h` 和 `objman.cpp` 中，将 `Thread` 的 `stack_base_` 和 `stack_commit_` 成员以及对应的 Getters/Setters 和 `init_teb` 参数全部由 `int` 提升为 `uint64_t`，避免 64 位平台上的内存地址信息截断，并彻底消除了相关的 MSVC 编译警告。
  - **Shellcode 规范化装载**：重构了 `load_shellcode` 以支持 `filename` 覆盖。当传入的 `data` 为空时自动退回读取 `path` 的物理文件。引入 `speakeasy::ShellcodeLoader` 对 Shellcode 进行规范化装载，生成带可执行权限 (`PERM_MEM_RWX` / 0x16) 的 `MemoryRegion` 并以 `RuntimeModule` 形式安全挂载至模块管理器中；同时使用 `picosha2` 自动提取 SHA-256 哈希，向 `profiler_` 全面同步装载元数据。
  - **仿真运行上下文补全**：重构并补全了 `run_shellcode` 的整套指令环境与仿真参数。增加地址范围校验，映射并挂接了 4 个大小为 1024 字节的虚拟参数页（`0x41420000 + i`），配置 `ECX` 寄存器为 1024，并为宿主进程分配 PEB 空间和 TEB 段寄存器（FS/GS）映射，完美对齐了 Python 侧的所有仿真控制流。
- **tests**: 在 `test_porting_winemu.cpp` 中新增了 `ObjmanPortingTest.ShellcodeLoadAndRun` 专项单元测试，验证了 1 字节 `RET` 指令 Shellcode 的装载、哈希生成、权限转换、栈管理与 clean returns 仿真回路，确保测试用例由 116 增至 **117** 并 100% 通过。
- **secpp**: 补全并重构了对象管理器中 `Thread` (ETHREAD) 类的 C++ 移植实现，并修复了线程特异性的 `last_error` 错误路由：
  - **Thread 结构与属性对齐**：在 `objman.h` 中将 `Token` 的定义移动到 `Thread` 之上，支持了由 `Thread` 以值类型持有 `Token token_` 成员（与 Python 中的 `self.token = Token(...)` 初始化一致），并增加了 `modified_pc_`、`suspend_count_`、`stack_base_`、`stack_commit_` 和 `get_tid()` 等关键属性的获取/修改接口。
  - **RIP/EIP 修改检测**：重构了 `Thread::set_context(void* ctx)`。当设置新的 CPU 上下文时，会提取新老上下文中的指令指针（x64 的 `RIP` 偏移 0x140，x86 的 `EIP` 偏移 0x98）进行对比。若存在修改，则自动设置 `modified_pc_ = true`，用于准确驱动调度器流程。
  - **TEB 自动读回同步**：在 `Thread::get_teb()` 中引入了 `teb_->read_back()` 调用，保证从 `Thread` 读取 TEB 时，它在仿真层物理内存中的全部最新改动能被正确、自动地拉取和同步到宿主 C++ 结构中。
  - **线程特异性错误码路由**：重构了 `Win32Emulator::set_last_error` 和 `Win32Emulator::get_last_error`。如果有活动线程运行，错误码将被自动路由存取在当前线程特有的 `last_error_` 中，而当无当前线程时则自动回退至全局 `last_error_`（完美复制 Python 层多线程模拟时的错误码隔离行为）。
- **tests**: 在 `test_porting_winemu.cpp` 中新增了 3 个专项测试，覆盖了 Thread 上下文 PC 修改触发、TEB 读回自动同步以及多线程下 `last_error` 隔离存取和降级逻辑，使测试用例数由 112 完美增至 115 且全票通过。
- **secpp**: 重构并完整同步了 `WindowsEmulator::load_module_by_name` 加载优先级链，使其与 Python 端设计完全一致：
  - **多优先级装载链**：依次支持 Priority 1 (Native PE 装载)、Priority 2 (API 关联 JIT PE 动态装载)、Priority 3 (Default Fallback PE 模板装载) 与 Priority 4 (Decoy 占位装载)，保证外部模块及库在仿真环境内可被鲁棒查找并挂载。
  - **模块仿真路径修正**：修复了在最终成功装载模块映像时，未重写 `LoadedImage::emu_path` 导致宿主和访客侧基名查询不一致的潜在 Bug。
- **tests**: 在 `test_porting_winemu.cpp` 中扩展了 `LoadModuleByNamePriorities` 专项单元测试，验证了 API 模块的 JIT 组装以及缺省诱饵的自动分类逻辑，确保测试用例由 115 增至 **116** 并全票通过。

### 2026-05-30

#### Changed
 
- **secpp**: 重构了结构体工具库 `secpp/struct.h` 与内存管理器 `secpp/memmgr.h` / `secpp/memmgr.cpp` 以提升在高频仿真过程中的读写性能：
  - **零拷贝内存访问**：为 `MemoryManager` 引入了 `mem_write(uint64_t addr, const void* data, size_t size)` 和 `mem_read(uint64_t addr, void* out_data, size_t size)` 原生指针重载，完全规避了原有基于 `std::vector` 临时内存分配产生的多余深拷贝和运行时开销，并将原有向量接口委托于新接口实现。
  - **直接 POD 结构体转换**：在 `struct.h` 中引入了 `speakeasy::cast_from_bytes<T>` 和 `speakeasy::cast_to_bytes<T>` 高性能模板函数，使得开发人员能够在一行代码中零开销地对任意 POD 结构体进行序列化与反序列化，无需手动逐字段硬编码大端/小端字节填充。
- **tests**: 在 `test_porting_struct.cpp` 和 `test_porting_memmgr.cpp` 中新增了全面的单元测试用例，覆盖验证了原生指针零拷贝操作以及 POD 结构体直接强转的准确性。
- **secpp**: 修复了 Windows 仿真环境下 `ddk.h` 中 `PASSIVE_LEVEL` / `DISPATCH_LEVEL` / `STATUS_*` / `IRP_MJ_*` 与 MSVC/Windows SDK 内置宏发生命名冲突而无法在特定包含顺序下顺利编译的重大兼容性阻碍。
- **tests**: 将综合测试套件 `test_porting.cpp` 进行了拆分，细化重构成 12 个独立的测试源文件，分别测试各个关键类和模块以提升测试的颗粒度：
  - `test_porting_struct.cpp`：验证 `EmuStruct` 字节布局与 SFINAE 多态序列化。
  - `test_porting_config.cpp`：验证 `SpeakeasyConfig` 缺省值、合并与 JSON 序列化。
  - `test_porting_module_name.cpp`：验证模块名称大小写转换与后缀截断的规范化逻辑。
  - `test_porting_profiler.cpp`：验证 `Profiler` 的进程、文件与注册表访问追踪记录。
  - `test_porting_volumes.cpp`：验证文件卷映射语法解析与目录展开。
  - `test_porting_artifact_store.cpp`：验证 `ArtifactStore` 的基本存取、去重与清理操作。
  - `test_porting_memmgr.cpp`：验证虚拟内存映射与保留页生命周期。
  - `test_porting_ntdefs.cpp`：验证 NT 内核基础数据结构的内存布局。
  - `test_porting_loaders.cpp`：验证运行时驱动/可执行文件分类与诱饵模块的匹配逻辑。
  - `test_porting_jitpe.cpp`：验证 `JitPeFile` 对 32/64 位诱饵 PE 部分的动态自组装行为。
  - `test_porting_pefile.cpp`：验证真实 PE 的 TLS 回调枚举与基址重定位偏移修正。
  - `test_porting_winemu.cpp`：验证多级多线程调度中 PEB/TEB 的动态链表链接与错误转储上下文分类。
- **tests**: 彻底移除了原有庞大的 `test_porting.cpp` 以杜绝用例重复，重新配置 CMake 并编译运行，全票通过了所有拆分后的 108 项端口测试用例。
- **secpp**: 创建了通用的工具文件 `secpp/helper.h` 与 `secpp/helper.cpp`，实现了高效的字符串大小写转换接口 `speakeasy::to_lower` 与 `speakeasy::to_upper`。重构了 `BinaryEmulator` 中的大量 `std::transform` C-style 转换，全部采用新封装的统一 Helper 接口，提升了代码的复用度与可读性。

#### Fixed

- **secpp**: 修复了 `BinaryEmulator` 的核心参数处理和调用约定（Calling Conventions）漏洞，使其完全同 Python 层对齐：
  - **`set_func_args`**：修复了在 `home_space=false` 时，误跳过前 4 个 AMD64 寄存器参数设置的严重 Bug。
  - **`get_func_argv`**：修复了从栈上抓取 AMD64 堆栈参数时出现的指针尺寸偏移差错（将起始偏移对齐至 `RSP+0x20+ptr_size`）；支持了 x86 下 `CALL_CONV_FASTCALL` 寄存器参数与 stack 参数的协同抓取；支持了 AMD64 下 float 实参在 `XMM0-XMM3` 寄存器中的读取。
  - **`do_call_return`**：修复了当未明确指定返回地址（`ret_addr=0`）时，未自动弹栈（pop return address）导致 PC 被设置至错误的栈指针值以及栈溢出的严重缺陷。
  - **`set_ptr_size`**：引入了对不支持的硬件架构抛出类型匹配异常 `EmuException` 的拦截检查，防止潜在的隐式 32-bit 回退。
  - **`reg_read/reg_write`**：对于不合法的寄存器字符串传入，由原本的静默忽略/返回 0 修正为规范抛出 `EmuException`。
  - **`read_mem_string`**：限制并校验字符宽度 `width` 仅能在 `1`（UTF-8）和 `2`（UTF-16LE）中，并修正了宽字符转码的内存遍历越界细节，彻底对齐 Python 解码行为。
  - **`get_stack_trace`/`format_stack`**：对栈内存 Jun 物理读取流程增加了越界/失效捕获（`try-catch`），从而避免由于未映射内存的读取异常中断调用栈解析，确保发生崩溃时测试和排错流的弹性。
  - **`Win32Emulator::setup`**：修复了在初始化过程中未同步本端 `this->arch` 到 `my_arch`，直接向 `set_ptr_size` 传递零值造成 `"Unsupported architecture"` 异常而引发仿真奔溃的严重 Bug。

### 2026-05-29

#### Added

- **secpp**: 补全了 `BinaryEmulator` 的 X86/AMD64 调用约定栈帧清理与返回处理 `do_call_return` 及 `clean_stack_args`，支持 `cdecl`、`stdcall`、`fastcall` 等调用约定的传参和出栈清理。
- **secpp**: 补全了 `BinaryEmulator` 中与 Python 一致的 `_hook_mem_invalid_dispatch` 动态内存失效 Hook 调度分配器以及 `add_mem_invalid_hook` 首个原生调度 Hook 的注册挂载，大幅提升了仿真引擎对越界/失效内存访问的追踪分配效率。
- **secpp**: 补全了动态代码 Hook 触发路径 `_fire_dyn_code_hooks` 和 `_set_dyn_code_hook`（包含自关闭的临时 CodeHook），深度打通了 Profiler 动态代码的事件记录 (`log_dyn_code`) 以及 `DynCodeHook::invoke` 调度机制。
- **secpp**: 在 `Speakeasy` (在 `speakeasy.cpp`) 对外暴露的 Hook 注册 API 中添加了类型安全的 Lambda 闭包包装器，完美适配并对齐了 `BinaryEmulator` 全新现代化的 Callback 签名，彻底解决了头文件重构后的回调类型编译冲突。

#### Changed

- **secpp**: 重构规范化了 `BinaryEmulator::set_func_args` 和 `get_func_argv` 中 AMD64 架构下前 4 个参数寄存器的绑定与读取，完全改用 `speakeasy::arch` 下的标准 `REG_RCX`/`REG_RDX`/`REG_R8`/`REG_R9` 寄存器常量映射，消除了原有的硬编码占位符。
- **secpp**: 修复并对齐了 `BinaryEmulator::push_stack` 的返回值，使其返回被推入栈的数值本身，与 Python 仿真层返回逻辑完全保持一致。
- **secpp**: 改进了 `BinaryEmulator::read_mem_string` 中对 UTF-16LE 宽字符的解析逻辑，追加支持了制表符 `\t`、换行符 `\n` 以及回车符 `\r` 的完整解码输出。
- **secpp**: 对核心类、管理器类、基础仿真器类及用户态仿真器类中的所有 `private`/`protected` 成员变量进行了系统性的重构，在变量末尾统一追加下划线 `_`（包含：`BinaryEmulator`、`Win32Emulator`、`Console`、`SEH`、`KernelObject`、`Driver`、`Device`、`Irp`、`Thread`、`ObjectManager` – `FileMap`、`File`、`Pipe`、`FileManager`、`RegValue`·、`RegKey`、`RegistryManager` 等类中的所有私有/受保护成员）。完全消除了成员变量在构造函数初始化列表、Getter/Setter 接口以及继承子类中被 shadowing 遮蔽编译警告（MSVC `C4458`）的安全隐患，规范并统一了 C++ 代码风格，确保在 `/W4` 警告级别下编译零警告。
- **secpp**: 将 `BinaryEmulator` 内持有的 CPU 指令与内存读写 Hook 容器类型由裸指针 `std::map<int, std::vector<Hook*>>` 重构升级为智能指针 `std::map<int, std::vector<std::shared_ptr<Hook>>>`。这一现代化重构消除了原先由于在仿真器生命周期结束时未手动释放 Hook 对象而造成的潜在内存泄漏问题，全面规范了 C++ 代码的生命周期管理，使其符合 RAII 最佳实践。

#### Fixed

- **secpp**: 修复了 `speakeasy.h` 与 `speakeasy.cpp` 中由于延迟 Hook 队列容器错误存放 Hook 类类型而非 Callback 类型的编译模板实例化错误，将类型规范化为 Callback 包装容器。
- **secpp**: 修复了 `add_IN_instruction_hook` 与 `add_SYSCALL_instruction_hook` 将指令 Hook 错误存入 `mem_write_hooks` 队列的遗留 bug，独立划分了 `instruction_hooks` 延迟列表并在 `_init_hooks()` 中打通挂载注册。
- **secpp**: 修复了 `MapMemHook::invoke` 丢失参数的错误，更新其函数签名以携带全部 6 个环境上下文参数，完美对齐了 `MapMemCallback`。
- **secpp**: 修复了 `common.cpp` 中内存 Hook 子类（`ReadMemHook`、`WriteMemHook` 及 `InvalidMemHook`）构造函数在调用基类 `MemHook` 时直接丢弃了用户传入的 cb/begin/end 回调和访问地址范围的严重 Bug，确保所有内存 Hook 均能正常携带回调及其监视范围进行拦截调度。
- **secpp**: 修复了 C++ Hook 框架子类（`MemHook` 及其派生类、`InterruptHook`、`InstructionHook`、`InvalidInstructionHook`）在注册回调时传递错误 context 指针的严重内存安全 bug（在 `hook_add` 中将原本的 `container` 修正为 `this`），彻底消除了在此类 Hook 触发时由于类型强转错误（`WindowsEmulator*` 转具体 `Hook*`）而引发的 Segmentation Fault 隐患，保障了 C++ Emulation 运行时 Hook 调度的内存安全。

### 2026-05-28

#### Changed

- **docs**: 重新核对 `PORTING_PROGRESS.md`、`CHANGELOG.md` 与当前 `secpp` 移植代码中的显式 TODO 标记，更新遗留 TODO 总数为 20，并补充遗漏的 `ntdll.cpp` 注册表/句柄相关移植项。

### 2026-05-27

#### Added

- **tests**: 在 `test_porting.cpp` 中新增了 `JitPeFileTest.ConstructorDecoyAssembly` 单元测试用例，用以验证通过 `JitPeFile` 构造函数直接指定导出函数名称列表时，自动触发 PE 诱饵头部与 `.text` / `.edata` 节段组装的正确性。
- **secpp**: 成功将 `win32::prepare_module_for_emulation` 模块准备逻辑从 Python 移植至 C++。
  - 在 `Run` 类中添加了 `args_values` 向量以暂存 raw numeric arguments。
  - 在 `WindowsEmulator::_prepare_run_context` 中实现了对 `set_func_args` 的调用，使之能够在每次执行 `Run` 之前，将运行参数准确载入 CPU 寄存器与堆栈。
  - 完整补全了 `prepare_module_for_emulation` 和 `run_module` 对 `entry_point` 参数的可选支持。
  - 重构了 `build_service_main_args` 使之能够以 `std::pair` 形式返回 `argc` 和 `argv_ptr`。

#### Fixed

- **secpp**: 补全并修复了 `JitPeFile` 的 C++ 缺失实现与 MSVC 编译警告（对齐 Python 行为）：
  - 补充实现了 `add_section`、`pad_file`、`get_current_offset` 和 `append_data` 成员函数，解决了单元测试链接时出现的 unresolved external symbol (`LNK2019`) 错误。
  - 重命名了 `add_section` 和 `get_decoy_pe_image` 中的参数名称（如 `name` -> `sect_name`，`exports` -> `export_names`），消除了 MSVC 编译器下由于遮蔽（shadowing）成员变量而引发的 `C4458` 警告。
  - 在 32 位 `JitPeFile` 模版构造中，对 optional header 中的 `ImageBase` 赋值进行了显式的 `static_cast<uint32_t>` 强类型转换，消除了 `C4244` 精度丢失警告，确保了整个项目在 `/W4` 下的高标准 Warning-Free 编译。

### 2026-05-26

#### Changed

- **全部159个.h/.cpp文件**: 移除所有非ASCII字符（56352字符），消除编译时 warnings/internationalization 干扰
  - UTF-8 EM DASH (U+2014) → 移除
  - BOX DRAWINGS (U+2500) → 移除
  - 此前文档中的中文字符全部清理

#### Fixed

- **CMakeLists.txt**: 修复 pe-parse 构建失败 — `third_party/pe-parse` 为空目录
  - git clone trailofbits/pe-parse 到 `third_party/pe-parse/`
  - 安装 `libicu-dev` 系统包（pe-parse 依赖 ICU）
- **picosha2.h**: 从 vcpkg 拷贝到 `secpp/` 目录并改用 `#include "picosha2.h"` 形式
- **windows/common.cpp**: 添加缺失的 `#include <cstring>` 解决 `std::memcpy` 未声明错误

### 2026-05-25

#### Changed

- **secpp**: 重构文件系统管理模型 (FileManager)，深度现代化内核对象表示与 Python 行为对齐：
  - 将 `File`、`Pipe`、`FileMap` 改为继承自 `KernelObject` 基类，实现统一的句柄安全生命周期与托管。
  - 将 `FileManager::get_object_from_handle` 接口的返回类型由 bare `void*` 重构为 `std::shared_ptr<KernelObject>`，完全替换原先的裸指针类型转换，并在 `WindowsEmulator::get_object_from_handle` 中启用了文件句柄备用解析。
  - 重构了 `File`、`Pipe`、`FileMap` 构造函数，支持传递 `emu` 参数以传递给 `KernelObject` 构造函数进行平台架构、属性管理链式传递，并更新了全部 `std::make_shared` 和测试用例中的调用。

#### Added

- **secpp**: 补全并同步了 `FileManager::get_emu_file` 的全部 Python 逻辑：
  - 支持按需清理路径、相对路径转换（对齐 `config.current_dir`）和通配符匹配（实现了 case-insensitive `wildcard_match`）。
  - 支持将需要仿真的用户/系统 DLL 转换为对应架构 `decoy_dir` 下的诱饵 PE。
  - 完美支持了文件扩展名匹配 (`by_ext`) 和默认仿真回退 (`default`) 配置，并添加了 `emu_file_configs` 映射级缓存。
  - 完美支持了仿真配置中 `byte_fill` 的提取、格式化与向后填充机制，并在 `File::handle_file_data` 和 `FileManager::handle_file_data` 中完全移植了对应字节填充数据生成功能。
  - 实现了 `walk_files()` 接口，能够返回当前仿真环境的全部虚拟文件路径。

### 2026-05-24

#### Changed

- **secpp**: 重构内核对象管理模型，全面现代化为智能指针生命周期托管：
  - 将 `ObjectManager` 内持有的对象映射以及 `WindowsEmulator` 内的活动进程列表重构为智能指针 `std::shared_ptr<KernelObject>` 与 `std::shared_ptr<Process>`，取代原先的 `void*` 裸指针，消除了潜在的内存泄漏与野指针隐患。
  - 重构了 `ObjectManager` (在 `objman.h` / `objman.cpp`)、`WindowsEmulator` (在 `winemu.h` / `winemu.cpp`)、`ApiHandler` (在 `api.h` / `api.cpp`) 中的对象创建与检索接口签名（如 `get_object_from_handle`、`get_object_from_id`、`create_event`、`create_mutant` 等），统一返回智能指针。
  - 批量重构并同步更新了 `ntdll.cpp`、`kernel32.cpp`、`psapi.cpp` 等多态 API 处理程序中的对象生命周期控制流，全面与智能指针接口对齐。

#### Fixed

- **secpp**: 修复了 `ObjectManager::new_object<T>()` 模板方法在实例化时的编译错误：
  - 解决了由于 `add_object(obj)` 返回基类指针 `std::shared_ptr<KernelObject>` 导致 `new_object` 返回派生类（如 `Event`、`Mutant`）时发生的下转型（downcast）隐式转换失败编译错误（C2440）。修正为先执行 `add_object` 注册，再直接返回已带有子类强类型的 `std::shared_ptr<T> obj`。

### 2026-05-23

#### Added

- **secpp**: 实现 `winapi.py` 的 `autoload_api_handlers` 和 `API_HANDLERS` 注册表移植。
  - 新增了中央预注册实现文件 [winapi_registration.cpp](file:///d:/Projects/github/speakeasy/secpp/winenv/api/winapi_registration.cpp)，显示注册了所有 39 个用户态 DLL 和 8 个内核态驱动处理类，保证静态链接不被编译器剪裁（linker pruning）。
  - 在 `WindowsApi::load_api_handler` 中实现了 v2 style 处理器的按需加载、导出钩子自动绑定与路由分发逻辑。
  - 补充实现了 `WinHttp` (在 `winhttp.cpp`) 和 `Ws2_32` (在 `ws2_32.cpp`) 的默认构造函数，使用 `INIT_API_TABLE` / `REG` 初始化 API 注册表映射。

#### Changed

- **secpp**: 合并全局基类 `::ApiHandler` (v1) 与 `ApiHandler2` (v2) 为单一的统一 `::ApiHandler` 类：
  - 完全删除了冗余的继承中间层 `api_handler_base.h`。
  - 将所有 API Table 注册宏、`ApiFunc`/`ApiEntry` 结构体、虚函数接口及辅助函数等直接统一至全局基类 `::ApiHandler` 中。
  - 强制所有 47 个子类（用户态 DLL 和内核态驱动）的构造函数签名接收 `void* emu`，并显式且必须传递给 `ApiHandler(emu)` 基类构造函数，删除了所有默认实参 `emu = nullptr` 以增强强类型安全性。
  - 批量重构更新了所有 47 个 DLL/驱动类的头文件与源文件实现（如 `advapi32.h` / `advapi32.cpp`、`ntoskrnl.h` / `ntoskrnl.cpp` 等），使其继承直接指向 `::ApiHandler`。
  - 更新了 `winapi_registration.cpp` 中的工厂注册函数，自动捕获并传入 `emu` 指针。
  - 优化了 `WindowsApi::call_api_func` 与 `WindowsApi::load_api_handler`，省去了不必要的下转型 `dynamic_cast`，直接通过统一的 `ApiHandler` 派发多态方法。

- **secpp**: 重构了 v1/v2 `ApiHandler` 的命名和包含路径以消除层级混淆：
  - 将 `api_handler_base.h` 从 `secpp/winenv/api/usermode/api_handler_base.h` 移动到中央的 `secpp/winenv/api/api_handler_base.h`。
  - 将 v2 宏驱动的子类从 `speakeasy::api::ApiHandler` 重命名为 `speakeasy::api::ApiHandler2`，基类依然为全局命名空间的 `::ApiHandler`。
  - 将 `ApiHandler2` 的构造函数重构为统一的单构造函数签名：`ApiHandler2(void* emu = nullptr)`，保持与 47 个子类声明的向后兼容。
  - 自动批量更新了所有 47 个 usermode DLL 和 kernelmode 驱动的头文件，使之包含 `../api_handler_base.h` 并继承自 `ApiHandler2`。
  - 更新了 `winapi.cpp`，改用 `speakeasy::api::ApiHandler2` 进行多态下转型 (`dynamic_cast`) 判定。
  - 重命名 `ApiHandler::get_ptr_size` 成员函数为 `get_pointer_size`，以防和 `ntdll.cpp` 中全局/静态辅助函数冲突导致变量或函数遮蔽。

#### Fixed

- **secpp**: 修正了若干编译警告和处理器继承冲突：
  - 修复 `iphlpapi.cpp` 中 `write_string` 隐式调用基类同名重载导致的 C2660 编译错误，显式指定 `speakeasy::write_string` 命名空间。
  - 修正了 `sfc_os.cpp` 构造函数的显式基类初始化，使之正确调用 `ApiHandler2()`。

### 2026-05-22

#### Added

- **secpp**: 实现 PE 基址重定位处理 `PeFile::relocate_image(uint64_t new_base)`（对齐 Python `pefile::relocate_image` 逻辑）。
  - 支持解析 Page RVA 块、Block Size 以及 16-bit descriptor。
  - 支持 32 位 `IMAGE_REL_BASED_HIGHLOW` (type 3) 和 64 位 `IMAGE_REL_BASED_DIR64` (type 10) 的绝对地址重定位修正。
  - 在 `PeFile::rebase(uint64_t to)` 中自动调用 `relocate_image` 修正映射映像，在 `PeFile` 构造函数对于 ImageBase 为 `0` 的特殊 PE 初始重定位至 `DEFAULT_LOAD_ADDR`。
  - 在 `tests/test_porting.cpp` 中新增 `PeFileMemoryMappedImageTest.RelocateImage` 单元测试，加载 `antidbg.exe` 验证重定位前后 32 位/64 位绝对地址修正在 RVA 映像中的正确性。
- **secpp**: 实现 `PeFile::get_memory_mapped_image` 和 `DecoyModule::get_memory_mapped_image` (对齐 Python `pefile` 实现)。
  - 对齐了 Python 端的 `adjust_PointerToRawData`、`adjust_SectionAlignment`、`get_PointerToRawData_adj` 及 `get_VirtualAddress_adj` 等边界与对齐逻辑。
  - 在 `PeFile` 中新增了 `raw_pe_data` 原始字节存储，并完美处理了空区填充、多节对齐等细节。
  - 在 `tests/test_porting.cpp` 中新增了 `PeFileMemoryMappedImageTest.GetMemoryMappedImage` 单元测试，加载 `tests/bins/antidbg.exe` 验证内存加载映像的正确性。
  - 新增 `PeFileMemoryMappedImageTest.GetTlsCallbacksAndReloc` 单元测试，专门验证 TLS 回调指针的读取和 Reloc Table 是否存在逻辑。

#### Changed

- **secpp**: 进一步深度对齐 `PeFile` / `JitPeFile` 及其辅助函数与 Python 端的实现逻辑：
  - **PeFile::get_tls_callbacks()**: 摆脱之前的空占位，完美实现了基于 `IMAGE_DIRECTORY_ENTRY_TLS` 的 TLS 回调指针解析，通过解析数据目录内的 `AddressOfCallBacks` VA 指针并在 RVA 空间上循环读取，实现与 Python `_PeParser` 100% 对等的 TLS 回调收集功能。
  - **PeFile::has_reloc_table()**: 替换了 defer 占位符，直接通过检查 PE 可选头的 `DataDirectory[5]` (IMAGE_DIRECTORY_ENTRY_BASERELOC) 的 `Size` 属性判定 relocation 目录的存在性，完美对齐 Python `has_reloc_table`。
  - **pefile_imp_cb**: 修改了导入模块解析的后缀去除逻辑，改用与 Python `os.path.splitext` 对等的 `.rfind('.')` 后缀名剥离，完美解决非 `.dll` 模块（如 `.sys`）的前缀提取错误。
  - **JitPeFile::update_image_size()**: 实现了此前声明但缺失定义的 `JitPeFile::update_image_size()` 方法，通过安全解析 `e_lfanew` 计算并向 OptionalHeader 的 SizeOfImage offset 处回写正确的 Image 映射大小，并重新触发 `update()` 刷新。
- **secpp**: 将 Thread 指针生命周期管理重构为 `std::shared_ptr<Thread>`，避免多处内存泄漏并现代化线程生命周期管理。
  - **objman.h/cpp**: 将 Process 类中的 `std::vector<Thread> threads` 修改为 `std::vector<std::shared_ptr<Thread>> threads`，`Thread curr_thread` 修改为 `std::shared_ptr<Thread> curr_thread`。
  - **winemu.h/cpp**: 将 emulator 的 `curr_thread` 重构为 `std::shared_ptr<Thread>`，并将 `init_teb`、`init_tls`、`get_thread_context`、`load_thread_context`、`resume_thread` 等 API/辅助签名中的 `void* thread` 或 `Thread*` 统一更新为 `std::shared_ptr<Thread>`，添加 `find_thread` 和 `find_thread_by_ptr` 线程安全检索辅助函数。
  - **win32.cpp**: 更新 `run_module` 和 `run_shellcode` 中线程对象的创建方式，由 `new Thread` 重构为 `std::make_shared<Thread>` 并正确归入 Process 的线程向量中，解决了裸指针内存泄漏。
  - **kernel32.cpp**: 将 `CreateProcessA`、`CreateThread`、`CreateRemoteThread` 等函数中对 `Thread*` / `void* thread` 的检索 and 传递转换为 `std::shared_ptr<Thread>` 并在需要裸指针时获取 `.get()` 或 `->get_id()`，更新 Snapshot 线程存储。
  - **ntdll.cpp**: 重构线程相关的 `NtCreateThread`、`NtOpenThread`、`NtGetContextThread` 函数，使用 `wemu->find_thread` 等方法实现安全的线程转换与生命周期控制。
  - **msvcrt.cpp**: 更新 `_beginthreadex` 和 `_beginthread` 以接收 `std::shared_ptr<Thread>` 并返回 `thread.get()`，完成 C++ 线程智能指针管理的全面现代化。
- **secpp**: 深度对齐 `secpp/windows/common.cpp` 和 `loaders.cpp` 中的 PE 处理与映像加载逻辑到 Python 端的 `_PeParser` 与 `loaders.py`：
  - **PeFile::is_driver()**: 增加对可选头中 Subsystem 字段的判定（`IMAGE_SUBSYSTEM_NATIVE` 为 1 时归为驱动），全面对齐 Python 端的驱动类型推导。
  - **PeFile::rebase(uint64_t to)**: 实现了完整的内存映像重建逻辑（更新 entry point、重新生成 mapped_image 映像、重解析 sections/imports/exports，并使用 `_patch_imports()` 重写导入表指针），解决了在进行重定位时内存映像与实际基址脱节的隐患。
  - **PeLoader::make_image()**: 修复了此前在 C++ `PeLoader` 中将原始磁盘文件数据直接映射进模拟器内存的严重移植缺陷。现在正确使用 `pefile.mapped_image`（经对齐与零填充的内存映像）作为 MemoryRegion 的初始化数据。

#### Fixed

- **secpp/windows/common.cpp**: 修复重定位过程中的 RVA 偏移和区段解析错误：
  - 修复 `PeFile::_get_pe_sections()` 重定位时的 Bug。此前 `_get_pe_sections()` 在解析 section descriptors 时使用动态 `base`（即当前的虚拟加载地址）初始化 `ctx.image_base`，导致重定位（rebase）后计算出的 section RVA 大小与实际头部大小不一致而产生下溢/上溢错乱。现已修正为严格基于 PE 首部固有的 preferred `ImageBase` 来计算，使得 `mapped_image` 始终具备稳定的 RVA 对齐映射。
  - 修复 `tests/test_porting.cpp` 中 `RelocateImage` 单元测试使用 `pe.get_memory_mapped_image` 重新从磁盘文件构造导致未带上重定位修改的 Bug，修正为直接读取 `pe.mapped_image`。
- **secpp/windows/common.h & common.cpp**: 修复并消除所有 MSVC 编译警告（包含变量重名遮蔽 C4458、隐式类型转换截断 C4244、未引用形参 C4100 等），实现 100% warning-free 安全编译。
- **secpp/windows/loaders.cpp & loaders.h**: 修复并消除了所有的 MSVC 编译警告（包含变量重名遮蔽 C4458、未引用形参 C4100、局部变量未引用 C4189、未引用函数 C4505 等），确保加载器实现完全无警告编译。
- **loaders.cpp**: 修复了 `PeLoader::make_image` 从 Python 移植到 C++ 时的若干移植错误：
  - 修复了 PE 入口点 (entry point) 相对虚拟地址 (RVA) 的获取错误（此前被错误地写为硬编码的 `(sections_.empty()) ? 0 : 0` 导致始终返回 `0` 从而使得仿真环境起始执行在无效的 PE 头部），现在可以正确读取并获取 PE 的 `AddressOfEntryPoint`。
  - 实现了 `rsrc_cb` 资源文件解析回调函数，将 PE 中的资源条目 (Resource Entry) 提取并正确填充到 `metadata_.resources` 中，与 Python 端逻辑完全对齐。
  - 修复了 PE 模块类型分类的移植错误：解决了命令行（CUI）可执行程序（Subsystem 3）在 `RuntimeModule` 的构造函数中被错误分类为 `"dll"` 的问题。引入了 `is_dll` 和 `is_decoy` 等标志，实现了在 C++ `RuntimeModule` 构造时根据 `LoadedImage` 的 `is_decoy`、`is_driver` 和 `is_dll` 标志进行与 Python 完全对齐的类型推导。
  - 在 `DecoyLoader::make_image` 中设置 `img->is_decoy = true;`，在 `ApiModuleLoader::make_image` 中设置 `img->is_dll = true;`，在 `PeLoader::make_image` 中依 PE 头部特征字及导入系统 DLLs 判定并填充 `is_driver` 及 `is_dll`，彻底解决了 CUI 程序分类和 decoy/api 模块分类的不一致。
  - 修复了导入表模块后缀剥离的移植错误：在 `imp_cb` 中，使用 `.rfind('.')` 进行剥离，正确支持非 `.dll` 文件名后缀（例如 `.sys`）的剥离，与 Python 的 `os.path.splitext` 完全对齐。
  - 在 `tests/test_porting.cpp` 中新增了 `LoaderModuleClassificationTest` 单元测试，全方位覆盖并验证 CUI exe、decoy 模块和 api 模块的加载器类型分类与智能推导逻辑。

### 2026-05-21

#### Added

- **win32.cpp**: 实现 `Win32Emulator::init_processes` — 从配置创建 Process 对象并注册到 ObjectManager
- **win32.cpp**: 实现 `Win32Emulator::init_sys_modules` — 加载系统模块并处理驱动设备
- **win32.cpp**: 实现 `Win32Emulator::init_container_process` — 从配置查找主进程并创建
- **win32.cpp**: 实现 `Win32Emulator::get_user_modules` — 返回非驱动模块列表
- **winemu.cpp**: 实现 `WindowsEmulator::_init_module_group` — 从模块配置列表批量初始化模块
  - 三级 fallback: PeLoader → ApiModuleLoader → DecoyLoader
  - ntdll 特殊处理：ntoskrnl 处理器附加
- **profiler.h**: 添加 `set_strings()` / `get_strings()` 公共访问器 (`strings` → `strings_`)
- **winemu.cpp**: `load_image` 添加 `profiler.strings` 字符串提取

#### Changed

- **secpp**: 将所有 `Process*` 裸指针重构为 `std::shared_ptr<Process>` 智能指针以实现安全的自动生命周期管理，涉及 `memmgr`、`winemu`、`win32`、`kernel` 等核心组件，彻底移除手动 `delete` 逻辑。
- **binemu.cpp**: `get_ansi_strings` / `get_unicode_strings` 重写为 `std::regex` 实现
- **win32.cpp**: 4 个 TODO → 实现说明
- **winemu.cpp**: 1 个 TODO → 实现说明
- **api.cpp**: 更新 `ApiHandler::create_thread` 接口以支持 `std::shared_ptr<Process>`，安全地使用 `find_process` 解析 `void* hproc`。

#### Fixed

- **win32.cpp**: 解决 `std::make_shared<Process>` 对空初始化列表 `{}` 进行模板类型推导失败的错误，显式指定为空 vector 类型。
- **winemu.cpp**: 修复 `_prepare_run_context` 成员中 `std::shared_ptr<Process>` 类型的 `process_context` 与 raw 指针进行 inequality (`!=`) 比较的编译错误。
- **ntdll.cpp**: 修复 `NtCreateThreadEx` 中 `proc_obj` `void*` 裸指针转换为 `std::shared_ptr<Process>` 并传递给 `create_thread` 的类型不匹配错误。
- **winemu.cpp**: `get_peb_modules()` 返回值生命周期修复 (non-const lvalue → rvalue)

### 2026-05-20

#### Added

- **winemu.cpp**: `WindowsEmulator::setup()` 基类实现
- **winemu.cpp**: `WindowsEmulator::on_run_complete()` 基类实现
- **speakeasy.cpp**: `Speakeasy::load_image` (委托给 `emu->load_image()`)
- **speakeasy.cpp**: `Speakeasy::_auto_mount_target_directory` (std::filesystem 目录遍历)
- **loaders.h/cpp**: `Loader` 抽象基类 + `PeLoader`/`ShellcodeLoader`/`ApiModuleLoader`/`DecoyLoader`
- **loaders.h/cpp**: `RuntimeModule` 类 (封装 `LoadedImage` + 运行时状态追踪)
- **win32.cpp**: `load_module` 完整逻辑 (文件读取、元数据、func_args)
- **win32.cpp**: `on_run_complete` 完整逻辑 (ret_val、profiler、_exec_next_run)

#### Fixed

- **win32.cpp**: MSVC 编译错误 (`get_return_addr`→`get_ret_address`, `set_func_args` 缺参数)
- **smoke_test.cpp**: GDT_ACCESS_BITS ODR 违规 (`static const` → `inline constexpr`)
- **profiler.h**: `strings`/`decoded_strings` 重命名为 `strings_`/`decoded_strings_` + 公共访问器

### 2026-05-19

#### Added

- **win32.cpp**: `load_module` 增强 (`_make_emu_path`、`fileman.add_existing_file`、`_set_input_metadata`、`set_func_args`)
- **win32.cpp**: `on_run_complete` 增强 (ret_val、profiler 记录、_capture_memory_layout、_exec_next_run)

#### Changed

- **api.h**: EmuStruct 命名空间修复 (`class EmuStruct;` → `namespace speakeasy { class EmuStruct; }` + using)
- **api.cpp**: 54 个委托方法实现 (58 TODO → 0)
- **objman.cpp**: 38+ TODO 实现 (39 → 1)
- **objman.h**: 类型注释清理 (30 → 0)
- **fileman.cpp**: 全部 TODO 实现 (36 → 0)

#### Fixed

- **winenv/defs/windows/com.h**: GUID 初始化 MSVC/GCC 兼容性
- **winenv/defs/windows/windef.h**: GUID 构造函数 + initializer_list 支持
- **common.h**: GDT_ACCESS_BITS ODR 违规 → `inline constexpr`
- **winemu.cpp**: Hook 回调签名不兼容 (profiler 私有成员访问)
- **objman.cpp**: SEH/EmuStruct/Driver/Thread 成员访问修复
- **api.cpp**: sizeof/cast 编译错误修复

### 2026-05-16

#### Changed

- **system**: 整体 TODO 从 264 降至 170 (35%)

#### Fixed

- **common.cpp**: MSVC Hook 回调修复 — 7 处成员函数指针→nullptr

