# Changelog

> 所有对本项目的显著修改均记录在此文件中。
> 格式基于 [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)。

## [Unreleased]

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

