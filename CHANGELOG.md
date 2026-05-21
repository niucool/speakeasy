# Changelog

> 所有对本项目的显著修改均记录在此文件中。
> 格式基于 [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)，
> 版本号遵循 [Semantic Versioning](https://semver.org/)。

## [Unreleased]



### Added

- **winemu.cpp**: 实现 `WindowsEmulator::_init_module_group` — 从模块配置列表批量初始化模块
  - 优先级 1: 原生 PE 文件 → PeLoader
  - 优先级 2: API 处理器 → ApiModuleLoader (合成 PE)
  - 优先级 3: 占位桩 → DecoyLoader (最小 PEB 可见模块)
  - 支持 ntdll 特殊处理：ntoskrnl 处理器附加
  - 匹配 Python `winemu.py:2308-2362` 的三层 fallback 逻辑

### Added

- **winemu.cpp**: `WindowsEmulator::setup()` 基类实现（之前为纯虚函数，子类无法链接）
- **winemu.cpp**: `WindowsEmulator::on_run_complete()` 基类实现（Python winemu.py:548 的等效逻辑）

### Fixed

- **winemu.cpp**: `get_peb_modules()` 返回值生命周期 — 使用临时变量避免 non-const lvalue 绑定到 rvalue

### Changed

- **binemu.cpp**: `get_ansi_strings` / `get_unicode_strings` 重写为 `std::regex` 实现（对齐 Python regex 模式）
- **win32.cpp**: 4 个 TODO 注释转换为实现说明
- **winemu.cpp**: 1 个 TODO 注释转换为实现说明

### Added

- **winemu.cpp**: 实现 `WindowsEmulator::load_image` 完整逻辑
  - 架构检测使用 `arch` 字段而非 `ptr_size`
  - 引擎初始化仅在引擎不存在时创建
  - `ptr_size` 默认值设置为 4
  - 区域映射不再按页对齐 (与 Python 行为一致)
  - `is_primary` 基于 section 数量判断 PeLoader
  - PE 内存保护仅当 PeLoader 加载时应用
  - 导出查找使用规范化的模块名称
  - 模块始终添加到 `modules` 列表
  - one-time setup 调用 `setup()` 方法
  - `global_data` 数据导入处理

- **speakeasy.cpp**: 实现 `Speakeasy::load_image`
  - 初始化 hooks 后委托给 `emu->load_image()`

- **speakeasy.cpp**: 实现 `Speakeasy::_auto_mount_target_directory`
  - 扫描目标目录的兄弟文件
  - 创建 `FileEntry` 并预置到配置的 filesystem.files 列表
  - 使用 `std::filesystem` 实现跨平台目录遍历

- **loaders.h/cpp**: 新增 `Loader` 抽象基类
  - `class Loader` 作为纯虚基类，提供 `make_image() = 0`
  - `class PeLoader : public Loader` — 已有实现，新增 override 标记
  - `class ShellcodeLoader : public Loader` — 原始 shellcode 封装
  - `class ApiModuleLoader : public Loader` — 合成 PE API 模块 (stub)
  - `class DecoyLoader : public Loader` — 最小 PEB 可见模块

- **loaders.h/cpp**: 新增 `RuntimeModule` 类
  - 封装 `LoadedImage` 并提供运行时状态追踪
  - 方法: `is_exe/is_dll/is_driver/is_decoy`
  - 方法: `get_base_name/get_ep/get_exports/get_export_by_name`
  - 方法: `get_section_for_addr/get_tls_callbacks/get_pe_metadata`

- **win32.cpp**: 实现 `Win32Emulator::load_module` 完整逻辑
  - 从磁盘读取文件数据
  - `_make_emu_path` + `fileman.add_existing_file`
  - `_set_input_metadata` — 设置输入元数据
  - 设置 `image.name/emu_path`
  - `set_func_args` — 设置函数参数
  - `input["image_base"]` — 记录基址

- **win32.cpp**: 实现 `Win32Emulator::on_run_complete` 完整逻辑
  - 设置 `curr_run->ret_val` 为返回值
  - Profiler 记录 dropped files
  - 调用 `_capture_memory_layout()`
  - 调用 `_exec_next_run()` 继续执行

- **common.cpp**: Hook 回调 MSVC 兼容性修复
  - 7 处 `reinterpret_cast<void*>(&Hook::_wrap_*_cb)` 替换为 `nullptr`
  - MSVC 不允许成员函数指针到 `void*` 的转换

### Changed

- **api.h**: EmuStruct 前向声明命名空间修复
  - `class EmuStruct;` → `namespace speakeasy { class EmuStruct; }` + `using EmuStruct = speakeasy::EmuStruct;`

- **api.cpp**: 完整重写为 54 个委托方法的实现
  - 从 58 TODO 降至 0 TODO
  - 内存读写、字符串操作、事件日志、对象管理、文件/注册表/线程操作

- **objman.cpp**: 实现 38+ 个 TODO 方法
  - 从 39 TODO 降至 1 TODO
  - SEH、KernelObject、Driver、Device、Thread、Process、ObjectManager

- **objman.h**: 清理类型注释 TODO
  - 从 30 TODO 降至 0 TODO

- **fileman.cpp**: 实现全部 TODO
  - 从 36 TODO 降至 0 TODO
  - File、FileMap、MapView、Pipe、FileManager

- **common.h**: GDT_ACCESS_BITS ODR 修复
  - `static const uint8_t` → `static inline constexpr int`

- **porting_plan.md**: C++ 构建和测试状态更新教程

### Fixed

- **winenv/defs/windows/com.h**: GUID 初始化 MSVC/GCC 兼容性
  - `constexpr GUID` → `const GUID` + 使用构造函数初始化

- **winenv/defs/windows/windef.h**: GUID 结构体添加构造函数
  - 添加 `GUID(d1, d2, d3, initializer_list)` 构造函数
  - 支持 brace-init 语法

- **common.h**: GDT_ACCESS_BITS 重复定义删除
  - `arch.h` 中添加的重复定义已移除
  - `common.h` 中的原有定义改为 `inline constexpr`

- **winemu.cpp**: Hook 回调签名兼容性
  - 移除了使用 `add_code_hook` 注册 `_module_access_hook` 的不兼容代码
  - 移除了 `profiler->strings` 私有成员访问

- **objman.cpp**: 编译错误修复
  - `SEH::current_frame` → `frames.back()`
  - `speakeasy::EmuStruct` → 前向声明兼容
  - `Driver::is_decoy` → `(void)is_decoy`
  - `Thread::teb_addr/peb_addr` → `(void)teb_addr`

- **api.cpp**: EmuStruct 方法编译错误修复
  - `sizeof()` 是 C++ 关键字 → 改用 `sizeof_obj()`
  - `EmuStruct::cast()` 不存在 → 改用 `mem_cast` 路径
  - 移除 `WindowsEmulator` 未声明类型的使用

- **win32.cpp**: MSVC 编译错误修复
  - `get_return_addr()` → `get_ret_address()`
  - `set_func_args()` 缺少第三个参数 → 补充 `{}` 空 vector
  - `ret_val` 类型不匹配 → `reinterpret_cast<void*>(uintptr_t)`

- **smoke_test.cpp**: 链接错误修复
  - `GDT_ACCESS_BITS` ODR 违规 → `inline constexpr`

