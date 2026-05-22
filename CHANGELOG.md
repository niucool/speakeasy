# Changelog

> 所有对本项目的显著修改均记录在此文件中。
> 格式基于 [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)。

## [Unreleased]

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

- **binemu.cpp**: `get_ansi_strings` / `get_unicode_strings` 重写为 `std::regex` 实现
- **win32.cpp**: 4 个 TODO → 实现说明
- **winemu.cpp**: 1 个 TODO → 实现说明

#### Fixed

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

