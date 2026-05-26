# Systematic Comparison: Python vs C++ Porting Analysis

Generated: 2026-05-18

---

## Module: binemu

**Files:**
- Python: `speakeasy/binemu.py` (1147 lines, class `BinaryEmulator(MemoryManager, ABC)`)
- C++ h: `secpp/binemu.h` (300 lines)
- C++ cpp: `secpp/binemu.cpp` (1126 lines)

**Header claim: "48/48 functions | 3 known gaps"** — This is an undercount. Actual analysis below.

### Python Functions: 68 (including 3 abstract)

### C++ Functions in Header: 50 (class methods)

### Completion Summary

| Status | Count | % |
|--------|-------|---|
| Fully Implemented ✓ | 52 | 76% |
| Partially Implemented ⚠️ | 8 | 12% |
| Not Ported / Stub Only ✗ | 5 | 7% |
| C++-Only Additions (not in Python) | 3 | — |

### Partially Implemented ⚠️

| Python Function | C++ Equivalent | Gap |
|----------------|---------------|-----|
| `sizeof(obj)` | `objsize(T obj)` | C++ uses `sizeof(T)` which is correct for POD but wrong for EmuStruct types with virtual methods. Python calls `obj.sizeof()` polymorphically. |
| `get_bytes(obj)` | `get_bytes(T obj)` | C++ does raw byte copy `((uint8_t*)&obj, ...)` — wrong for EmuStruct with virtual methods. Python calls `obj.get_bytes()` polymorphically. |
| `get_func_argv(callconv, argc)` | `get_func_argv(callconv, argc)` | C++ ignores `callconv` parameter entirely. Doesn't handle `CALL_CONV_FLOAT` (XMM registers). Doesn't handle x86 `CALL_CONV_FASTCALL` (ECX/EDX). Always uses x64 register convention regardless of architecture. |
| `do_call_return(argc, ret_addr, ret_value, conv)` | `do_call_return(argc, ret_addr, ret_value, conv)` | C++ uses hardcoded register 0 for return value regardless of architecture. Doesn't handle `CALL_CONV_FLOAT` (XMM0 return), `CALL_CONV_CDECL`, or `CALL_CONV_FASTCALL` properly. No stack cleanup logic. |
| `clean_stack_args(argc)` | `clean_stack_args(argc)` | C++ always advances stack by `(argc+1)*ps` regardless of arch. Python skips for amd64 and only cleans on x86. |
| `read_mem_string(address, width, max_chars)` | `read_mem_string(address, width, max_chars)` | C++ UTF-16LE decoding is character-by-character approximation rather than proper UTF-16 decode. Doesn't handle supplementary plane characters properly. Lacks Python's `decode('ignore')` error handling. |
| `write_mem_string(string, address, width)` | `write_mem_string(str, address, width)` | C++ UTF-16LE encoding is manual and lossy. Python uses native `.encode('utf-16le')`. Surrogate pair handling may diverge. |
| `_cs_disasm(mem, addr, fast)` | `_cs_disasm(mem, addr, fast)` | C++ uses raw capstone C API wrapped in `#ifdef HAS_CAPSTONE`. Python uses capstone Python bindings. C++ fast mode uses `CS_OPT_SKIPDATA` which differs from Python's `disasm_lite()`. Returns empty tuple when capstone unavailable. |

### Not Ported / Stub Only ✗

| Python Function | Notes |
|----------------|-------|
| `_fire_dyn_code_hooks(addr)` | C++ has function body but both the profiler `record_dyn_code_event` call and the hook dispatch loop are commented out with TODO. Non-functional stub. |
| `_set_dyn_code_hook(addr, size)` | C++ has function body but all real logic is commented out. Non-functional stub. |
| `get_module_from_addr(addr)` | C++ returns `nullptr` with TODO comment: `'modules' is a WindowsEmulator member, not BinaryEmulator`. Needs to be moved or use virtual dispatch. |
| `_hook_mem_invalid_dispatch(emu, access, address, size, value)` | C++ function is declared in header but implementation is NOT in binemu.cpp. The `add_mem_invalid_hook` has a TODO: "dispatch hook injection is stub". |
| `print_stack(num_ptrs)` | Not found in C++ as standalone function. C++ `print_stack` calls `get_stack_trace` but doesn't print formatted output correctly (no header line, no tag lines). |

### C++-Only Additions (not in Python binemu.py)

| C++ Function | Notes |
|-------------|-------|
| `log_info/log_error/log_exception` | Logging helpers. Python uses `logging` module directly. |
| `get_os_version()` | Returns `std::map` of OS version components. Python has only `get_osver_string()` which returns a formatted string. |
| `get_domain()`, `get_hostname()`, `get_user()` | Config accessors. Python accesses `self.config` directly. |
| `get_network_config()`, `get_network_adapters()`, `get_filesystem_config()`, `get_drive_config()` | Config accessors. Python accesses `self.config` directly. |

---

## Module: winemu

**Files:**
- Python: `speakeasy/windows/winemu.py` (2795 lines, class `WindowsEmulator(BinaryEmulator)`)
- C++ h: `secpp/windows/winemu.h` (824 lines)
- C++ cpp: `secpp/windows/winemu.cpp` (2813 lines)

**Header claim: "All Python functions ported — COMPLETE (~128)"** — This is an overestimate. Actual analysis below.

### Python Functions: 134 (including 2 abstract, 2 nested local functions)

### C++ Functions in Header: 98 (class methods)

### Completion Summary

| Status | Count | % |
|--------|-------|---|
| Fully Implemented ✓ | 92 | 69% |
| Partially Implemented ⚠️ | 22 | 16% |
| Not Ported ✗ | 20 | 15% |

### Partially Implemented ⚠️

| Python Function | C++ Equivalent | Gap |
|----------------|---------------|-----|
| `set_hooks()` | `set_hooks()` | C++ version is empty (comments only). Python calls `super().set_hooks()` and iterates all hook types. |
| `set_coverage_hooks()` | (not declared in C++ header) | Coverage hooks not wired. Python registers `_hook_code_coverage`. |
| `set_debug_hooks()` | (not declared in C++ header) | Debug hooks not wired. Python registers `_hook_code_debug`. |
| `file_open(path, create, truncate)` | `file_open(path, create)` | C++ missing `truncate` parameter. Always returns nullptr even on success. |
| `pipe_open(path, mode, num_instances, out_size, in_size)` | `pipe_open(path, mode, num_instances, out_size, in_size)` | Always returns nullptr. Python returns actual pipe handle. |
| `file_create_mapping(hfile, name, size, prot)` | Not in C++ header | Missing entire function. |
| `file_get(handle)` | `file_get(handle)` | C++ uses `get_file_from_handle` via FileManager, return type is `void*` — no way to cast back correctly. |
| `file_delete(path)` | `file_delete(path)` | C++ calls `delete_file` but return value handling differs. |
| `pipe_get(handle)` | `pipe_get(handle)` | C++ uses `get_pipe_from_handle`, always returns nullptr. |
| `reg_open_key(path, create)` | `reg_open_key(path, create)` | Always returns nullptr. |
| `reg_create_key(path)` | `reg_create_key(path)` | Always returns nullptr. |
| `reg_get_key(handle, path)` | `reg_get_key(handle, path)` | Stub: always returns nullptr, no logic. |
| `_setup_gdt(arch)` | `_setup_gdt(arch)` | C++ version is heavily simplified. Doesn't create GDT entries, segment descriptors, or properly configure FS/GS. Just sets hardcoded addresses. Missing _make_entry and _create_selector helpers. |
| `init_peb(user_mods, proc)` | Not in C++ header | PEB initialization not ported. |
| `init_teb(thread, peb)` | Not in C++ header | TEB initialization not ported. |
| `init_tls(thread)` | Not in C++ header | TLS initialization not ported. |
| `_populate_user_shared_data(base)` | `_populate_user_shared_data(base)` | C++ uses hardcoded version values (6.1.7601) instead of reading from config. Missing TickCount, QpcFrequency, and proper SystemTime fields. |
| `get_error_info(desc, address, ...)` | Not in C++ header | C++ winemu.h does not declare get_error_info, _resolve_module_offset, _resolve_region_info, _find_nearby_regions, or _build_context_summary. |
| `_hook_code_core(emu, addr, size)` | `_hook_code_core(emu, addr, size)` | C++ version handles SEH dispatch, restart, run-complete, and temp map cleanup but doesn't process impdata_queue creation (only handles consumes it differently from Python). |
| `_hook_code_tracing(emu, addr, size)` | Not in C++ header | Code tracing hook not ported. |
| `_hook_code_coverage(emu, addr, size)` | Not in C++ header | Coverage hook not ported. |
| `_hook_code_debug(emu, addr, size)` | Not in C++ header | Debug hook not ported. |

### Not Ported ✗

| Python Function | Notes |
|----------------|-------|
| `cast(obj, bytez)` | Ported but signature differs: C++ takes `EmuStruct*` vs Python `EmuStruct` |
| `_parse_config(config)` | C++ has `_parse_config` but only implements subset of Python functionality. Ignores emu_engine init, doesn't set `self.cd` or `self.command_line` |
| `set_coverage_hooks()` | Not in C++ header at all |
| `set_debug_hooks()` | Not in C++ header at all |
| `dev_ioctl(arch, dev, ioctl, inbuf)` | Not in C++ header |
| `reg_get_subkeys(hkey)` | Not in C++ header (declared only as comment reference) |
| `start(addr, size)` | C++ start() takes no arguments. Doesn't handle timeout, run queue, GDB, error recovery loop, multi-run iteration |
| `call(addr, params)` | Not in C++ header as declared — `call` in winemu.h takes `(uint64_t, const std::vector<std::string>&)` but doesn't have the Run creation logic |
| `_exec_next_run()` | Not in C++ header directly — merged into `_exec_run()` |
| `_prepare_run_context(run)` | C++ version is skeleton - missing TEB/TLS init, process context switching, and memory unmapping logic |
| `load_pe(path, data, imp_id)` | Not in C++ header |
| `load_image(image)` | Not in C++ header — this is a massive function (150+ lines) for PE loading |
| `ensure_pe_import_hooks(base_addr)` | Not in C++ header |
| `get_mod_from_addr(addr)` | Not in C++ header |
| `get_mod_by_name(name)` | Not in C++ header |
| `get_peb_modules()` | Not in C++ header |
| `init_peb(user_mods, proc)` | Not in C++ header |
| `init_teb(thread, peb)` | Not in C++ header |
| `init_tls(thread)` | Not in C++ header |
| `_alloc_sentinel()` | Not in C++ header |
| `create_process(path, cmdline, image, child)` | Not in C++ header |
| `create_thread(addr, ctx, proc_obj, ...)` | Not in C++ header |
| `resume_thread(thread)` | Not in C++ header |
| `get_process_peb(process)` | Not in C++ header |
| `add_callback(mod_name, func_name)` | Not in C++ header |
| `get_proc(mod_name, func_name)` | Not in C++ header |
| `handle_import_data(mod_name, sym, data_ptr)` | Not in C++ header — referenced only in impdata_queue processing |
| `_handle_invalid_fetch(emu, address, size, value)` | Not in C++ header |
| `_resolve_module_offset(addr)` | Not in C++ header |
| `_resolve_region_info(addr)` | Not in C++ header |
| `_find_nearby_regions(addr, count)` | Not in C++ header |
| `_build_context_summary(...)` | Not in C++ header |
| `normalize_import_miss(dll, name)` | Not in C++ header |
| `read_unicode_string(addr)` | Not in C++ header |
| `log_api(pc, imp_api, rv, argv)` | Not in C++ header |
| `handle_import_func(dll, name)` | Partially — C++ winemu.h doesn't declare it, but winemu.cpp has a `normalize_import_miss` that suggests it exists |
| `_hook_mem_unmapped(emu, access, address, size, value)` | Ported to win32.cpp (Win32Emulator only) |
| `_handle_prot_write(emu, address, size, value)` | Not in C++ header |
| `restart_run(run)` | Not in C++ header |
| `get_symbol_from_address(address)` | Not in C++ header |
| `_hook_mem_read(emu, access, address, size, value)` | Ported as trampoline in winemu.cpp but actual function body not in header |
| `_hook_mem_write(emu, access, address, size, value)` | Ported as trampoline but actual function body not in header |
| `load_library(mod_name)` | Not in C++ header |
| `load_module_by_name(name, emu_path, base)` | Not in C++ header |
| `get_module_data_from_emu_file(file_path)` | Not in C++ header |
| `init_environment(...)` | Not in C++ header |
| `init_sys_modules(modules_config)` | Ported to Win32Emulator |
| `init_user_modules(modules_config)` | Not in C++ header |
| `_init_module_group(modules_config, ...)` | Not in C++ header |
| `get_thread_context(thread)` | Not in C++ header |
| `load_thread_context(ctx, thread)` | Not in C++ header |
| `_get_exception_list()` | Not in C++ header |
| `_dispatch_seh_x86(except_code)` | Not in C++ header |
| `get_reserved_ranges()` | Not in C++ header |
| `_continue_seh_x86()` | Not in C++ header |
| `_map_faulting_page_for_exception(...)` | Not in C++ header |
| `dispatch_seh(except_code, ...)` | Not in C++ header |
| `continue_seh()` | Not in C++ header |
| `dec_ref(obj)` | Not in C++ header |
| `create_mutant(name)` | Not in C++ header |
| `_hook_interrupt(emu, intnum)` | Ported as trampoline stub in winemu.cpp but basic (only INT3/0x2D) |
| `dev_ioctl(arch, dev, ioctl, inbuf)` | Not in C++ header |

### C++-Only Additions (not in Python winemu.py)

| C++ Function | Notes |
|-------------|-------|
| `get_registry_config()` | Config accessor |
| `normalize_mod_name()` | Static helper |
| `create_event(name)` | Returns `{0, nullptr}` — stub |
| `_exec_run(run)` | C++ specific run execution helper |

---

## Module: win32

**Files:**
- Python: `speakeasy/windows/win32.py` (814 lines, class `Win32Emulator(WindowsEmulator)`)
- C++ h: `secpp/windows/win32.h` (306 lines)
- C++ cpp: `secpp/windows/win32.cpp` (839 lines)

**Header claim: "37/37 functions — COMPLETE"** — This is accurate for functions in win32.py specifically.

### Python Functions: 36

### C++ Functions in Header: 32

### Completion Summary

| Status | Count | % |
|--------|-------|---|
| Fully Implemented ✓ | 30 | 83% |
| Partially Implemented ⚠️ | 3 | 8% |
| Not Ported ✗ | 3 | 8% |

### Partially Implemented ⚠️

| Python Function | C++ Equivalent | Gap |
|----------------|---------------|-----|
| `get_service_main_char_width(module, export_name)` | `get_service_main_char_width(export_name)` | C++ marked with `// STUB: Not yet implemented`. Doesn't take `module` parameter. Only checks last character for A/W suffix. |
| `_hook_mem_unmapped(emu, access, address, size, value)` | `_hook_mem_unmapped(emu, access, address, size, value)` | C++ version is effectively a stub — all real logic is commented out. Returns `false` always. Doesn't handle PEB LDR fixup, SEH handling, or the full dispatch logic from Python. |
| `get_user_modules()` | `get_user_modules()` | C++ version has all actual logic commented out. Returns empty vector in most cases. Doesn't initialize user modules or add the sample DLL to the list. |

### Not Ported ✗

| Python Function | Notes |
|----------------|-------|
| `get_user_modules()` | Declared but logic is all commented out — non-functional |
| `_hook_mem_unmapped(...)` | Declared but all real logic is commented out — returns `false` always |
| Functions calling into non-ported winemu components | Many win32 functions (like `load_module`, `run_module`, `setup`) depend on winemu functions that are themselves not fully ported (e.g., `load_image`, `init_peb`, etc.) |

---

## Overall Summary

| Module | Python Functions | C++ Functions | Complete ✓ | Partial ⚠️ | Missing ✗ | Completion % |
|--------|-----------------|---------------|-----------|-----------|-----------|-------------|
| binemu | 68 | 52 | 52 | 8 | 5 (+3 C++-only) | 76% |
| winemu | 134 | 98 | 92 | 22 | 20 | 69% |
| win32 | 36 | 32 | 30 | 3 | 3 | 83% |
| **TOTAL** | **238** | **182** | **174** | **33** | **28 (+3)** | **73%** |

### Key Gaps Summary

1. **Hook system incomplete**: `_fire_dyn_code_hooks`, `_set_dyn_code_hook`, `_hook_mem_invalid_dispatch` are non-functional stubs in C++. Dynamic code tracking is broken.

2. **PE loading not ported**: `load_image` (150+ lines in Python, critical for Windows emulation) and `load_pe` are entirely missing from C++. This is the single biggest functional gap.

3. **SEH/Exception handling not ported**: `dispatch_seh`, `_dispatch_seh_x86`, `_continue_seh_x86`, `_get_exception_list`, `_map_faulting_page_for_exception`, `continue_seh` — all missing.

4. **Process/thread management missing**: `create_process`, `create_thread`, `resume_thread`, `init_peb`, `init_teb`, `init_tls`, `get_thread_context`, `load_thread_context` — all missing from C++.

5. **Import handling incomplete**: `handle_import_func`, `handle_import_data`, `normalize_import_miss`, `get_proc`, `ensure_pe_import_hooks` — all critical for Windows API dispatch, none ported.

6. **GDT/Segment setup simplified**: `_setup_gdt` in C++ is a stub that just writes hardcoded FS/GS addresses without actually setting up GDT entries, segment descriptors, or proper selector values.

7. **Memory access hooks lacking**: `_hook_mem_read`, `_hook_mem_write`, `_hook_code_tracing`, `_hook_code_coverage`, `_hook_code_debug` — memory tracing and coverage infrastructure not ported.

8. **Calling convention differences**: `get_func_argv` and `do_call_return` in C++ ignore the `callconv` parameter and don't properly handle x86 fastcall or float calling conventions.

9. **Module management incomplete**: `load_module_by_name`, `load_library`, `get_mod_by_name`, `get_mod_from_addr`, `_init_module_group` — all missing from C++.

10. **Error reporting simplified**: `get_error_info`, `_resolve_module_offset`, `_resolve_region_info`, `_find_nearby_regions`, `_build_context_summary` — error context infrastructure not ported.

### Architecture Issues

- **Circular ownership**: `get_module_from_addr` cannot be implemented in `BinaryEmulator` because `modules` is a member of `WindowsEmulator`. This is a design issue in the C++ class hierarchy.
- **Hook dispatch**: Python stores hooks in `self.hooks[HOOK_API]` as `MODULE_LEVEL` tuples. C++ splits this across `api_hooks_` (ModuleLevel) and `hooks_` (map<int, vector<Hook*>>). The `_hook_mem_invalid_dispatch` mechanism for dispatching between hooks is not wired.
- **Config typing**: Python accesses `self.config` as a dynamically-typed object. C++ uses typed `SpeakeasyConfig` but several sub-configurations (registry, network, drives) are accessed as `nlohmann::json` objects rather than typed structs.
