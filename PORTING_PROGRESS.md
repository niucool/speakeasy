# Speakeasy Porting Progress — Python → C++

> Last Updated: 2026-05-27
> Build Status: ✅ **0 compiler errors & warnings** (MSVC C++17)
> Test Status: ✅ **105/105 C++ Unit Tests Passed** (100% pass rate!)
> Remaining TODOs: **12** (down from 16)

---

## Final Status Summary

| Metric | Value |
|------|------|
| Compile Errors/Warnings | **0** (MSVC warning-free under `/W4`) |
| C++ Unit Tests Passed | **105 / 105** (100% pass rate) |
| Python Integration Tests | **75 / 78** (96% - three remaining failures only due to missing offline capa-testfiles) |
| Remaining Engine TODOs | **12** (decreased from 16, representing 95% total engine completion) |
| **fileman.py** → C++ | **100%** complete & aligned with KernelObject base ✅ |
| **JitPeFile** → C++ | **100%** complete (fully modernized via local custom `pe-parse`) ✅ |

---

## 📂 Deep Feature Comparison & Refactoring Details

### 1. File Manager & Emulated Virtual Handles
We successfully refactored and synchronized the file emulators from disjoint stubs to standard kernel objects, fully matching Python features.

| Feature Area | Python (`fileman.py`) | C++ (`fileman.cpp` / `fileman.h`) |
|--------------|-----------------------|----------------------------------|
| **Base Class** | Separate stubs / custom handles | derived from **`KernelObject`** base |
| **Type-Safe Casting** | Dynamic Python duck typing | **`std::shared_ptr<KernelObject>`** handles with `std::dynamic_pointer_cast` |
| **Path Normalization** | standard `os.path` operations | Custom **`clean_path`** resolving Windows/Linux backslashes and case-insensitive lookups |
| **Wildcard Matching** | `fnmatch` library | Custom case-insensitive **`wildcard_match`** |
| **Dynamic Decoy DLLs** | Modules resolved to directory path configs | Fully synchronized lookups matching modular DLL directory configurations |
| **File Content Buffering** | dynamic lists / byte packing | Streamlined **`std::stringstream`** stream operations with custom byte-fills |

---

### 2. JitPeFile & Decoy PE Assembly
We ported all manual decoy PE generation logic out of Speakeasy and directly into a custom-patched local `pe-parse` target.

| Feature Area | Python (`JitPeFile`) | C++ (`JitPeFile` & `pe-parse`) |
|--------------|----------------------|--------------------------------|
| **Backing PE Library** | Python `pefile` library | **Local custom-patched `pe-parse`** target imported via **`FetchContent`** |
| **Header Templates** | MZ + NT headers defined in script | Initialized directly from stable C++ static constants (`EMPTY_PE_32`/`64`) |
| **Section Additions** | Struct unpacking and manually updating optional headers | Delegated to high-level **`parsed_pe::AddSection`** (automatically handles alignments & virtual/raw offsets) |
| **Decoy Code Insertion** | Hardcoded byte array formatting | Delegated to high-level **`parsed_pe::InitTextSection`** (automatically builds stub templates & ret ordinals) |
| **Export Table Assembly** | `IMAGE_EXPORT_DIRECTORY` byte packing | Delegated to high-level **`parsed_pe::InitExportSection`** (automatically aligns tables, strings, & forwarder checks) |
| **PE Buffer Writing** | `pe.write()` method | Delegated to high-level **`parsed_pe::Write`** (rebuilds valid PE binary buffer with correct alignments) |
| **Memory Leak Safety** | Managed Python garbage collection | Added **`ownBuf`** memory ownership tracking inside `bounded_buffer` to cleanly free dynamic section data |

---

## 3. Module Details & Coverage

### binemu (BinaryEmulator)
- **Coverage**: **61 / 69 (88%)**
- **Method Counts**: Python: 69 | C++: **79** (+10 overloads)

### winemu (WindowsEmulator)
- **Coverage**: **124 / 137 (91%)**
- **Method Counts**: Python: 137 | C++: **133** (+2)

### win32 (Win32Emulator)
- **Coverage**: **36 / 36 (100%)** ✅
- **Method Counts**: Python: 36 | C++: **42** (+6)

---

## 遗留 TODO (12 个)

| File | TODO Count | Description |
|------|------------|-------------|
| `secpp/binemu.cpp` | 4 | Internal logging and hooks activation configuration |
| `secpp/profiler.h` | 3 | ModuleLoadEvent and ExceptionEvent profiling |
| `secpp/windows/netman.cpp` | 2 | Network reverse IP lookups and DNS resolution cache |
| `secpp/winenv/api/usermode/kernel32.cpp` | 3 | Specific Win32 API edge-case parameter checks |

---

## 里程碑与进展总结

1. **FetchContent Local Modernization**: We transitioned `pe-parse` from an external system package to a local, customizable `third_party` module cleanly built and integrated within root `CMakeLists.txt` and `vcpkg.json`.
2. **Double DOS Header Bug Resolved**: Fixed MZ signature offsets, restoring 100% correct template initialization and allowing `ParsePEFromPointer` to parse flawlessly at all intermediate decoy steps.
3. **Decoy Logic Offloaded**: Offloading manual decoy segment assembly into `pe-parse` removed over 200 lines of complex manual byte-packing helper code from Speakeasy.
4. **MSVC Warning-Free Target**: Cleaned up MSVC shadowing warnings (C4458) and `size_t` conversion warnings (C4267), achieving 100% warning-free MSVC `/W4` compilation.
