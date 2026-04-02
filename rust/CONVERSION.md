# Speakeasy Python to Rust Conversion Guide

## Overview

This document provides a comprehensive guide for converting the Speakeasy Windows malware emulation framework from Python to Rust.

## Architecture Comparison

### Python Architecture
```
speakeasy/
├── cli.py                 # CLI interface
├── speakeasy.py          # Main API wrapper
├── binemu.py             # Binary emulation
├── windows/              # Windows subsystems
│   ├── winemu.py        # Emulator
│   ├── fileman.py       # File manager
│   ├── regman.py        # Registry manager
│   ├── netman.py        # Network manager
│   └── ...
├── winenv/              # Windows environment
│   ├── api/            # API handlers
│   ├── defs/           # Windows definitions
│   └── ...
└── tests/              # Test suite
```

### Rust Architecture
```
speakeasy-rust/
├── src/
│   ├── lib.rs               # Library entry point
│   ├── bin/cli.rs          # CLI binary
│   ├── config.rs           # Configuration
│   ├── emulator/           # Core emulation
│   │   ├── mod.rs
│   │   ├── memory.rs
│   │   ├── cpu.rs
│   │   └── modules.rs
│   ├── windows/            # Windows subsystems
│   │   ├── api/
│   │   ├── kernel.rs
│   │   ├── file_system.rs
│   │   ├── registry.rs
│   │   ├── network.rs
│   │   └── objects.rs
│   ├── peparser.rs        # PE file parsing
│   ├── profiler.rs        # Performance profiling
│   ├── report.rs          # Report generation
│   ├── error.rs           # Error types
│   └── utils.rs           # Utilities
├── tests/                 # Test suite
└── Cargo.toml
```

## Key Conversions

### 1. Configuration System

**Python:**
```python
config = SpeakeasyConfig(
    memory=MemoryConfig(stack_size=0x200000),
    modules=ModuleConfig(load_base=0x400000)
)
```

**Rust:**
```rust
let config = SpeakeasyConfig::default();
config.memory.stack_size = 2 * 1024 * 1024;
config.modules.load_base = 0x400000;
```

### 2. Error Handling

**Python:**
```python
try:
    se = Speakeasy()
except SpeakeasyError as e:
    logger.error("Error: %s", str(e))
```

**Rust:**
```rust
match Speakeasy::new(None) {
    Ok(emulator) => { /* ... */ },
    Err(e) => eprintln!("Error: {}", e),
}
```

### 3. Memory Management

**Python:**
```python
addr = se.allocate_memory(0x1000)
se.write_memory(addr, b"\x90" * 16)
data = se.read_memory(addr, 16)
```

**Rust:**
```rust
let addr = memory.allocate(0x1000)?;
memory.write(addr, &[0x90u8; 16])?;
let data = memory.read(addr, 16)?;
```

### 4. Module Loading

**Python:**
```python
module = se.load_module("sample.dll")
se.run_module(module)
```

**Rust:**
```rust
let module_name = emulator.load_module("sample.dll")?;
emulator.run_module(&module_name)?;
```

### 5. API Handlers

**Python:**
```python
def kernel32_CreateFileA(se, args):
    filename = se.read_string(args[0])
    # ... implementation
    return handle

se.hook_api("CreateFileA", kernel32_CreateFileA)
```

**Rust:**
```rust
pub struct CreateFileHandler;

impl ApiHandler for CreateFileHandler {
    fn call(&mut self, args: &[u64]) -> u64 {
        // Read string from memory
        // ... implementation
        0xFFFFFFFF
    }

    fn get_name(&self) -> &str {
        "CreateFileA"
    }
}
```

## Migration Path

### Phase 1: Foundation (IM Complete)
✅ Project structure  
✅ Configuration system  
✅ Error handling  
✅ Report generation  

### Phase 2: Core Engine (In Progress)
✅ Memory manager (basic)  
✅ CPU emulator (shell)  
✅ Module manager (basic)  
⏳ Unicorn integration  
⏳ PE parsing completion  

### Phase 3: Windows Subsystems (In Progress)
✅ Kernel management  
✅ File system (basic)  
✅ Registry (basic)  
✅ Network manager  
✅ Object manager  
⏳ Windows API implementations  

### Phase 4: API Handlers (Not Started)
⏳ Kernel32 API functions  
⏳ User32 API functions  
⏳ Network APIs (WS2_32)  
⏳ NT kernel APIs  

### Phase 5: Testing & Polish (Not Started)
⏳ Unit tests  
⏳ Integration tests  
⏳ CLI compatibility  
⏳ Performance optimization  

## Key Dependency Mappings

| Python Package | Rust Crate | Notes |
|---|---|---|
| pefile | goblin | PE file parsing |
| capstone | capstone | Disassembly |
| lznt1 | lznt1 | Compression |
| unicorn | unicorn | CPU emulation |
| pycryptodome | ring, md5 | Cryptography |
| pydantic | serde | Data validation |
| rich | colored | Console output |
| logging | log | Logging |

## Building and Running

### Build
```bash
cd rust
cargo build --release
```

### Run
```bash
./target/release/speakeasy --target sample.exe --output report.json
```

### Test
```bash
cargo test
```

## Performance Considerations

1. **Memory**: Rust's stack allocation vs Python's heap allocation
2. **String Handling**: UTF-8 vs Python's flexible string types
3. **Dynamic Dispatch**: API handlers use trait objects (slight overhead)
4. **Concurrency**: Rust's safety helps with thread safety guarantees
5. **FFI**: PE parsing may use goblin (pure Rust) vs pefile (C)

## Debugging

Enable detailed logging:
```bash
RUST_LOG=debug ./speakeasy --target sample.exe -v
```

## Next Steps

1. **Unicorn Integration**: Complete integration with CPU emulation engine
2. **PE Parsing**: Full PE header parsing with goblin
3. **API Handlers**: Implement common Windows APIs
4. **Testing**: Port Python test cases to Rust
5. **Performance**: Profile and optimize bottlenecks
6. **Compatibility**: Ensure JSON report format compatibility

## Resources

- [Rust Book](https://doc.rust-lang.org/book/)
- [Goblin PE Parsing](https://docs.rs/goblin/)
- [Unicorn Engine](https://www.unicorn-engine.org/)
- [Capstone Disassembly](https://www.capstone-engine.org/)
