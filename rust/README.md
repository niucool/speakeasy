# Speakeasy - Rust Implementation

This is a Rust rewrite of the Speakeasy Windows malware emulation framework.

## Building

```bash
cargo build --release
```

## Running

```bash
# Emulate a PE binary
./speakeasy --target sample.exe --output report.json

# Run shellcode
./speakeasy --target shellcode.bin --do-raw --arch x86

# Show help
./speakeasy --help
```

## Project Structure

- `src/lib.rs` - Main library entry point
- `src/config.rs` - Configuration management
- `src/error.rs` - Error types
- `src/report.rs` - Report generation
- `src/utils.rs` - Utility functions
- `src/emulator/` - Core emulation engine
  - `mod.rs` - Main emulator interface
  - `memory.rs` - Memory management
  - `cpu.rs` - CPU emulation
  - `modules.rs` - Module management
- `src/windows/` - Windows subsystems
  - `kernel.rs` - Kernel management
  - `file_system.rs` - Virtual filesystem
  - `registry.rs` - Registry emulation
  - `network.rs` - Network activity
  - `objects.rs` - Windows objects

## Implementation Status

### Phase 1: Foundation ✅
- [x] Project structure
- [x] Error handling
- [x] Configuration system
- [x] Report generation

### Phase 2: Core Engine (In Progress)
- [x] Memory management (basic)
- [x] CPU emulation (shell)
- [x] Module management (basic)
- [ ] Unicorn integration
- [ ] PE parsing

### Phase 3: Windows Subsystems (Started)
- [x] Kernel management
- [x] File system (basic)
- [x] Registry (basic)
- [x] Network management
- [x] Object manager

### Phase 4: API Handlers (TODO)
- [ ] Win32 API handlers
- [ ] Kernel32 functions
- [ ] Other system libraries

### Phase 5: CLI & Integration (In Progress)
- [x] CLI argument parsing
- [x] Basic commands
- [ ] Full feature parity

## Dependencies

- unicorn - CPU emulation
- goblin - PE file parsing
- capstone - Disassembly
- serde/serde_json - Serialization
- clap - CLI parsing
- Various utility crates

## Next Steps

1. Integrate Unicorn CPU emulator
2. Implement PE file parsing with goblin
3. Create API hook system
4. Implement Win32 API handlers
5. Add comprehensive testing
6. Performance optimization
