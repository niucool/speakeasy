# Speakeasy Rust Implementation - Index

## Getting Started

1. **New to Speakeasy?**
   - Start with [README.md](README.md) - Feature overview
   - Then [QUICKSTART.md](QUICKSTART.md) - Usage examples
   
2. **Installing from Source?**
   - Follow [INSTALL.md](INSTALL.md) - Detailed setup guide
   - Use `cargo build --release` for optimized build

3. **Migrating from Python?**
   - Read [CONVERSION.md](CONVERSION.md) - Complete API mapping and architecture comparison

## Documentation

### User Documentation
- [README.md](README.md) - Overview and features
- [QUICKSTART.md](QUICKSTART.md) - Quick start guide with examples
- [INSTALL.md](INSTALL.md) - Installation and troubleshooting
- [CLI Reference](../doc/cli-reference.md) - CLI options and usage

### Developer Documentation
- [DEVELOPMENT.md](DEVELOPMENT.md) - Build, test, and development workflow
- [CONVERSION.md](CONVERSION.md) - Architecture and API reference
- [TODO.md](TODO.md) - Task tracking and roadmap
- [Architecture Documentation](src/arch.rs) - Internal design details

### Configuration
- Default configuration: [SpeakeasyConfig](src/config.rs)
- Examples: [config.rs](src/config.rs#L6-L50)

## Code Structure

### Core Libraries
- [lib.rs](src/lib.rs) - Library entry point and module declarations
- [error.rs](src/error.rs) - Error types and handling
- [config.rs](src/config.rs) - Configuration system
- [report.rs](src/report.rs) - Report generation and structures
- [peparser.rs](src/peparser.rs) - PE file parsing
- [profiler.rs](src/profiler.rs) - Performance profiling
- [utils.rs](src/utils.rs) - Utility functions

### Emulation Engine
- [emulator/mod.rs](src/emulator/mod.rs) - Main Speakeasy class
- [emulator/memory.rs](src/emulator/memory.rs) - Memory manager
- [emulator/cpu.rs](src/emulator/cpu.rs) - CPU emulation
- [emulator/modules.rs](src/emulator/modules.rs) - Module loading

### Windows Subsystems
- [windows/mod.rs](src/windows/mod.rs) - Windows module organization
- [windows/kernel.rs](src/windows/kernel.rs) - Kernel services
- [windows/file_system.rs](src/windows/file_system.rs) - Virtual filesystem
- [windows/registry.rs](src/windows/registry.rs) - Registry emulation
- [windows/network.rs](src/windows/network.rs) - Network stubs
- [windows/objects.rs](src/windows/objects.rs) - Object management
- [windows/api/mod.rs](src/windows/api/mod.rs) - API dispatcher
- [windows/api/kernel32.rs](src/windows/api/kernel32.rs) - Kernel32 stubs
- [windows/api/user32.rs](src/windows/api/user32.rs) - User32 stubs
- [windows/api/ws2_32.rs](src/windows/api/ws2_32.rs) - Winsock stubs
- [windows/api/ntoskrnl.rs](src/windows/api/ntoskrnl.rs) - NT Kernel stubs

### CLI Application
- [bin/cli.rs](src/bin/cli.rs) - Command-line interface

### Tests
- [tests/unit.rs](tests/unit.rs) - Unit tests
- [tests/integration.rs](tests/integration.rs) - Integration tests

## Building and Running

### Quick Build
```bash
# Debug build
cargo build

# Release build
cargo build --release

# Run tests
cargo test

# Generate documentation
cargo doc --open

# Code quality checks
cargo fmt
cargo clippy
```

### Running Speakeasy
```bash
# Emulate a PE binary
speakeasy --target sample.exe --output report.json

# Emulate shellcode
speakeasy --target shellcode.bin --do-raw --arch x86

# With custom config
speakeasy --target sample.exe --config config.json

# Verbose output
speakeasy --target sample.exe -v
```

### Using Make (if available)
```bash
make help        # Show available targets
make build       # Build debug
make release     # Build release
make test        # Run tests
make check       # Format, lint, compile
make doc         # Generate docs
```

## Key Classes and Interfaces

### Speakeasy (Main API)
```rust
impl Speakeasy {
    fn new(config: Option<SpeakeasyConfig>) -> Result<Self>
    fn load_module(&self, path: &str) -> Result<String>
    fn run_module(&self, module_name: &str) -> Result<()>
    fn load_shellcode(&self, data: &[u8], arch: &str) -> Result<u64>
    fn run_shellcode(&self, address: u64) -> Result<()>
    fn get_report(&self) -> Report
    fn get_json_report(&self) -> Result<String>
    fn shutdown(&mut self) -> Result<()>
}
```

### SpeakeasyConfig
```rust
pub struct SpeakeasyConfig {
    pub memory: MemoryConfig,
    pub modules: ModuleConfig,
    pub file_system: FileSystemConfig,
    pub registry: RegistryConfig,
    pub network: NetworkConfig,
    pub api: ApiConfig,
    pub process: ProcessConfig,
    pub logging: LoggingConfig,
    pub env_vars: HashMap<String, String>,
}
```

### Report
```rust
pub struct Report {
    pub sha256: String,
    pub filetype: String,
    pub arch: String,
    pub entry_points: Vec<EntryPoint>,
    pub modules: Vec<ModuleInfo>,
    pub api_calls: Vec<ApiCall>,
    pub file_accesses: Vec<FileAccess>,
    pub registry_accesses: Vec<RegistryAccess>,
    pub network_activity: Vec<NetworkActivity>,
    pub stats: ExecutionStats,
}
```

## Common Tasks

### Add a New API Handler
1. Create struct in `src/windows/api/`
2. Implement `ApiHandler` trait
3. Register in `ApiDispatcher`
4. Add tests

### Add Configuration Option
1. Add field to config struct in [config.rs](src/config.rs)
2. Add CLI argument in [cli.rs](src/bin/cli.rs)
3. Update default configuration
4. Document in README

### Debug an Issue
1. Enable logging: `RUST_LOG=debug`
2. Build debug: `cargo build`
3. Run with backtrace: `RUST_BACKTRACE=1`
4. Check error type in [error.rs](src/error.rs)

## Project Status

### Phase 1: Foundation ✅
- Project setup complete
- All core infrastructure in place

### Phase 2: Core Engine 🔄
- Basic memory and CPU shells
- Module manager functional
- Unicorn integration pending

### Phase 3: Windows Subsystems 🔄
- Basic implementations complete
- API stubs in place
- Full implementations pending

### Phase 4: API Handlers ⏳
- Handler framework ready
- Function stubs created
- Implementations needed

### Phase 5: Testing & Polish ⏳
- Basic tests in place
- Comprehensive testing needed
- Performance optimization pending

## Important Links

- **GitHub Repository**: https://github.com/mandiant/speakeasy
- **Original Python Project**: https://github.com/mandiant/speakeasy
- **Mandiant Blog**: https://cloud.google.com/blog/topics/threat-intelligence/
- **Rust Book**: https://doc.rust-lang.org/book/
- **Cargo Manual**: https://doc.rust-lang.org/cargo/

## FAQ

**Q: Why Rust instead of Python?**  
A: Rust provides better performance, memory safety, and static analysis while providing the same high-level API abstraction.

**Q: Will this be compatible with Python bindings?**  
A: Not in the initial release, but could be added later using PyO3.

**Q: Can I use this with existing Python scripts?**  
A: The CLI maintains compatibility, but library usage would require calling via subprocess.

**Q: What about performance?**  
A: Rust should provide similar or better performance than Python, especially for CPU-intensive emulation.

**Q: How complete is it?**  
A: Currently Phase 2-3, with basic functionality working. See [TODO.md](TODO.md) for detailed status.

## Support

- **Issues**: https://github.com/mandiant/speakeasy/issues
- **Discussions**: https://github.com/mandiant/speakeasy/discussions
- **Docs**: All files in this directory

## Contributing

See [DEVELOPMENT.md](DEVELOPMENT.md) for contribution guidelines.

---

**Rust Implementation Status**: In Development  
**Target**: Phase 5 completion  
**Last Updated**: April 2026
