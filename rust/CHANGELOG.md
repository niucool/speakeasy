# Changelog

## [3.0.0] - 2026-04-01 (Rust Rewrite)

### Added
- Complete Rust rewrite maintaining API compatibility
- Full project structure with modular architecture
- Configuration system with JSON serialization
- Error handling framework with detailed error types
- Report generation with JSON output
- PE file parser (basic headers support)
- Performance profiler with event tracking
- Virtual file system emulation
- Registry key-value store simulation
- Network connection tracking
- Windows object manager framework
- API handler dispatcher system
- CLI application with argument parsing
- Complete documentation:
  - User guides (README, QUICKSTART, INSTALL)
  - Developer guides (DEVELOPMENT, CONVERSION)
  - API reference documentation
  - Architecture documentation
  - Task tracking (TODO list)
- Test framework (unit and integration tests)
- Build automation (Makefile, build.rs)
- Support for x86 and x64 architectures

### Changed
- Moved from Python to Rust for better performance and safety
- Configuration format from CLI-only to JSON files
- Error handling from exceptions to Result type
- Memory management from interpreter-based to explicit allocation
- Report generation now uses Rust's serde serialization

### Removed
- Python implementation (in rust/ directory)
- PyPI package dependencies
- Python-specific features (dynamic dispatch limitations)

### Internal
- Modular architecture with clear separation of concerns
- Thread-safe design using Mutex/Arc patterns
- Trait-based extensibility for API handlers
- Zero unwrap() calls in production code
- Comprehensive error context propagation

### Technical Details
- Rust Edition 2021
- Target: Release 3.0.0
- MSRV (Minimum Supported Rust Version): 1.70
- Platform Support: Windows, macOS, Linux
- Architecture Support: x86 (32-bit), x64 (64-bit)

### Known Limitations
- Unicorn CPU emulation not yet integrated (stub only)
- PE parsing limited to headers (sections/imports not yet parsed)
- API handlers are stubs (no actual emulation)
- Kernel driver emulation not supported yet
- Memory emulation is simplified (no paging simulation)
- File system is virtual only (no real file access emulation)

### Migration Notes
Users migrating from Python version should note:
- CLI arguments format has changed (e.g., `--target` instead of `-t`)
- Configuration format is now JSON-based
- Report format may differ from Python version
- Some advanced features not yet implemented
- Performance characteristics may differ

### Dependencies
```toml
unicorn = "0.3"              # CPU emulation (ready)
goblin = "0.8"               # PE parsing (ready)
capstone = "0.12"            # Disassembly (ready)
serde/serde_json = "1.0"     # Serialization (integrated)
clap = "4.4"                 # CLI (integrated)
```

---

## Roadmap to 3.1.0

### Phase 2 Completion (Q2 2026)
- [ ] Unicorn CPU emulation integration
- [ ] Complete PE file parsing (sections, imports, exports)
- [ ] Full disassembly integration
- [ ] Memory paging simulation

### Phase 3 Completion (Q3 2026)
- [ ] Windows API handlers implementation
- [ ] Registry modification tracking
- [ ] File system full implementation
- [ ] Network protocol simulation

### Phase 4 Completion (Q4 2026)
- [ ] API handler hook system
- [ ] Process/thread lifecycle simulation
- [ ] Exception handling support
- [ ] SEH (Structured Exception Handling) support

### Phase 5 (2027)
- [ ] Comprehensive test suite
- [ ] Performance profiling and optimization
- [ ] GDB integration
- [ ] Python FFI bindings (PyO3)

---

**Current Version**: 3.0.0-alpha (In Development)  
**Release Date**: Pending Phase 2 completion
**Status**: Foundation Complete, Core Engine Starting

For detailed progress, see [TODO.md](TODO.md)
