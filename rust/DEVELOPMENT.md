# Development Guide

## Setup

### Prerequisites
- Rust 1.70+ (https://rustup.rs/)
- Windows SDK (for Windows development)
- LLVM (for Capstone disassembly)

### Initial Setup
```bash
cd rust
cargo build
```

## Building

### Debug Build
```bash
cargo build
```

### Release Build
```bash
cargo build --release
```

### With Specific Features
```bash
cargo build --features "debug-logging"
```

## Testing

### Run All Tests
```bash
cargo test
```

### Run Specific Test
```bash
cargo test test_config_default
```

### Run Integration Tests
```bash
cargo test --test integration_tests
```

### With Output
```bash
cargo test -- --nocapture
```

## Debugging

### Enable Debug Logging
```bash
RUST_LOG=speakeasy=debug cargo run -- --target sample.exe
```

### Use GDB
```bash
rust-gdb ./target/debug/speakeasy
```

### Check for Memory Issues
```bash
RUSTFLAGS="-Z sanitizer=address" cargo test
```

## Code Quality

### Format Code
```bash
cargo fmt
```

### Lint Code
```bash
cargo clippy
```

### Check All
```bash
cargo fmt -- --check
cargo clippy -- -D warnings
```

## Documentation

### Build Documentation
```bash
cargo doc --no-deps --open
```

### Document with Examples
```bash
cargo test --doc
```

## Performance Profiling

### Flamegraph
```bash
cargo install flamegraph
cargo flamegraph --bin speakeasy -- --target sample.exe
```

### Perf
```bash
cargo build --release
perf record -g ./target/release/speakeasy --target sample.exe
perf report
```

## Troubleshooting

### Build Issues
```bash
# Clean build
cargo clean
cargo build

# Check dependencies
cargo tree

# Update dependencies
cargo update
```

### Runtime Issues
```bash
# Get backtrace
RUST_BACKTRACE=1 ./target/debug/speakeasy --target sample.exe

# Verbose backtrace
RUST_BACKTRACE=full ./target/debug/speakeasy --target sample.exe
```

### Performance Issues
```bash
# Profile
cargo build --release
time ./target/release/speakeasy --target sample.exe

# Check allocations
valgrind ./target/debug/speakeasy --target sample.exe
```

## Project Structure

### Key Files
- `src/lib.rs` - Library root
- `src/bin/cli.rs` - CLI binary
- `Cargo.toml` - Dependencies and metadata
- `CONVERSION.md` - Python to Rust conversion guide
- `README.md` - Quick start guide

### Module Organization
- `config.rs` - Configuration structures
- `emulator/` - Core emulation engine
- `windows/` - Windows subsystem implementations
- `report.rs` - Report generation
- `peparser.rs` - PE file parsing
- `profiler.rs` - Performance profiling
- `utils.rs` - Utility functions
- `error.rs` - Error types

## Adding New Features

### Adding a Windows API Handler
1. Create handler struct in `src/windows/api/`
2. Implement `ApiHandler` trait
3. Register in `ApiDispatcher`
4. Add documentation and tests

### Adding a Configuration Option
1. Add field to relevant config struct in `config.rs`
2. Add CLI argument in `src/bin/cli.rs`
3. Add to default configuration
4. Update documentation

### Adding Tests
1. Add to `tests/unit.rs` for unit tests
2. Add to `tests/integration.rs` for integration tests
3. Run `cargo test` to verify
4. Ensure >80% code coverage

## Continuous Integration

### GitHub Actions
- Build on push
- Test on all commits
- Clippy linting
- Format checking
- Documentation building

### Local Pre-commit Hooks
```bash
#!/bin/sh
cargo fmt -- --check || exit 1
cargo clippy -- -D warnings || exit 1
cargo test || exit 1
```

## Release Process

1. Update version in `Cargo.toml`
2. Update `CHANGELOG.md`
3. Run full test suite: `cargo test --all`
4. Build release: `cargo build --release`
5. Tag release: `git tag v3.0.0`
6. Publish: `cargo publish`

## Performance Considerations

### Memory
- Mutex overhead on hot paths
- Consider RwLock for read-heavy sections
- Arena allocators for frequent allocations

### CPU
- Unicorn CPU emulation dominates runtime
- Minimal overhead in I/O handlers
- Profile before optimizing

### String Handling
- Prefer `&str` over `String`
- Use `intern` pattern for common strings
- Cache parsed values

## Resources

- [Rust Book](https://doc.rust-lang.org/book/)
- [Cargo Manual](https://doc.rust-lang.org/cargo/)
- [Clippy](https://github.com/rust-lang/rust-clippy)
- [Flamegraph](https://www.brendangregg.com/flamegraphs.html)

## Contributing

1. Fork repository
2. Create feature branch
3. Make changes
4. Run tests and linting
5. Submit pull request

## Questions?

See the main [README](README.md) or [Conversion Guide](CONVERSION.md).
