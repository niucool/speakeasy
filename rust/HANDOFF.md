# Developer Checklist & Handoff Guide

## Pre-Development Checklist

Before starting Phase 2 development, ensure:

### Environment Setup
- [ ] Rust 1.70+ installed (`rustc --version`)
- [ ] Cargo working (`cargo --version`)
- [ ] Git configured for commits
- [ ] IDE/editor configured (VS Code with Rust-Analyzer recommended)
- [ ] All dependencies building (`cargo build`)

### Code Review
- [ ] Review entire [README.md](README.md)
- [ ] Review [CONVERSION.md](CONVERSION.md) for architecture
- [ ] Review [src/lib.rs](src/lib.rs) for module organization
- [ ] Review [src/emulator/mod.rs](src/emulator/mod.rs) for main API
- [ ] Run tests: `cargo test`
- [ ] Generate docs: `cargo doc --no-deps --open`

### Code Quality
- [ ] Run formatter: `cargo fmt`
- [ ] Run linter: `cargo clippy`
- [ ] Check for issues: `cargo check`
- [ ] All warnings resolved

## Phase 2 Development Checklist

### Unicorn CPU Integration
- [ ] Add unicorn engine initialization to CPU emulator
- [ ] Implement memory access hooks
- [ ] Implement code execution hooks
- [ ] Map x86 and x64 registers
- [ ] Initialize stack and entry point
- [ ] Handle instruction counting
- [ ] Add breakpoint support
- [ ] Test with simple shellcode
- [ ] Performance profiling

### PE Parsing Enhancement
- [ ] Parse full PE headers
- [ ] Parse section table
- [ ] Map sections to memory
- [ ] Parse import table
- [ ] Parse export table
- [ ] Handle relocations
- [ ] Support for both x86 and x64
- [ ] Error handling for malformed PEs
- [ ] Test with real binaries

### Testing
- [ ] Write tests for Unicorn integration
- [ ] Write tests for PE parsing
- [ ] Validate output format matches Python version
- [ ] Test with known malware samples
- [ ] Performance benchmarking

## Phase 3 Development Checklist

### Windows API Implementation
- [ ] Implement Kernel32 functions
- [ ] Implement User32 functions  
- [ ] Implement WS2_32 functions
- [ ] Implement NTOSKRNL functions
- [ ] Add API call logging
- [ ] Add parameter validation
- [ ] Handle API callbacks

### Platform-Specific Features
- [ ] Registry operations
- [ ] File operations
- [ ] Network operations
- [ ] Process management
- [ ] Thread management

### Testing
- [ ] API handler tests
- [ ] Integration tests with real samples
- [ ] Regression tests against Python version
- [ ] Error case handling

## Code Organization Guidelines

### Adding a New Module
1. Create file in appropriate directory
2. Add `pub mod` declaration in parent `mod.rs`
3. Add public re-exports in parent `mod.rs`
4. Document module purpose
5. Add error types to [error.rs](src/error.rs) if needed
6. Write unit tests
7. Update [TODO.md](TODO.md)

### Adding Configuration Options
1. Add field to config struct
2. Add CLI argument
3. Add to default configuration  
4. Document in README
5. Add tests

### Adding Tests
1. Add to appropriate test file
2. Use descriptive names
3. Include documentation comments
4. Test both success and failure cases
5. Update test count in documentation

## Best Practices

### Code Style
- Use `cargo fmt` for consistent formatting
- Follow Rust naming conventions
- Use meaningful variable names
- Add doc comments to public APIs
- Keep functions small and focused

### Error Handling
- Use `Result<T>` return types
- Never use `.unwrap()` in production
- Provide context with errors
- Use `?` operator for error propagation
- Custom error types in [error.rs](src/error.rs)

### Testing
- Minimum 80% code coverage
- Test both happy and sad paths
- Use descriptive test names
- Keep tests independent
- Mock external dependencies

### Documentation
- Document all public items
- Include examples in docs
- Keep README up to date
- Update TODO as you progress
- Link related documentation

### Performance
- Profile before optimizing
- Use benchmarks for comparisons
- Consider memory allocation patterns
- Use appropriate data structures
- Avoid unnecessary cloning

### Git Workflow
1. Create feature branch: `git checkout -b feature/xyz`
2. Make changes, commit regularly
3. Run tests: `cargo test`
4. Run checks: `cargo fmt && cargo clippy`
5. Create pull request
6. Address review comments
7. Merge to main

## Common Commands Reference

```bash
# Build
cargo build                    # Debug build
cargo build --release         # Release build
cargo build --no-default-features  # Custom features

# Test
cargo test                     # All tests
cargo test test_name          # Specific test
cargo test -- --nocapture     # Show output
cargo test --doc              # Doc tests

# Code Quality
cargo fmt                      # Format code
cargo clippy                   # Lint
cargo check                    # Check without building
cargo doc --open              # View docs

# Development
cargo run                      # Run binary
RUST_LOG=debug cargo run      # With debug logging
RUST_BACKTRACE=1 cargo test   # Full backtrace

# Maintenance
cargo update                   # Update dependencies
cargo outdated                # Check outdated crates
cargo audit                   # Security check
```

## Debugging Tips

### Enable Logging
```bash
RUST_LOG=speakeasy=debug cargo run -- --target sample.exe -v
```

### Get Full Backtrace
```bash
RUST_BACKTRACE=full cargo test test_name
```

### Memory Issues
```bash
RUSTFLAGS="-Z sanitizer=address" cargo test
```

### Use Debugger
```bash
rust-gdb ./target/debug/speakeasy
```

## Deployment Checklist

Before release:
- [ ] All tests passing
- [ ] No warnings in `cargo build`
- [ ] Code formatted `cargo fmt`
- [ ] Linter passing `cargo clippy`
- [ ] Documentation updated
- [ ] CHANGELOG updated
- [ ] Version bumped in Cargo.toml
- [ ] Git tagged with version
- [ ] Tested on Windows, macOS, Linux
- [ ] Binary size acceptable
- [ ] Performance meets baseline

## Common Issues & Solutions

### Build Failures
```bash
# Clean and rebuild
cargo clean
cargo build
```

### Linking Errors
```bash
# Update build tools
rustup update
rustup component add rust-src
```

### Test Failures
```bash
# Run with backtrace
RUST_BACKTRACE=1 cargo test

# Run single test
cargo test test_name -- --nocapture
```

### Performance Issues
```bash
# Profile with flamegraph
cargo flamegraph --bin speakeasy
```

## Resources

- [Rust Standard Library](https://doc.rust-lang.org/std/)
- [The Rust Book](https://doc.rust-lang.org/book/)
- [Cargo Manual](https://doc.rust-lang.org/cargo/)
- [Clippy](https://github.com/rust-lang/rust-clippy)
- [Crates.io](https://crates.io/)

## Questions?

1. Check [README.md](README.md)
2. Check [DEVELOPMENT.md](DEVELOPMENT.md)
3. Check [CONVERSION.md](CONVERSION.md)
4. Review [TODO.md](TODO.md)
5. Check existing tests for examples
6. Review [src/arch.rs](src/arch.rs) for architecture notes

## Handoff Notes

**Current Status**:
- Phase 1 (Foundation) complete
- Phase 2 (Core Engine) ready to start
- All infrastructure in place
- Comprehensive documentation written
- Clean, working codebase

**Next Developer Should**:
1. Review all documentation
2. Run all tests successfully
3. Generate and read API docs
4. Start with Unicorn integration
5. Reference Python version for API compatibility

**Key Contacts**:
- Original Python: See GitHub

**Project Location**:
`c:\Projects\github\speakeasy\rust\`

**Build Command**:
```bash
cd rust && cargo build --release
```

**Test Command**:
```bash
cd rust && cargo test
```

---

**Last Updated**: April 1, 2026
**Status**: Ready for Phase 2
**Next Step**: Unicorn CPU Integration
