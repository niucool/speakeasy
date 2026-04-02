# Installation Guide

## Prerequisites

### Windows
- Windows 10/11 or Windows Server 2019+
- Visual Studio 2019+ or Visual Studio Build Tools
- Rust 1.70+

### macOS
- macOS 10.15+
- Xcode Command Line Tools
- Rust 1.70+

### Linux
- GCC/Clang toolchain
- Rust 1.70+

## Install Rust

### Using Rustup (Recommended)

```bash
# Download and run installer
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Verify installation
rustc --version
cargo --version
```

### Using Package Manager

#### Windows (Chocolatey)
```powershell
choco install rust
```

#### macOS (Homebrew)
```bash
brew install rust
```

#### Ubuntu/Debian
```bash
sudo apt-get install rustc cargo
```

## Build from Source

### Clone Repository
```bash
git clone https://github.com/mandiant/speakeasy.git
cd speakeasy/rust
```

### Build Debug Version
```bash
cargo build
```

### Build Release Version (Optimized)
```bash
cargo build --release
```

The compiled binary will be at:
- Debug: `target/debug/speakeasy`
- Release: `target/release/speakeasy`

## Install as Command

```bash
# Install to ~/.cargo/bin/
cargo install --path .

# Verify installation
speakeasy --version
```

## Docker Build (Optional)

```dockerfile
FROM rust:1.75 as builder
WORKDIR /speakeasy
COPY rust/ .
RUN cargo build --release

FROM debian:bookworm-slim
COPY --from=builder /speakeasy/target/release/speakeasy /usr/local/bin/
ENTRYPOINT ["speakeasy"]
```

Build Docker image:
```bash
docker build -f Dockerfile.rust -t speakeasy:latest .
```

Run in Docker:
```bash
docker run -v /path/to/samples:/samples speakeasy:latest \
  --target /samples/sample.exe \
  --output /samples/report.json
```

## Verify Installation

```bash
# Show help
speakeasy --help

# Show version
speakeasy --version

# Run basic test (requires a sample)
speakeasy --target sample.exe --no-mp -o report.json
```

## Troubleshooting

### Rust Installation Issues

**Problem**: `cargo: command not found`

**Solution**:
```bash
# Add Rust to PATH (if not done automatically)
source $HOME/.cargo/env
```

### Build Failures

**Problem**: Build fails with linking errors

**Solution**:
```bash
# Clean and rebuild
cargo clean
cargo build

# Check environment
cargo --version
rustc --version
```

**Problem**: `error: linker cc not found`

**Solution - Ubuntu/Debian**:
```bash
sudo apt-get install build-essential
```

**Solution - macOS**:
```bash
xcode-select --install
```

**Solution - Windows**:
- Install Visual Studio Build Tools from Microsoft

### Runtime Issues

**Problem**: `error: Emulator not initialized`

**Solution**: Make sure a target is specified:
```bash
speakeasy --target sample.exe --output report.json
```

## Next Steps

1. Read [Quick Start](QUICKSTART.md)
2. Check [CLI Reference](../doc/cli-reference.md)
3. Review [Examples](../examples/)
4. See [Development Guide](DEVELOPMENT.md)

## Support

- Issues: https://github.com/mandiant/speakeasy/issues
- Discussions: https://github.com/mandiant/speakeasy/discussions
- Documentation: See `doc/` directory
