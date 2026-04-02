# Quick Start

## Installation

See [Installation Guide](INSTALL.md) for detailed setup instructions.

Quick install:
```bash
cd rust
cargo build --release
```

## Basic Usage

### Emulate a PE Binary

```bash
./target/release/speakeasy --target sample.exe --output report.json
```

Output JSON report to file instead:
```bash
speakeasy --target sample.exe > report.json
```

### Emulate Raw Shellcode

```bash
speakeasy --target shellcode.bin --do-raw --arch x86 --output report.json
```

### Show Help

```bash
speakeasy --help
```

### Display Version

```bash
speakeasy --version
```

## Configuration

### Using Default Configuration

```bash
speakeasy --target sample.exe
```

### Using Custom Configuration

Create `config.json`:
```json
{
  "memory": {
    "stack_size": 2097152,
    "heap_size": 536870912,
    "track_accesses": false
  },
  "process": {
    "process_name": "explorer.exe",
    "command_line": [],
    "emulate_children": false
  }
}
```

Then use:
```bash
speakeasy --target sample.exe --config config.json
```

### Export Configuration Template

```bash
speakeasy config --output default-config.json
```

## Report Analysis

The JSON report contains:

```json
{
  "sha256": "...",
  "arch": "x86",
  "filetype": "exe",
  "entry_points": [...],
  "modules": [...],
  "api_calls": [...],
  "file_accesses": [...],
  "registry_accesses": [...],
  "network_activity": [...],
  "stats": {
    "total_instructions": 12345,
    "total_api_calls": 42,
    ...
  }
}
```

### Extract Key Information

Using `jq`:
```bash
# Get basic info
jq '{sha256, arch, filetype}' report.json

# Count API calls
jq '.api_calls | length' report.json

# List all file accesses
jq '.file_accesses[] | {timestamp, path}' report.json

# Get statistics
jq '.stats' report.json
```

## Common Tasks

### Analyze Multiple Samples

```bash
for sample in samples/*.exe; do
  echo "Analyzing $sample..."
  speakeasy --target "$sample" -o "report_$(basename $sample).json"
done
```

### Extract Hashes

```bash
for report in report_*.json; do
  jq '.sha256' "$report"
done
```

### Find Dropped Files

```bash
jq '.file_accesses[] | select(.access_type == "write") | {timestamp, path}' report.json
```

### Track Network Activity

```bash
jq '.network_activity[]' report.json
```

### Analyze API Calls

```bash
# Count API calls to each module
jq 'group_by(.module) | map({module: .[0].module, count: length})' \
  <(jq '.api_calls[]' report.json)
```

## Verbose Output

Enable debug logging:
```bash
RUST_LOG=debug speakeasy --target sample.exe -v
```

Or just basic verbose:
```bash
speakeasy --target sample.exe -v
```

## Performance

### Faster Analysis (Disable Features)

Configuration:
```json
{
  "api": {"track_calls": false},
  "memory": {"track_accesses": false},
  "file_system": {"track_accesses": false}
}
```

### Profile Execution

```bash
time speakeasy --target sample.exe
```

## Examples

See the `examples/` directory for complete examples:
- Simple shellcode analysis
- DLL execution
- Batch processing
- Custom report generation

## Troubleshooting

### File Not Found

```bash
speakeasy --target sample.exe
# Error: IO error: No such file or directory (os error 2)

# Solution: Use absolute path
speakeasy --target /full/path/to/sample.exe
```

### Unsupported Architecture

```bash
speakeasy --target driver.sys
# Error: Not supported: Kernel driver emulation not yet supported

# Currently supports: x86 and amd64 usermode binaries
```

### Invalid Configuration

```bash
speakeasy --target sample.exe --config bad.json
# Error: Configuration error: invalid type

# Check config.json format is valid JSON
```

## Next Steps

1. **Learn More**: Read [CLI Reference](../doc/cli-reference.md)
2. **Configuration**: See [Configuration Guide](../doc/configuration.md)
3. **Development**: Check [Development Guide](DEVELOPMENT.md)
4. **API Handlers**: See [API Handlers Documentation](../doc/api-handlers.md)
5. **Reporting**: Learn about [Reports](../doc/reporting.md)

## Getting Help

- **Documentation**: See `README.md` and `doc/` directory
- **Issues**: https://github.com/mandiant/speakeasy/issues
- **Q&A**: Check existing issues for answers
