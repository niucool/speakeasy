# AGENTS.md - Speakeasy Development Guide

## Overview

Speakeasy is a Windows malware emulation framework written primarily in Python with a Rust component. It emulates Windows APIs, process/thread behavior, filesystem, registry, and network activity.

## Build, Lint, and Test Commands

### Python (Main)

```bash
# Install dependencies (using uv)
uv pip install -e ".[dev]"

# Format code
just format

# Run linter (ruff check + import sorting)
just ruff

# Run full lint (format + ruff)
just lint

# Run all tests
just test

# Run specific test file
.venv/bin/pytest -x -q tests/test_struct.py

# Run specific test function
.venv/bin/pytest -x -q tests/test_struct.py::test_function_name

# Run tests matching pattern
.venv/bin/pytest -x -q -k "test_name_pattern"

# Run PMA (Portable Malware Analyzer) tests
just test-pma
```

### Rust Component

```bash
cd rust

# Build debug binary
make build

# Build release binary
make release

# Run tests
make test

# Check code (format, lint, compile)
make check

# Format code
make fmt

# Run clippy linter
make clippy

# Generate documentation
make doc
```

### Direct Python Commands (without just)

```bash
# Format
uvx ruff format

# Lint
uvx ruff check --fix
uvx ruff check --select I --fix

# Type check (note: currently disabled due to many errors)
uvx mypy --check-untyped-defs speakeasy tests examples
```

## Code Style Guidelines

### General

- **Line length**: 120 characters
- **Python version**: 3.10+
- **Type hints**: Required for function signatures
- **No trailing whitespace**

### Imports

- Use ruff for import sorting (enabled via `I` rule)
- Group imports: stdlib, third-party, local
- Do not use wildcard imports (`from x import *`)

### Formatting

- Use `ruff format` for all formatting
- 4 spaces for indentation (no tabs)
- Use underscores for variable/function names (snake_case)
- Use PascalCase for classes, CAPS for constants

### Type Annotations

- Use type hints for all function parameters and return types
- Python 3.10+ union syntax preferred: `str | None` over `Optional[str]`
- Use `Any` sparingly - avoid when possible
- The codebase has many dynamic ctypes structures; mypy strict checking is disabled for:
  - `speakeasy.winenv.defs.*`
  - `speakeasy.windows.objman`
  - `speakeasy.winenv.api.*` (various usermode/kernelmode modules)

### Naming Conventions

- Variables/functions: `snake_case`
- Classes: `PascalCase`
- Constants: `UPPER_CASE`
- Private methods: prefix with underscore `_private_method`
- Module names: `snake_case.py`

### Error Handling

- Use custom exceptions from `speakeasy.errors`
- Raise exceptions with descriptive messages
- Handle exceptions at appropriate boundaries (CLI, API entry points)
- Prefer specific exception types over generic `Exception`

### Testing

- Tests live in `tests/` directory
- Use pytest framework
- Test files: `test_*.py`
- Use descriptive test names: `test_function_description`
- Use fixtures from `conftest.py` where applicable

### Documentation

- Use docstrings for public APIs and complex functions
- Prefer clear code over comments
- Do not include commented-out code

### Special Guidelines for Dynamic Code

The codebase extensively uses ctypes for Windows API structures. Due to the dynamic nature of:
- Struct attribute access
- Union handling
- Windows API dispatch

The following modules have relaxed mypy rules (defined in pyproject.toml):
- Windows struct definitions (`speakeasy.winenv.defs.*`)
- Object manager (`speakeasy.windows.objman`)
- WDF driver framework (`speakeasy.winenv.api.kernelmode.wdfldr`)
- Various API handler modules (kernel32, user32, ntoskrnl, etc.)

When modifying these areas, maintain consistency with existing patterns and don't add strict typing that will break the build.

### CLI Entry Point

- Entry point: `speakeasy.cli:main`
- Use Click or argparse for CLI argument handling
- Exit with appropriate status codes (0 success, 1 error)

## Project Structure

```
speakeasy/
├── speakeasy/          # Main package
│   ├── engines/        # Emulation engines
│   ├── windows/        # Windows-specific modules
│   ├── winenv/         # Windows environment (API handlers, definitions)
│   ├── resources/      # Embedded resources
│   ├── cli.py          # CLI entry point
│   ├── config.py       # Configuration management
│   └── ...
├── tests/              # Test suite
├── rust/               # Rust component
└── examples/           # Usage examples
```

## Running a Single Test Example

```bash
# Run specific test
pytest -xvs tests/test_struct.py::test_struct_creation

# Run tests in a specific class
pytest -xvs tests/test_struct.py::TestStructClass
```