.PHONY: build release clean test check fmt clippy doc help

help:
	@echo "Speakeasy Rust Build System"
	@echo ""
	@echo "Targets:"
	@echo "  make build      - Build debug binary"
	@echo "  make release    - Build optimized release binary"
	@echo "  make test       - Run all tests"
	@echo "  make check      - Check code (format, lint, compile)"
	@echo "  make fmt        - Format code"
	@echo "  make clippy     - Run clippy linter"
	@echo "  make doc        - Generate documentation"
	@echo "  make clean      - Clean build artifacts"
	@echo "  make run ARGS   - Run speakeasy with arguments"

build:
	cargo build

release:
	cargo build --release

test:
	cargo test --all

check:
	cargo fmt -- --check
	cargo clippy -- -D warnings
	cargo check

fmt:
	cargo fmt --all

clippy:
	cargo clippy -- -D warnings

doc:
	cargo doc --no-deps --open

clean:
	cargo clean

run:
	cargo run -- $(ARGS)

run-release:
	cargo run --release -- $(ARGS)

clippy-fix:
	cargo clippy --fix --allow-dirty --allow-staged

fmt-check:
	cargo fmt -- --check

install:
	cargo install --path .

all: check test build doc
