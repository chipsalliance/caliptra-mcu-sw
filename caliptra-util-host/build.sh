# Licensed under the Apache-2.0 license

# Build script for the entire Caliptra Utility Host Library project

#!/bin/bash

set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
echo "Building Caliptra Utility Host Library from: $PROJECT_ROOT"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if Rust is installed
if ! command -v cargo &> /dev/null; then
    print_error "Rust/Cargo not found. Please install Rust: https://rustup.rs/"
    exit 1
fi

# Check if cbindgen is installed (for C bindings)
if ! command -v cbindgen &> /dev/null; then
    print_warning "cbindgen not found. Installing..."
    cargo install cbindgen
fi

print_status "Building all workspace crates..."

# Build the entire workspace
cargo build

print_status "Building with C bindings enabled..."
cargo build --features cbinding

print_status "Running tests..."
cargo test

print_status "Building examples..."
cargo build --example basic_usage

print_status "Building C bindings and generating header..."
cd caliptra-util-host-cbinding
cargo build
if [ -f "caliptra_util_host.h" ]; then
    print_status "C header generated: caliptra_util_host.h"
    cp caliptra_util_host.h ../examples/c-usage/
else
    print_warning "C header not generated"
fi
cd ..

print_status "Building C example (with mock implementation)..."
cd examples/c-usage
make clean && make
cd ../..

print_status "Running release build..."
cargo build --release

print_status "Generating documentation..."
cargo doc --no-deps

# Check for common issues
print_status "Running cargo check..."
cargo check

print_status "Running clippy..."
if command -v clippy &> /dev/null; then
    cargo clippy -- -W clippy::all
else
    print_warning "Clippy not available, skipping lint checks"
fi

print_status "Formatting code..."
if command -v rustfmt &> /dev/null; then
    cargo fmt --check || {
        print_warning "Code formatting issues found. Run 'cargo fmt' to fix."
    }
else
    print_warning "rustfmt not available, skipping format check"
fi

print_status "Build completed successfully!"
echo ""
echo "Artifacts generated:"
echo "  - Rust libraries: target/release/"
echo "  - C bindings: caliptra-util-host-cbinding/target/release/"
echo "  - C header: caliptra-util-host-cbinding/caliptra_util_host.h"
echo "  - Examples: examples/"
echo "  - Documentation: target/doc/"
echo ""
echo "To run examples:"
echo "  cargo run --example basic_usage -- --help"
echo "  cd examples/c-usage && ./caliptra_c_example"