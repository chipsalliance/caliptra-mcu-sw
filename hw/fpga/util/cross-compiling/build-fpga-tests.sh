#!/bin/bash
# Licensed under the Apache-2.0 license

# Build all Caliptra[SS] ROM and Runtime firmware for the FPGA platform.
cargo xtask-fpga all-build --platform fpga

# Build build xtask binary for the FPGA's ARM core.
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER="aarch64-linux-gnu-gcc"
cargo build -p xtask --features fpga_realtime --target aarch64-unknown-linux-gnu

# Build all test binaries and archive them into a file.
cargo nextest archive \
  --features="fpga_realtime" \
  --release \
  --target=aarch64-unknown-linux-gnu \
  --archive-file=caliptra-test-bins.tar.zst
