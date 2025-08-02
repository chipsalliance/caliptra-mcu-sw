# Licensed under the Apache-2.0 license
#
# Makefile for building the Caliptra MCU Emulator C binding

# Default target
.PHONY: all clean lib header emulator

all: lib header emulator

# Build the Rust static library
lib:
	cargo build --release

# Generate the header file
header:
	cargo build --release

# Build the C emulator binary
emulator: lib header
	gcc -std=c11 -Wall -Wextra -O2 \
		-I. \
		-o emulator \
		emulator.c \
		-L../../target/release \
		-lemulator_cbinding \
		-lpthread -ldl -lm

# Clean build artifacts
clean:
	cargo clean
	rm -f emulator emulator_cbinding.h

# Help target
help:
	@echo "Available targets:"
	@echo "  all      - Build library, header, and emulator binary (default)"
	@echo "  lib      - Build the Rust static library"
	@echo "  header   - Generate the C header file"
	@echo "  emulator - Build the C emulator binary"
	@echo "  clean    - Clean build artifacts"
	@echo "  help     - Show this help message"
