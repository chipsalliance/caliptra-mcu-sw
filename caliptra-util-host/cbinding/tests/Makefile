# Makefile for Caliptra C bindings tests

# Compiler settings
CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -g -O0
INCLUDES = -I../include
LDFLAGS = -ldl -lpthread -lm

# Directories
TARGET_DIR = ../../../target/caliptra-util-host/debug
INCLUDE_DIR = ../include
TEST_DIR = .

# Targets
TESTS = test_get_device_id test_custom_c_transport
STATIC_LIB = $(TARGET_DIR)/libcaliptra_util_host_cbinding.a
TEST_UTILS_LIB = $(shell find $(TARGET_DIR)/build -name "libcaliptra_test_utils.a" -type f | head -1)
DYNAMIC_LIB = $(TARGET_DIR)/libcaliptra_util_host_cbinding.so
HEADER = $(INCLUDE_DIR)/caliptra_util_host.h

.PHONY: all clean build-rust test check-deps

all: check-deps build-rust $(TESTS)

# Check if required tools are available
check-deps:
	@which cargo >/dev/null || (echo "Error: cargo not found. Please install Rust." && exit 1)
	@which $(CC) >/dev/null || (echo "Error: $(CC) not found. Please install a C compiler." && exit 1)

# Build the Rust library and generate headers
build-rust:
	@echo "Building Rust library..."
	cd .. && cargo build
	@echo "Rust library built successfully"
	@if [ ! -f "$(HEADER)" ]; then \
		echo "Warning: C header not generated. Make sure cbindgen is working."; \
	fi

# Build test executables
test_get_device_id: test_get_device_id.c $(STATIC_LIB) $(TEST_UTILS_LIB) $(HEADER)
	@echo "Building test: $@"
	@mkdir -p $(TARGET_DIR)
	$(CC) $(CFLAGS) $(INCLUDES) -o $(TARGET_DIR)/$@ $< $(STATIC_LIB) $(TEST_UTILS_LIB) $(LDFLAGS)

test_custom_c_transport: test_custom_c_transport.c $(STATIC_LIB) $(HEADER)
	@echo "Building test: $@"
	@mkdir -p $(TARGET_DIR)
	$(CC) $(CFLAGS) $(INCLUDES) -o $(TARGET_DIR)/$@ $< $(STATIC_LIB) $(LDFLAGS)

# Run tests
test: $(TESTS)
	@echo "Running tests..."
	@for test in $(TESTS); do \
		echo ""; \
		echo "Running $$test..."; \
		LD_LIBRARY_PATH=$(TARGET_DIR):$$LD_LIBRARY_PATH $(TARGET_DIR)/$$test; \
		if [ $$? -ne 0 ]; then \
			echo "Test $$test failed!"; \
			exit 1; \
		fi; \
	done
	@echo ""
	@echo "All tests completed successfully!"

# Clean build artifacts
clean:
	rm -f $(foreach test,$(TESTS),$(TARGET_DIR)/$(test))
	rm -f *.o
	cd .. && cargo clean

# Help target
help:
	@echo "Available targets:"
	@echo "  all        - Build everything (default)"
	@echo "  build-rust - Build only the Rust library"
	@echo "  test       - Build and run tests"
	@echo "  clean      - Clean all build artifacts"
	@echo "  help       - Show this help message"
	@echo ""
	@echo "Environment variables:"
	@echo "  CC         - C compiler (default: gcc)"
	@echo "  CFLAGS     - C compiler flags"