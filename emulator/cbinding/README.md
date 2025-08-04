# Caliptra MCU Emulator C Bindings

This crate provides C bindings for the Caliptra MCU Emulator, allowing C applications to control the emulator with real-time UART streaming and console input support.

## Overview

The C bindings provide:
- **Complete C control**: C code manages emulator memory allocation and lifetime
- **Real-time UART streaming**: Live UART output display and console input handling
- **Full configuration access**: All emulator parameters available from C
- **GDB integration**: Built-in GDB server support for debugging
- **Static library**: Easy integration into existing C projects
- **Zero changes to emulator.rs**: Original Rust code remains untouched

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   C Application │───▶│   C Bindings    │───▶│   Rust Emulator │
│                 │    │  (cbinding crate)│    │   (emulator crate)│
│ - Memory mgmt   │    │ - C interface   │    │ - Original code │
│ - UART I/O      │    │ - Type safety   │    │ - Full features │
│ - Console input │    │ - Error handling│    │ - Unchanged     │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## Building

### Prerequisites
- Rust toolchain
- C compiler (gcc/clang)
- cbindgen (automatically installed as build dependency)

### Build Steps

The emulator C binding can be built using the `cargo xtask emulator-cbinding` command:

```bash
# Show all available commands and options
cargo xtask emulator-cbinding --help

# Build all components (library, header, and binary) - recommended
cargo xtask emulator-cbinding build                    # Debug build (default)
cargo xtask emulator-cbinding build --release          # Release build (optimized)

# Alternative: Build individual components
cargo xtask emulator-cbinding build-lib                # Build only the Rust static library (debug)
cargo xtask emulator-cbinding build-lib --release      # Build only the Rust static library (release)
cargo xtask emulator-cbinding build-emulator           # Build only the C emulator binary (debug)
cargo xtask emulator-cbinding build-emulator --release # Build only the C emulator binary (release)

# Clean build artifacts
cargo xtask emulator-cbinding clean                    # Clean debug artifacts
cargo xtask emulator-cbinding clean --release          # Clean release artifacts
```

**Build Modes:**
- **Debug builds** (default): Include debug symbols, no optimization, larger binaries
- **Release builds** (`--release`): Optimized, smaller binaries, faster execution

This generates:
- `target/debug/emulator_cbinding/libemulator_cbinding.a` or `target/release/emulator_cbinding/libemulator_cbinding.a` - Static library
- `emulator_cbinding.h` - C header file
- `emulator` - Example C application

## Quick Start

### Basic Usage

```c
#include "emulator_cbinding.h"
#include <stdio.h>
#include <stdlib.h>

int main() {
    // 1. Allocate memory
    size_t size = emulator_get_size();
    size_t align = emulator_get_alignment();
    void* memory = aligned_alloc(align, size);
    
    // 2. Configure emulator
    struct CEmulatorConfig config = {
        .mRomPath = "rom.bin",
        .mFirmwarePath = "firmware.bin",
        .mCaliptraRomPath = "caliptra_rom.bin",
        .mCaliptraFirmwarePath = "caliptra_firmware.bin",
        .mSocManifestPath = "manifest.bin",
        .mGdbPort = 0,  // No GDB
        .mStdinUart = 1,  // Enable console input
        .mCaptureUartOutput = 1,  // Capture UART output
        // All memory layout parameters default to -1 (use defaults)
        .mRomOffset = -1, .mRomSize = -1,
        .mUartOffset = -1, .mUartSize = -1,
        // ... other parameters
    };
    
    // 3. Initialize
    if (emulator_init((struct CEmulator*)memory, &config) != Success) {
        free(memory);
        return 1;
    }
    
    // 4. Run with UART streaming
    char uart_buffer[1024];
    while (1) {
        enum CStepAction action = emulator_step((struct CEmulator*)memory);
        
        // Check for UART output
        int len = emulator_get_uart_output_streaming(
            (struct CEmulator*)memory, uart_buffer, sizeof(uart_buffer));
        if (len > 0) {
            printf("%.*s", len, uart_buffer);
            fflush(stdout);
        }
        
        if (action != Continue) break;
    }
    
    // 5. Cleanup
    emulator_destroy((struct CEmulator*)memory);
    free(memory);
    return 0;
}
```

## Configuration

### Required Parameters
```c
struct CEmulatorConfig config = {
    // Required file paths
    .mRomPath = "path/to/rom.bin",
    .mFirmwarePath = "path/to/firmware.bin", 
    .mCaliptraRomPath = "path/to/caliptra_rom.bin",
    .mCaliptraFirmwarePath = "path/to/caliptra_firmware.bin",
    .mSocManifestPath = "path/to/manifest.bin",
    
    // Basic configuration
    .mGdbPort = 0,                    // 0 = no GDB, >0 = GDB port
    .mI3cPort = 0,                    // 0 = no I3C, >0 = I3C port
    .mTraceInstr = 0,                 // 0 = no trace, 1 = trace instructions
    .mStdinUart = 1,                  // 1 = enable console input to UART
    .mManufacturingMode = 0,          // 0 = normal, 1 = manufacturing mode
    .mCaptureUartOutput = 1,          // 1 = capture UART output
    
    // Hardware version
    .mHwRevisionMajor = 2,
    .mHwRevisionMinor = 0,
    .mHwRevisionPatch = 0,
};
```

### Memory Layout Customization
All memory layout parameters use `-1` for defaults or specific values for custom layouts:

```c
// Use all defaults (recommended for most cases)
.mRomOffset = -1, .mRomSize = -1,
.mUartOffset = -1, .mUartSize = -1,
.mSramOffset = -1, .mSramSize = -1,
// ... all other offset/size parameters

// Custom memory layout example
.mRomOffset = 0x40000000,   // ROM at 1GB
.mRomSize = 0x100000,       // 1MB ROM
.mSramOffset = 0x20000000,  // SRAM at 512MB
.mSramSize = 0x800000,      // 8MB SRAM
// ... customize as needed
```

Available memory layout parameters:
- `mRomOffset/mRomSize`, `mUartOffset/mUartSize`, `mCtrlOffset/mCtrlSize`
- `mSpiOffset/mSpiSize`, `mSramOffset/mSramSize`, `mPicOffset`
- `mDccmOffset/mDccmSize`, `mI3cOffset/mI3cSize`
- `mPrimaryFlashOffset/mPrimaryFlashSize`, `mSecondaryFlashOffset/mSecondaryFlashSize`
- `mMciOffset/mMciSize`, `mDmaOffset/mDmaSize`
- `mMboxOffset/mMboxSize`, `mSocOffset/mSocSize`
- `mOtpOffset/mOtpSize`, `mLcOffset/mLcSize`
- `mExternalTestSramOffset/mExternalTestSramSize`

## UART and Console Features

### Real-time UART Streaming
The emulator supports real-time UART output and console input:

```c
// Enable UART features in configuration
config.mStdinUart = 1;          // Console input → UART RX
config.mCaptureUartOutput = 1; // Capture UART TX

// In your main loop
char uart_buffer[1024];
while (1) {
    emulator_step(emulator);
    
    // Get streaming UART output (clears buffer after reading)
    int len = emulator_get_uart_output_streaming(emulator, uart_buffer, sizeof(uart_buffer));
    if (len > 0) {
        printf("%.*s", len, uart_buffer);  // Display UART output
        fflush(stdout);
    }
}
```

### Console Input Functions
```c
// Send character to UART RX
int emulator_send_uart_char(struct CEmulator* emulator, char character);

// Check if UART RX is ready for input
int emulator_uart_rx_ready(struct CEmulator* emulator);

// Get UART output (keeps data in buffer)
int emulator_get_uart_output(struct CEmulator* emulator, char* buffer, size_t size);

// Get UART output (clears buffer after reading - for streaming)
int emulator_get_uart_output_streaming(struct CEmulator* emulator, char* buffer, size_t size);
```

## GDB Integration

### Basic GDB Setup
```c
struct CEmulatorConfig config = {
    // ... other config ...
    .mGdbPort = 3333,  // Enable GDB server on port 3333
};

emulator_init(memory, &config);

if (emulator_is_gdb_mode(memory)) {
    printf("GDB server available on port %u\n", emulator_get_gdb_port(memory));
    printf("Connect with: gdb -ex 'target remote :%u'\n", emulator_get_gdb_port(memory));
}
```

### GDB Usage Patterns

**C-Controlled Execution with GDB Available:**
```c
// Your C code controls stepping, GDB available for inspection
while (1) {
    enum CStepAction action = emulator_step(memory);
    // Handle UART, check state, etc.
    if (action != Continue) break;
}
```

**GDB-Controlled Execution:**
```c
// GDB controls all execution (blocking)
if (emulator_is_gdb_mode(memory)) {
    emulator_run_gdb_server(memory);  // Blocks until GDB disconnects
}
```

### Connecting with GDB
```bash
gdb firmware.elf
(gdb) target remote :3333
(gdb) break main
(gdb) continue
```

## API Reference

### Memory Management
```c
size_t emulator_get_size();           // Required memory size
size_t emulator_get_alignment();      // Required alignment
```

### Initialization and Control
```c
enum EmulatorError emulator_init(struct CEmulator* memory, const struct CEmulatorConfig* config);
enum CStepAction emulator_step(struct CEmulator* memory);
void emulator_destroy(struct CEmulator* memory);
unsigned int emulator_get_pc(struct CEmulator* memory);  // Get program counter
```

### Error Codes
```c
enum EmulatorError {
    Success = 0,
    InvalidArgs = -1,
    InitializationFailed = -2,
    NullPointer = -3,
    InvalidEmulator = -4,
};

enum CStepAction {
    Continue = 0,
    Break = 1,
    ExitSuccess = 2,
    ExitFailure = 3,
};
```

### GDB Functions
```c
int emulator_is_gdb_mode(struct CEmulator* memory);
unsigned int emulator_get_gdb_port(struct CEmulator* memory);
enum EmulatorError emulator_run_gdb_server(struct CEmulator* memory);
```

### Utility Functions
```c
enum EmulatorError emulator_trigger_exit();  // Request clean shutdown
```

## Integration

### Linking
```bash
# Link with debug library
gcc -o my_app my_app.c \
    -L./target/debug \
    -lemulator_cbinding \
    -lpthread -ldl -lm -lrt

# Link with release library (optimized)
gcc -o my_app my_app.c \
    -L./target/release \
    -lemulator_cbinding \
    -lpthread -ldl -lm -lrt
```

**Note:** The `-lrt` library is required for POSIX real-time extensions used by the emulator.

### Command Line Example
The included C application supports the same command line arguments as the Rust emulator:

```bash
./emulator \
    --rom rom.bin \
    --firmware firmware.bin \
    --caliptra-rom caliptra_rom.bin \
    --caliptra-firmware caliptra_firmware.bin \
    --soc-manifest manifest.bin \
    --gdb-port 3333 \
    --trace-instr
```

## Platform Support

Supports the same platforms as the Rust emulator:
- Linux (x86_64, aarch64)
- macOS (x86_64, aarch64)
- Windows (x86_64)

## Thread Safety

- The emulator is **not thread-safe**
- Use external synchronization in multi-threaded environments
- Each emulator instance should be accessed from only one thread

## Example Application

The included `emulator.c` demonstrates:
- Complete command line argument parsing
- Real-time console input handling with raw terminal mode
- Live UART output streaming
- GDB integration
- Proper cleanup and error handling
- Signal handling (Ctrl+C)

Run with console input:
```bash
./emulator --rom rom.bin --firmware fw.bin --caliptra-rom crom.bin --caliptra-firmware cfw.bin --soc-manifest manifest.bin
```

Run with GDB:
```bash
./emulator --gdb-port 3333 --rom rom.bin --firmware fw.bin --caliptra-rom crom.bin --caliptra-firmware cfw.bin --soc-manifest manifest.bin
```

This provides a complete, production-ready C interface to the Caliptra MCU Emulator with full feature parity and real-time interaction capabilities.
