# Caliptra Utility Host Library

A flexible framework for communicating with Caliptra devices through various transports (MCTP, DOE, etc.) with pluggable command handlers and support for both Rust and C applications.

## Features

- **Transport Abstraction**: Support for MCTP, DOE, TCP and custom transports
- **Command System**: Extensible command handlers for SPDM, PLDM, and custom commands
- **Plugin Framework**: Load plugins written in Rust or C to extend functionality
- **C Bindings**: Complete C API with proper memory management
- **Async Support**: Built with async/await for efficient I/O operations

## Crates

- `caliptra-util-host-core`: Core library functionality
- `caliptra-util-host-cbinding`: C bindings and API
- `caliptra-util-host-plugins`: Plugin system extensions
- `caliptra-util-host-transports`: Additional transport implementations
- `examples/basic-usage`: Example usage of the library

## Quick Start

### Rust

```rust
use caliptra_util_host_core::*;

#[tokio::main]
async fn main() -> Result<()> {
    // Create transport
    let transport = Box::new(transport::MctpTransport::new(0x1D));
    
    // Create host library instance
    let mut host = CaliptraUtilHost::new(transport);
    
    // Register command handlers
    host.register_command_handler(Box::new(command::SpdmCommandHandler))?;
    
    // Execute command
    let cmd = command::Command::new(
        command::CommandType::Spdm,
        0x81, // GET_VERSION
        vec![0x10, 0x11, 0x00, 0x00]
    );
    
    let result = host.execute_command(cmd).await?;
    println!("Response: {:?}", result.response_data);
    
    Ok(())
}
```

### C

```c
#include "caliptra_util_host.h"

int main() {
    // Create MCTP transport
    CaliptraUtilHostHandle* host = caliptra_util_host_create_mctp(0x1D);
    
    // Register built-in handlers
    caliptra_util_host_register_builtin_handlers(host);
    
    // Execute command
    CCommand cmd = {
        .command_type = SPDM,
        .opcode = 0x81,
        .payload_data = (uint8_t[]){0x10, 0x11, 0x00, 0x00},
        .payload_size = 4
    };
    
    CCommandResult result;
    CaliptraUtilResult status = caliptra_util_host_execute_command(host, &cmd, &result);
    
    if (status == Success) {
        printf("Command executed successfully\\n");
        caliptra_util_host_free_result(&result);
    }
    
    caliptra_util_host_destroy(host);
    return 0;
}
```

## Building

```bash
# Build all crates
cargo build

# Build with C bindings
cargo build --features cbinding

# Run examples
cargo run --example basic_usage

# Run tests
cargo test
```

## License

Apache-2.0