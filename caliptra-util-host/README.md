# Caliptra Utility Host Library

A robust library for communicating with Caliptra devices using different transports. Provides both Rust and C APIs with command translation between internal and external formats.

## Architecture

The library is organized into several focused crates:

- `command-types`: Command structures and types with zerocopy support
- `transport`: Transport abstractions including the Mailbox transport layer
- `session`: Session management for command execution
- `commands`: High-level API functions for device commands
- `osal`: OS abstraction layer for cross-platform compatibility
- `cbinding`: C bindings providing a C-compatible API
- `apps/mailbox`: Example applications demonstrating client/server usage

## Quick Start

### Rust API

```rust
use caliptra_util_host_session::CaliptraSession;
use caliptra_util_host_transport::{Mailbox, MailboxDriver};
use caliptra_util_host_commands::api::device_info::caliptra_cmd_get_device_id;

// Implement a custom mailbox driver (e.g., UDP-based)
struct UdpMailboxDriver { /* ... */ }
impl MailboxDriver for UdpMailboxDriver { /* ... */ }

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create mailbox driver and transport
    let mut udp_driver = UdpMailboxDriver::new("127.0.0.1:8080".parse()?);
    let mut mailbox_transport = Mailbox::new(&mut udp_driver);
    
    // Create session and connect
    let mut session = CaliptraSession::new(1, &mut mailbox_transport)?;
    session.connect()?;
    
    // Execute get device ID command
    let device_id = caliptra_cmd_get_device_id(&mut session)?;
    println!("Device ID: 0x{:04X}", device_id.device_id);
    println!("Vendor ID: 0x{:04X}", device_id.vendor_id);
    
    Ok(())
}
```

### C API

```c
#include "caliptra_util_host.h"

int main() {
    CaliptraError result;
    CaliptraDeviceId device_id;
    
    // Create UDP-based mailbox driver 
    CMailboxDriver* driver = caliptra_create_udp_mailbox_driver("127.0.0.1", 8080);
    if (!driver) {
        printf("Failed to create mailbox driver\n");
        return -1;
    }
    
    // Create session with the mailbox driver
    CaliptraSession* session = caliptra_session_create_with_driver(1, driver);
    if (!session) {
        printf("Failed to create session\n");
        caliptra_destroy_mailbox_driver(driver);
        return -1;
    }
    
    // Connect session
    result = caliptra_session_connect(session);
    if (result != CaliptraSuccess) {
        printf("Failed to connect session\n");
        caliptra_session_destroy(session);
        caliptra_destroy_mailbox_driver(driver);
        return -1;
    }
    
    // Execute get device ID command
    result = caliptra_get_device_id(session, &device_id);
    if (result == CaliptraSuccess) {
        printf("Device ID: 0x%04X\n", device_id.device_id);
        printf("Vendor ID: 0x%04X\n", device_id.vendor_id);
    } else {
        printf("Failed to get device ID\n");
    }
    
    // Cleanup
    caliptra_session_destroy(session);
    caliptra_destroy_mailbox_driver(driver);
    return 0;
}
```

## Mailbox Applications

The `apps/mailbox/` directory contains ready-to-use applications for sending External Mailbox Commands to Caliptra subsystem:

### Mailbox Server (`apps/mailbox/server`)

A UDP-based mailbox server that receives commands and returns responses. The library can be used by the subsystem to receive commands from a client through the network.

```bash
cd apps/mailbox/server
cargo run -- --bind 127.0.0.1:8080
```

### Mailbox Client (`apps/mailbox/client`) 

A client library and validator for sending external mailbox requests to the server (Caliptra subsystem). It also provides a validator application to execute test commands against the target.

```bash
cd apps/mailbox/client
# Run validator against a server
cargo run --example validator -- --server 127.0.0.1:8080
```

## Building

```bash
# Build all crates
cargo build --workspace

# Build C bindings  
cd cbinding && make

# Run integration tests
cd tests && cargo test

# Run C binding tests
cd cbinding/tests && make && make test
```

## Testing

The library includes comprehensive tests:

- **Rust Integration Tests**: `tests/` - Test command execution and session management
- **C Binding Tests**: `cbinding/tests/` - Verify C API functionality  

