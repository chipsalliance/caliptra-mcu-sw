# Caliptra Mailbox Applications

This directory contains client and server applications for communicating with Caliptra devices over UDP networks.

## Overview

The mailbox applications provide a network-based interface to Caliptra devices, allowing remote command execution and device simulation:

- **Client**: Sends Caliptra mailbox commands over UDP to a remote device or simulator
- **Server**: Simulates a Caliptra device, responding to mailbox commands over UDP

## Architecture

```
┌─────────────────┐       UDP      ┌─────────────────┐
│  Mailbox Client │◄──────────────►│  Mailbox Server │
│                 │                │   (Simulator)   │
│ ┌─────────────┐ │                │ ┌─────────────┐ │
│ │   Session   │ │                │ │  Command    │ │
│ └─────────────┘ │                │ │  Processor  │ │
│ ┌─────────────┐ │                │ └─────────────┘ │
│ │   Mailbox   │ │                │ ┌─────────────┐ │
│ └─────────────┘ │                │ │   Device    │ │
│ ┌─────────────┐ │                │ │ Simulator   │ │
│ │ UDP         │ │                │ └─────────────┘ │
│ │ Driver      │ │                └─────────────────┘
│ └─────────────┘ │
└─────────────────┘
```

## Quick Start

### 1. Start the Server (Device Simulator)

```bash
cd apps/mailbox/server
cargo run -- --bind 127.0.0.1:8080
```

### 2. Run the Client Validator

```bash
cd apps/mailbox/client
# Run validation tests against the server
use caliptra_mailbox_client::Validator;

let validator = Validator::new("127.0.0.1:8080".parse()?);
let results = validator.start()?;
for result in results {
    println!("Test '{}': {}", result.test_name, 
        if result.passed { "PASSED" } else { "FAILED" });
}
```

## Use Cases

### Development and Testing
- Test Caliptra command implementations without hardware
- Develop and debug client applications
- Validate command serialization/deserialization

### Integration Testing
- Simulate device responses for CI/CD pipelines
- Test network communication layers
- Validate error handling scenarios

### Remote Device Access
- Access Caliptra devices over network infrastructure
- Centralized device management
- Remote debugging and diagnostics

## Supported Commands

Currently implemented:
- **GetDeviceId**: Retrieve device identification information (vendor ID, device ID, subsystem information)

## Network Protocol

### UDP Transport
- **Protocol**: UDP datagrams with simple framing: `[4 bytes command ID][payload]`
- **Transport**: UdpTransportDriver implements MailboxDriver interface
- **Reliability**: Application-level acknowledgment through request/response pattern
- **Use Case**: Low-latency local network communication with Caliptra devices

### Architecture Integration

The mailbox applications demonstrate the full transport stack:

1. **UdpTransportDriver**: Implements `MailboxDriver` for UDP communication
2. **Mailbox Transport**: Provides `Transport` interface with command translation  
3. **CaliptraSession**: Session management and command execution
4. **High-level API**: Type-safe command functions (e.g., `caliptra_cmd_get_device_id`)

This layered approach allows easy substitution of transport mechanisms while maintaining the same high-level API.

## Client Library

The client provides:
- **MailboxClient**: High-level client for command execution
- **Validator**: Automated validation framework for testing
- **UdpTransportDriver**: UDP-based mailbox driver implementation

## Server Application

The server provides:
- **Mock mailbox responses**: Simulates Caliptra device behavior
- **Configurable device parameters**: Set device ID, vendor ID, etc.
- **Protocol compliance**: Implements external mailbox command specification