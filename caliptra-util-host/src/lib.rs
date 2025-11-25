// Licensed under the Apache-2.0 license

//! Caliptra Utility Host Library
//!
//! A robust library for communicating with Caliptra devices using the Mailbox transport protocol.
//!
//! This library provides a modular architecture for Caliptra device communication with
//! automatic command translation between internal and external formats:
//!
//! - **command-types**: Command structures and type definitions with zerocopy support
//! - **transport**: Mailbox transport layer with command translation
//! - **session**: Session management for command execution
//! - **commands**: High-level API functions for device commands
//! - **osal**: Operating System Abstraction Layer for cross-platform compatibility
//! - **cbinding**: C bindings for interoperability with C applications
//!
//! ## Architecture Overview
//!
//! ```text
//!     ┌─────────────────┐    ┌─────────────────┐
//!     │ caliptra-       │    │ caliptra-       │
//!     │ commands        │    │ command-types   │
//!     │ (High-level API)│    │ (Type Defs)     │
//!     └─────────────────┘    └─────────────────┘
//!              │                       │
//!              └───────────────────────┘
//!                          │
//!             ┌──────────────────┐
//!             │ caliptra-        │
//!             │ session          │
//!             │ (Session Mgmt)   │
//!             └──────────────────┘
//!                      │
//!             ┌──────────────────┐
//!             │ caliptra-        │         ┌─────────────────┐
//!             │ transport        │◄────────│ MailboxDriver   │
//!             │ (Mailbox)        │         │ (UDP, TCP, etc.)│
//!             └──────────────────┘         └─────────────────┘
//!                      │
//!             ┌──────────────────┐
//!             │ caliptra-osal    │
//!             │ (OS Abstraction) │
//!             └──────────────────┘
//! ```
//!
//! ## Features
//!
//! - **Mailbox Protocol**: Native support for Caliptra mailbox command protocol
//! - **Command Translation**: Automatic conversion between internal types and external wire format
//! - **Pluggable Drivers**: Support for different communication mechanisms (UDP, TCP, serial, etc.)
//! - **Type Safety**: Strong typing with zerocopy serialization for performance
//! - **Session Management**: High-level session abstraction with connection management
//! - **Cross-Platform**: OS abstraction layer for portability
//! - **C Bindings**: Complete C API for integration with C applications
//!
//! ## Quick Start
//!
//! ```rust,ignore
//! use caliptra_util_host_session::CaliptraSession;
//! use caliptra_util_host_transport::{Mailbox, MailboxDriver};
//! use caliptra_util_host_commands::api::device_info::caliptra_cmd_get_device_id;
//!
//! // Implement or use a mailbox driver (e.g., UDP-based)
//! struct UdpMailboxDriver { /* ... */ }
//! impl MailboxDriver for UdpMailboxDriver { /* ... */ }
//!
//! // Create mailbox transport with your driver
//! let mut udp_driver = UdpMailboxDriver::new("127.0.0.1:8080".parse()?);
//! let mut mailbox_transport = Mailbox::new(&mut udp_driver);
//!
//! // Create session and connect
//! let mut session = CaliptraSession::new(1, &mut mailbox_transport)?;
//! session.connect()?;
//!
//! // Execute high-level commands
//! let device_id = caliptra_cmd_get_device_id(&mut session)?;
//! println!("Device ID: 0x{:04X}", device_id.device_id);
//! ```

// Re-export main public APIs for convenience
pub use caliptra_util_host_command_types::{
    CaliptraCommandId, GetDeviceCapabilitiesRequest, GetDeviceCapabilitiesResponse,
    GetDeviceIdRequest, GetDeviceIdResponse, GetDeviceInfoRequest, GetDeviceInfoResponse,
    GetFirmwareVersionRequest, GetFirmwareVersionResponse,
};
pub use caliptra_util_host_commands::api::device_info::caliptra_cmd_get_device_id;
pub use caliptra_util_host_session::CaliptraSession;
pub use caliptra_util_host_transport::{Mailbox, Transport};

// Re-export error types
pub use caliptra_util_host_session::SessionError;
pub use caliptra_util_host_transport::TransportError;
