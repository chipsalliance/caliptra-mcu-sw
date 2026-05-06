// Licensed under the Apache-2.0 license

//! SPDM VDM Transport Module
//!
//! This module provides SPDM VDM (Vendor Defined Message) transport implementation
//! for Caliptra commands. It follows the same pattern as the mailbox and MCTP VDM
//! transports: a trait-based driver abstraction with an encoder/decoder layer that
//! converts generic command IDs and payloads into Caliptra VDM wire-format messages
//! sent over SPDM VENDOR_DEFINED_REQUEST/RESPONSE.

pub mod commands;
pub mod dispatch;
pub mod protocol;
pub mod transport;

// Re-export main types
pub use protocol::{CaliptraVdmCommand, CaliptraVdmCompletionCode};
pub use transport::{SpdmVdmDriver, SpdmVdmError, SpdmVdmTransport};
