// Licensed under the Apache-2.0 license

//! MCTP VDM Transport Module
//!
//! This module provides MCTP VDM (Vendor Defined Message) transport implementation
//! with protocol encoding/decoding for supported VDM commands. It follows the same
//! pattern as the mailbox transport: a trait-based driver abstraction with an
//! encoder/decoder layer that converts generic command IDs and payloads into
//! MCTP VDM packets.

pub mod dispatch;
pub mod encode;
pub mod transport;

// Re-export main types
pub use transport::{MctpVdmDriver, MctpVdmError, MctpVdmTransport};
