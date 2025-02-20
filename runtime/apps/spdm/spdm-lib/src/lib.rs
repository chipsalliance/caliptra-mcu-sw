// Licensed under the Apache-2.0 license

#![no_std]

// Common errors
pub mod error;

// Codec and protocol buffer
// pub mod codec;
pub mod message_buf;

// Spdm common msg header stuff
pub mod protocol;

// Context and request handling
pub mod context;
pub mod error_rsp;
pub mod req_resp_codes;
pub mod version_rsp;

// Spdm responder state
pub mod state;

// Transport layer stuff
pub mod transport;

pub use context::MAX_SPDM_MSG_SIZE;
pub use version_rsp::SpdmVersion;
