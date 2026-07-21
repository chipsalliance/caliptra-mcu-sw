// Licensed under the Apache-2.0 license

#![allow(clippy::not_unsafe_ptr_arg_deref)]
#![allow(clippy::unnecessary_cast)]
#![allow(clippy::clone_on_copy)]

//! Caliptra Utility Host Library C Bindings
//!
//! This library provides C-compatible wrapper functions for the actual caliptra-util-host library.

// Core C binding modules
pub mod command;
pub mod error; // Error type mappings and conversions
pub mod session; // Session management C bindings (real implementations)
pub mod transport; // Transport layer C bindings (real implementations)

pub mod custom_transport;
pub mod mailbox_transport; // Mailbox transport // Custom transport support

// Re-export the main API - avoid conflicts by being specific
pub use command::*;
pub use custom_transport::*;
pub use error::CaliptraError;
pub use mailbox_transport::*;
pub use session::*;
pub use transport::*;
