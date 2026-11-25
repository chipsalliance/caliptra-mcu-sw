// Licensed under the Apache-2.0 license

//! `spdm-cert-rs`: Pure Rust DMTF SPDM certificate chain decoder.
//!
//! Provides utilities for decoding SPDM GET_CERTIFICATE responses,
//! verifying root certificate digests, splitting concatenated X.509 DER certificates,
//! and decoding DMTF SPDM certificate extensions.

pub mod chain;
pub mod error;
pub mod extensions;
pub mod oids;

pub use chain::{split_der_certs, SpdmCertChain};
pub use error::{Result, SpdmCertError};
pub use extensions::SpdmExtensions;
