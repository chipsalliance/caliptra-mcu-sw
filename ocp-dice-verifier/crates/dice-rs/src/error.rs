// Licensed under the Apache-2.0 license

//! Error types for `dice-rs`.

use thiserror::Error;

/// Result alias for `dice-rs` operations.
pub type Result<T> = core::result::Result<T, DiceError>;

/// Errors that can occur during DICE extension decoding and processing.
#[derive(Debug, Error)]
pub enum DiceError {
    /// Failed to parse ASN.1 DER structure.
    #[error("ASN.1 DER parsing error: {0}")]
    Asn1(String),

    /// Missing expected DICE extension in certificate.
    #[error("Missing DICE extension with OID: {0}")]
    MissingExtension(String),

    /// Invalid or unsupported DICE extension format.
    #[error("Invalid DICE extension format: {0}")]
    InvalidExtension(String),

    /// Certificate parsing error.
    #[cfg(feature = "std")]
    #[error("X.509 certificate parsing error: {0}")]
    Certificate(String),
}
