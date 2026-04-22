// Licensed under the Apache-2.0 license

use thiserror::Error;
/// Errors that can occur when working with OCP EAT tokens
#[derive(Error, Debug)]
pub enum OcpEatError {
    #[error("Invalid token: {0}")]
    InvalidToken(&'static str),

    /// Certificate parsing error
    #[error("Certificate error: {0}")]
    Certificate(String),

    /// Error from the common CoseSign1 verification module
    #[error("CoseSign1 verification: {0}")]
    Verification(#[from] crate::cose_verify::CoseSign1Error),

    /// Trust anchor store error
    #[error("Trust anchor: {0}")]
    TrustAnchor(#[from] crate::ta_store::TrustAnchorError),

    /// Claims decoding error
    #[error("Claims decode: {0}")]
    ClaimsDecode(#[from] coset::CoseError),

    /// Measurements decoding error
    #[error("Measurements decode: {0}")]
    MeasurementsDecode(String),
}

/// Result type for OCP EAT operations
pub type OcpEatResult<T> = std::result::Result<T, OcpEatError>;
