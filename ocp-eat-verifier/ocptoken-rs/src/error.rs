// Licensed under the Apache-2.0 license

use thiserror::Error;
/// Errors that can occur when working with OCP EAT tokens
#[derive(Error, Debug)]
pub enum OcpEatError {
    /// COSE parsing or validation error
    #[error("COSE error: {0:?}")]
    CoseSign1(coset::CoseError),

    #[error("Invalid token: {0}")]
    InvalidToken(&'static str),

    /// Certificate parsing error
    #[error("Certificate error: {0}")]
    Certificate(String),

    /// Signature verification failure
    #[error("Signature verification failed")]
    SignatureVerification,

    /// Crypto backend error
    #[error("Crypto error: {0}")]
    Crypto(String),
}

impl From<coset::CoseError> for OcpEatError {
    fn from(err: coset::CoseError) -> Self {
        OcpEatError::CoseSign1(err)
    }
}

/// Result type for OCP EAT operations
pub type OcpEatResult<T> = std::result::Result<T, OcpEatError>;
