// Licensed under the Apache-2.0 license

use thiserror::Error;

/// Errors that can occur when working with OCP EAT tokens
#[derive(Error, Debug)]
pub enum OcpEatError {
    /// COSE parsing or validation error
    #[error("COSE error: {0:?}")]
    CoseSign1(coset::CoseError),
    // Other error variants can be added here as needed
}

impl From<coset::CoseError> for OcpEatError {
    fn from(err: coset::CoseError) -> Self {
        OcpEatError::CoseSign1(err)
    }
}

/// Result type for OCP EAT operations
pub type OcpEatResult<T> = std::result::Result<T, OcpEatError>;