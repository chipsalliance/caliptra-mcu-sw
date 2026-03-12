// Licensed under the Apache-2.0 license

use thiserror::Error;

#[cfg(feature = "openssl")]
pub mod backends;
pub mod decode;
pub mod verifier;

// Convenience re-exports
#[cfg(feature = "openssl")]
pub use backends::openssl::OpenSslBackend;
pub use decode::{DecodedCoseSign1, VerifiedCoseSign1};
pub use verifier::CoseSign1Verifier;

/// Errors that can occur during COSE_Sign1 decoding and verification.
#[derive(Error, Debug)]
pub enum CoseSign1Error {
    /// CBOR/COSE decoding failure.
    #[error("COSE decoding error: {0:?}")]
    CoseDecode(coset::CoseError),

    /// CBOR tag at current position did not match the expected value.
    #[error("Invalid CBOR tag: expected {expected}, found {found}")]
    InvalidTag { expected: u64, found: u64 },

    /// More CBOR tags present than expected.
    #[error("Unexpected extra CBOR tag: {0}")]
    UnexpectedTag(u64),

    /// The inner CBOR structure is not a valid COSE_Sign1.
    #[error("Invalid COSE_Sign1 structure: {0}")]
    InvalidStructure(&'static str),

    /// The protected header does not contain an algorithm field.
    #[error("Missing algorithm in protected header")]
    MissingAlgorithm,

    /// The algorithm in the protected header is not supported.
    #[error("Unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),

    /// X.509 certificate parsing failed.
    #[error("Certificate error: {0}")]
    CertificateError(String),

    /// The cryptographic signature did not verify.
    #[error("Signature verification failed")]
    SignatureVerification,

    /// An error from the underlying crypto backend.
    #[error("Crypto backend error: {0}")]
    CryptoError(String),
}

/// Result type alias for this module.
pub type CoseSign1Result<T> = std::result::Result<T, CoseSign1Error>;

/// Trait abstracting the cryptographic operations needed for
/// COSE_Sign1 signature verification.
///
/// The backend receives the raw DER certificate and handles all
/// key extraction and verification internally, keeping key-type
/// details (EC, ML-DSA, etc.) as an implementation concern.
pub trait CryptoBackend {
    /// Verify a COSE_Sign1 signature using the public key from a
    /// DER-encoded X.509 certificate.
    ///
    /// - `algorithm`: the signing algorithm from the COSE protected header
    /// - `cert_der`: DER-encoded X.509 certificate of the signer
    /// - `signature`: raw COSE signature bytes
    /// - `to_be_signed`: the COSE Sig_structure bytes
    fn verify_signature(
        &self,
        algorithm: SigningAlgorithm,
        cert_der: &[u8],
        signature: &[u8],
        to_be_signed: &[u8],
    ) -> CoseSign1Result<()>;
}

/// Supported COSE signing algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningAlgorithm {
    /// ECDSA w/ SHA-384 on P-384
    ES384,
    /// ML-DSA-87 (post-quantum, FIPS 204)
    MLDSA87,
}

impl SigningAlgorithm {
    /// Try to convert from the coset algorithm type.
    pub fn from_cose_algorithm(
        alg: &coset::RegisteredLabelWithPrivate<coset::iana::Algorithm>,
    ) -> CoseSign1Result<Self> {
        use coset::iana::Algorithm;
        use coset::RegisteredLabelWithPrivate::{Assigned, PrivateUse};
        match alg {
            Assigned(Algorithm::ES384) | Assigned(Algorithm::ESP384) => Ok(SigningAlgorithm::ES384),
            // ML-DSA-87: draft-ietf-cose-dilithium proposes -48
            PrivateUse(n) if *n == -48 => Ok(SigningAlgorithm::MLDSA87),
            other => Err(CoseSign1Error::UnsupportedAlgorithm(format!("{:?}", other))),
        }
    }
}
