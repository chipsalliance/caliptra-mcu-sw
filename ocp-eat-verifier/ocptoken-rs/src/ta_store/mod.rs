// Licensed under the Apache-2.0 license

#[cfg(feature = "openssl")]
pub mod stores;

#[cfg(feature = "openssl")]
pub use stores::fs::FsTrustAnchorStore;

use thiserror::Error;

/// Errors that can occur when working with the Trust Anchor Store
#[derive(Error, Debug)]
pub enum TrustAnchorError {
    /// No certificate found for the given kid
    #[error("No certificate found for kid: {0}")]
    UnknownKid(String),

    /// Certificate chain does not terminate at a trusted root
    #[error("Untrusted root: chain does not terminate at a known trust anchor")]
    UntrustedRoot,

    /// Certificate chain validation failed
    #[error("Chain validation failed: {0}")]
    ChainValidation(String),

    /// Error loading certificates from the filesystem
    #[error("Failed to load trust anchor store: {0}")]
    Load(String),

    /// OpenSSL error
    #[cfg(feature = "openssl")]
    #[error("OpenSSL error: {0}")]
    OpenSsl(#[from] openssl::error::ErrorStack),

    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Empty certificate chain provided
    #[error("Empty certificate chain")]
    EmptyChain,
}

/// Trait for authenticating signing certificates.
///
/// Implementations provide two authentication paths:
///
/// - [`authenticate_by_kid`](Self::authenticate_by_kid): Look up a signing
///   certificate by `kid`, then validate it chains to a trusted root.
///   Used for CoRIM signers whose certificates are pre-provisioned.
///
/// - [`authenticate_chain`](Self::authenticate_chain): Validate a caller-provided
///   certificate chain against the trusted roots. Used for evidence tokens
///   where the device supplies its certificate chain (e.g. via x5chain).
pub trait TrustAnchorStore {
    /// Authenticate a signing certificate by `kid`.
    ///
    /// Looks up a certificate by the given key identifier, validates that
    /// it chains to a trusted root, and returns the DER-encoded signing
    /// certificate on success.
    fn authenticate_by_kid(&self, kid: &[u8]) -> Result<Vec<u8>, TrustAnchorError>;

    /// Authenticate a caller-provided certificate chain.
    ///
    /// The chain should be ordered leaf-first, with the root (or an
    /// intermediate signed by a trusted root) as the last element.
    ///
    /// Validates the chain against trusted roots and returns the
    /// DER-encoded leaf certificate on success.
    fn authenticate_chain(&self, chain: &[Vec<u8>]) -> Result<Vec<u8>, TrustAnchorError>;
}
