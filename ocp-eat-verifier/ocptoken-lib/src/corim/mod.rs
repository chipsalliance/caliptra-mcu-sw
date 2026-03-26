// Licensed under the Apache-2.0 license

//! Signed CoRIM authentication and verification.
//!
//! Each signed CoRIM is a COSE_Sign1 envelope (CBOR tag 18) produced by
//! `cocli corim sign`. The signing certificate is carried in the x5chain
//! (label 33) of the **protected** header and authenticated against the
//! Trust Anchor Store before the signature is verified.
//!
//! # Usage
//!
//! ```ignore
//! let corims = SignedCorim::decode_files(&corims_dir, &ta_store)?;
//! for corim in &corims {
//!     corim.authenticate()?;
//!     corim.verify(&verifier)?;
//! }
//! ```

pub mod refval;
pub use refval::RefValCorims;

use std::fs;
use std::path::Path;

use crate::cose_verify::{authenticate_signer, CoseSign1Verifier, CryptoBackend, DecodedCoseSign1};
use crate::ta_store::TrustAnchorStore;

/// CBOR tag for COSE_Sign1.
const CBOR_TAG_COSE_SIGN1: u64 = 18;

/// A decoded signed CoRIM bound to a [`TrustAnchorStore`].
///
/// Mirrors the [`Evidence`](crate::token::evidence::Evidence) pattern:
/// decode first, then authenticate and verify as separate steps.
pub struct SignedCorim<'a> {
    decoded: DecodedCoseSign1,
    ta_store: &'a dyn TrustAnchorStore,
    file_name: String,
}

impl<'a> SignedCorim<'a> {
    /// Decode a single signed CoRIM from raw CBOR bytes.
    pub fn decode(
        data: &[u8],
        file_name: String,
        ta_store: &'a dyn TrustAnchorStore,
    ) -> CorimResult<Self> {
        let decoded = DecodedCoseSign1::decode(data, &[CBOR_TAG_COSE_SIGN1]).map_err(|e| {
            CorimError::Decode {
                file: file_name.clone(),
                source: e,
            }
        })?;

        Ok(SignedCorim {
            decoded,
            ta_store,
            file_name,
        })
    }

    /// Decode all `.cbor` files in a directory, returning a `SignedCorim`
    /// for each one.
    pub fn decode_files(dir: &Path, ta_store: &'a dyn TrustAnchorStore) -> CorimResult<Vec<Self>> {
        let entries = collect_cbor_entries(dir)?;
        let mut corims = Vec::with_capacity(entries.len());

        for entry in &entries {
            let path = entry.path();
            let file_name = path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string();

            let data = fs::read(&path).map_err(|e| CorimError::FileRead {
                file: file_name.clone(),
                source: e,
            })?;

            corims.push(Self::decode(&data, file_name, ta_store)?);
        }

        Ok(corims)
    }

    /// Authenticate the signing certificate against the Trust Anchor Store.
    ///
    /// Returns the DER-encoded authenticated leaf certificate on success.
    pub fn authenticate(&self) -> CorimResult<Vec<u8>> {
        authenticate_signer(&self.decoded, self.ta_store, &[], &Default::default()).map_err(|e| {
            CorimError::Authentication {
                file: self.file_name.clone(),
                source: e,
            }
        })
    }

    /// Authenticate the signing certificate and verify the COSE_Sign1
    /// signature.
    pub fn verify(&self, verifier: &CoseSign1Verifier<impl CryptoBackend>) -> CorimResult<()> {
        let signing_cert = self.authenticate()?;
        verifier
            .verify_ref(&self.decoded, &signing_cert)
            .map_err(|e| CorimError::SignatureVerification {
                file: self.file_name.clone(),
                source: e,
            })?;
        Ok(())
    }

    /// Decode the COSE_Sign1 payload into a `corim_rs::CorimMap`.
    ///
    /// This should be called after [`verify()`](Self::verify) to access the
    /// reference values, endorsed values, and other CoRIM content carried
    /// inside the signed envelope.
    pub fn payload(&self) -> CorimResult<corim_rs::CorimMap<'static>> {
        let payload_bytes = self.decoded.payload().ok_or(CorimError::NoPayload {
            file: self.file_name.clone(),
        })?;
        let corim: corim_rs::Corim<'static> =
            corim_rs::Corim::from_cbor(payload_bytes).map_err(|e| CorimError::PayloadDecode {
                file: self.file_name.clone(),
                detail: e.to_string(),
            })?;
        Ok(corim.into_map())
    }

    /// The file name this CoRIM was loaded from.
    pub fn file_name(&self) -> &str {
        &self.file_name
    }
}

/// Errors from signed CoRIM operations.
#[derive(Debug, thiserror::Error)]
pub enum CorimError {
    #[error("directory does not exist: {0}")]
    DirNotFound(String),

    #[error("failed to read directory '{path}': {source}")]
    ReadDir {
        path: String,
        source: std::io::Error,
    },

    #[error("no .cbor files found in directory: {0}")]
    NoCborFiles(String),

    #[error("{file}: read error: {source}")]
    FileRead {
        file: String,
        source: std::io::Error,
    },

    #[error("{file}: COSE_Sign1 decode failed: {source}")]
    Decode {
        file: String,
        source: crate::cose_verify::CoseSign1Error,
    },

    #[error("{file}: signer authentication failed: {source}")]
    Authentication {
        file: String,
        source: crate::cose_verify::CoseSign1Error,
    },

    #[error("{file}: signature verification failed: {source}")]
    SignatureVerification {
        file: String,
        source: crate::cose_verify::CoseSign1Error,
    },

    #[error("{file}: COSE_Sign1 payload is missing")]
    NoPayload { file: String },

    #[error("{file}: CoRIM payload decode failed: {detail}")]
    PayloadDecode { file: String, detail: String },
}

pub type CorimResult<T> = std::result::Result<T, CorimError>;

/// Collect sorted `.cbor` file entries from a directory.
pub(crate) fn collect_cbor_entries(dir: &Path) -> CorimResult<Vec<fs::DirEntry>> {
    if !dir.is_dir() {
        return Err(CorimError::DirNotFound(dir.display().to_string()));
    }

    let mut entries: Vec<_> = fs::read_dir(dir)
        .map_err(|e| CorimError::ReadDir {
            path: dir.display().to_string(),
            source: e,
        })?
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().map_or(false, |ext| ext == "cbor"))
        .collect();
    entries.sort_by_key(|e| e.file_name());

    if entries.is_empty() {
        return Err(CorimError::NoCborFiles(dir.display().to_string()));
    }

    Ok(entries)
}
