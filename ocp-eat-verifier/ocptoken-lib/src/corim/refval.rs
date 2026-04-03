// Licensed under the Apache-2.0 license

//! Reference-value CoRIM collection.

use std::path::Path;

use crate::corim::{CorimResult, SignedCorim};
use crate::cose_verify::{CoseSign1Verifier, CryptoBackend};
use crate::ta_store::TrustAnchorStore;

/// A collection of verified and decoded reference-value CoRIM payloads.
///
/// Each entry is the source file name paired with the decoded [`corim_rs::CorimMap`].
/// This struct is produced by [`RefValCorims::decode_and_verify`] and can be
/// passed to later stages (printing, appraisal) without re-decoding.
pub struct RefValCorims {
    pub entries: Vec<(String, corim_rs::CorimMap<'static>)>,
}

impl RefValCorims {
    /// Decode, authenticate, verify, and extract payloads from all signed
    /// CoRIM `.cbor` files in `dir`.
    pub fn decode_and_verify(
        dir: &Path,
        ta_store: &dyn TrustAnchorStore,
        verifier: &CoseSign1Verifier<impl CryptoBackend>,
    ) -> CorimResult<Self> {
        let entries = SignedCorim::decode_files(dir, ta_store)?
            .iter()
            .map(|c| {
                c.verify(verifier)?;
                Ok((c.file_name().to_string(), c.payload()?))
            })
            .collect::<CorimResult<Vec<_>>>()?;

        Ok(Self { entries })
    }

    /// Returns `true` if there are no CoRIM entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Iterate over `(file_name, corim_map)` pairs.
    pub fn iter(&self) -> impl Iterator<Item = &(String, corim_rs::CorimMap<'static>)> {
        self.entries.iter()
    }
}
