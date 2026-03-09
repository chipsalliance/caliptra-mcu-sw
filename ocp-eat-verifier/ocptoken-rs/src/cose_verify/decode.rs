// Licensed under the Apache-2.0 license

use super::{CoseSign1Error, CoseSign1Result};
use coset::{cbor::value::Value, CborSerializable, CoseSign1, Header, TaggedCborSerializable};

/// A decoded but **not yet cryptographically verified** COSE_Sign1.
///
/// This type provides read access to the headers and payload. It is
/// obtained via `DecodedCoseSign1::decode()` and can be passed to
/// `CoseSign1Verifier::verify()` for signature verification.
pub struct DecodedCoseSign1 {
    pub(super) inner: CoseSign1,
}

impl DecodedCoseSign1 {
    /// Decode a COSE_Sign1 from raw bytes, stripping the expected CBOR
    /// tag sequence.
    ///
    /// Pass an empty slice for `expected_tags` if no outer tag wrapping
    /// is expected (bare COSE_Sign1).
    pub fn decode(bytes: &[u8], expected_tags: &[u64]) -> CoseSign1Result<Self> {
        let inner = strip_tags_and_decode(bytes, expected_tags)?;
        Ok(Self { inner })
    }

    /// Access the protected header.
    pub fn protected_header(&self) -> &Header {
        &self.inner.protected.header
    }

    /// Access the unprotected header.
    pub fn unprotected_header(&self) -> &Header {
        &self.inner.unprotected
    }

    /// Access the payload bytes (if present; `None` for detached payloads).
    pub fn payload(&self) -> Option<&[u8]> {
        self.inner.payload.as_deref()
    }
}

/// A cryptographically **verified** COSE_Sign1.
///
/// This type can only be obtained via `CoseSign1Verifier::verify()`,
/// providing a type-level guarantee that the signature was checked.
pub struct VerifiedCoseSign1 {
    inner: CoseSign1,
}

impl VerifiedCoseSign1 {
    pub(super) fn new(inner: CoseSign1) -> Self {
        Self { inner }
    }

    /// Access the verified payload.
    pub fn payload(&self) -> Option<&[u8]> {
        self.inner.payload.as_deref()
    }

    /// Access the protected header.
    pub fn protected_header(&self) -> &Header {
        &self.inner.protected.header
    }

    /// Access the unprotected header.
    pub fn unprotected_header(&self) -> &Header {
        &self.inner.unprotected
    }
}

/// Strip the expected CBOR tag sequence from `data` and decode the
/// inner COSE_Sign1.
///
/// - If `expected_tags` is empty, `data` is parsed directly as a
///   bare (untagged) COSE_Sign1.
/// - If `expected_tags` is non-empty, the tags are stripped in order
///   and then the inner value is decoded.
fn strip_tags_and_decode(data: &[u8], expected_tags: &[u64]) -> CoseSign1Result<CoseSign1> {
    if expected_tags.is_empty() {
        return CoseSign1::from_slice(data).map_err(CoseSign1Error::CoseDecode);
    }

    let mut value = Value::from_slice(data).map_err(CoseSign1Error::CoseDecode)?;
    let mut tag_iter = expected_tags.iter();

    loop {
        match value {
            Value::Tag(found_tag, boxed) => {
                match tag_iter.next() {
                    Some(&expected) => {
                        if found_tag != expected {
                            return Err(CoseSign1Error::InvalidTag {
                                expected,
                                found: found_tag,
                            });
                        }
                    }
                    None => {
                        return Err(CoseSign1Error::UnexpectedTag(found_tag));
                    }
                }
                value = *boxed;
            }
            Value::Bytes(bytes) => {
                return CoseSign1::from_tagged_slice(&bytes).map_err(CoseSign1Error::CoseDecode);
            }
            Value::Array(_) => {
                let bytes = value.to_vec().map_err(CoseSign1Error::CoseDecode)?;
                return CoseSign1::from_slice(&bytes).map_err(CoseSign1Error::CoseDecode);
            }
            _ => {
                return Err(CoseSign1Error::InvalidStructure(
                    "Expected CBOR Tag, Bytes, or Array for COSE_Sign1",
                ));
            }
        }
    }
}
