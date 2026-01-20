// Licensed under the Apache-2.0 license

//! COSE (CBOR Object Signing and Encryption) functionality
//!
//! This module provides structures and encoding functions for COSE Sign1
//! as defined in RFC 8152.

use crate::cbor::CborEncoder;
use crate::error::EatError;
use arrayvec::ArrayVec;

/// COSE header parameter as a key-value pair
#[derive(Debug, Clone, Copy)]
pub struct CoseHeaderPair<'a> {
    pub key: i32,
    pub value: &'a [u8],
}

/// COSE protected header structure
#[derive(Debug, Clone, Copy)]
pub struct ProtectedHeader {
    pub alg: i32, // Algorithm identifier
    pub content_type: Option<u16>,
    pub kid: Option<&'static [u8]>, // Key identifier
}

impl ProtectedHeader {
    /// Create a new protected header for ES384 (ECDSA with P-384 and SHA-384)
    pub fn new_es384() -> Self {
        Self {
            alg: -51, // ES384 algorithm ID
            content_type: None,
            kid: None,
        }
    }

    /// Estimate the size required for encoding this protected header
    pub fn estimate_size(&self) -> usize {
        let mut size = 0;

        // Map header (1-9 bytes, typically 1 byte for small maps)
        let mut entries = 1u64; // alg is mandatory
        if self.content_type.is_some() {
            entries = entries.saturating_add(1);
        }
        if self.kid.is_some() {
            entries = entries.saturating_add(1);
        }
        size += if entries < 24 { 1 } else { 9 };

        // Key 1 (alg): 1 byte + algorithm value (1-5 bytes for i32)
        size += 1;
        size += if self.alg >= -24 && self.alg < 24 {
            1
        } else {
            5
        };

        // Key 3 (content_type): 1 byte + value (1-3 bytes for u16)
        if let Some(content_type) = self.content_type {
            size += 1; // key
            size += if content_type < 24 {
                1
            } else if content_type < 256 {
                2
            } else {
                3
            };
        }

        // Key 4 (kid): 1 byte + byte string header + kid length
        if let Some(kid) = self.kid {
            size += 1; // key
            size += if kid.len() < 24 { 1 } else { 5 }; // byte string header
            size += kid.len(); // actual kid bytes
        }

        size
    }

    /// Encode the protected header into the provided buffer
    pub fn encode(&self, buffer: &mut [u8]) -> Result<usize, EatError> {
        // Estimate and validate buffer size
        let estimated_size = self.estimate_size();
        if buffer.len() < estimated_size {
            return Err(EatError::BufferTooSmall);
        }

        let mut encoder = CborEncoder::new(buffer);

        // Calculate number of entries
        let mut entries = 1u64; // alg is mandatory
        if self.content_type.is_some() {
            entries = entries.saturating_add(1);
        }
        if self.kid.is_some() {
            entries = entries.saturating_add(1);
        }

        encoder.encode_map_header(entries)?;

        // alg (label 1): algorithm identifier
        encoder.encode_int(1)?;
        encoder.encode_int(self.alg as i64)?;

        // content_type (label 3): content type (optional)
        if let Some(content_type) = self.content_type {
            encoder.encode_int(3)?;
            encoder.encode_uint(content_type as u64)?;
        }

        // kid (label 4): key identifier (optional)
        if let Some(kid) = self.kid {
            encoder.encode_int(4)?;
            encoder.encode_bytes(kid)?;
        }

        Ok(encoder.len())
    }
}

/// Constants for common COSE header parameters
pub mod cose_headers {
    pub const X5CHAIN: i32 = 33; // X.509 Certificate Chain
}

/// Default maximum size for the encoded protected header.
/// The current protected header uses at most the `alg`, `content_type`, and `kid` fields.
pub const DEFAULT_PROTECTED_HEADER_SIZE: usize = 256;

/// COSE Sign1 encoder with builder pattern and configurable protected header buffer
pub struct CoseSign1WithBuffer<'a, const PROTECTED_SIZE: usize> {
    encoder: CborEncoder<'a>,
    protected_header: Option<&'a ProtectedHeader>,
    unprotected_headers: Option<&'a [CoseHeaderPair<'a>]>,
    payload: Option<&'a [u8]>,
    signature: Option<&'a [u8]>,
}

/// Default COSE Sign1 encoder using [`DEFAULT_PROTECTED_HEADER_SIZE`].
pub type CoseSign1<'a> = CoseSign1WithBuffer<'a, DEFAULT_PROTECTED_HEADER_SIZE>;

impl<'a, const PROTECTED_SIZE: usize> CoseSign1WithBuffer<'a, PROTECTED_SIZE> {
    /// Create a new COSE Sign1 encoder with the given buffer
    pub fn new(buffer: &'a mut [u8]) -> Self {
        Self {
            encoder: CborEncoder::new(buffer),
            protected_header: None,
            unprotected_headers: None,
            payload: None,
            signature: None,
        }
    }

    /// Create COSE Sign1 signature context (as per RFC 8152)
    ///
    /// Creates the Sig_structure for COSE_Sign1 as defined in RFC 8152 Section 4.4:
    /// ```text
    /// Sig_structure = [
    ///    "Signature1",   // Context string for COSE_Sign1
    ///    protected,      // Protected header (serialized)
    ///    external_aad,   // Empty for basic use
    ///    payload         // The payload to be signed
    /// ]
    /// ```
    ///
    /// For most algorithms, this data should be hashed before signing.
    pub fn get_signature_context(&self, context_buffer: &mut [u8]) -> Result<usize, EatError> {
        // Encode protected header to temporary buffer
        let protected_buffer = self.encode_protected_header_to_buffer()?;
        let payload = self.payload.ok_or(EatError::MissingMandatoryClaim)?;

        // Create signature context
        let mut encoder = CborEncoder::new(context_buffer);

        // CBOR encode the Sig_structure array
        encoder.encode_array_header(4)?; // Array of 4 items

        // "Signature1" as text string
        encoder.encode_text("Signature1")?;

        // Protected header as byte string
        encoder.encode_bytes(&protected_buffer)?;

        // External AAD as empty byte string
        encoder.encode_bytes(&[])?;

        // Payload as byte string
        encoder.encode_bytes(payload)?;

        Ok(encoder.len())
    }

    fn encode_unprotected_header(
        encoder: &mut CborEncoder,
        headers: &[CoseHeaderPair],
    ) -> Result<(), EatError> {
        encoder.encode_map_header(headers.len() as u64)?;

        for header in headers {
            encoder.encode_int(header.key as i64)?;
            encoder.encode_bytes(header.value)?;
        }

        Ok(())
    }

    /// Encode the protected header into an ArrayVec buffer
    fn encode_protected_header_to_buffer(&self) -> Result<ArrayVec<u8, PROTECTED_SIZE>, EatError> {
        let mut protected_buffer = ArrayVec::new();
        let protected = self
            .protected_header
            .ok_or(EatError::MissingMandatoryClaim)?;

        // Encode into a temporary array, then copy to ArrayVec
        let mut temp_buffer = [0u8; PROTECTED_SIZE];
        let len = protected.encode(&mut temp_buffer)?;
        protected_buffer
            .try_extend_from_slice(&temp_buffer[..len])
            .map_err(|_| EatError::BufferTooSmall)?;

        Ok(protected_buffer)
    }

    /// Set the protected header
    pub fn protected_header(mut self, header: &'a ProtectedHeader) -> Self {
        self.protected_header = Some(header);
        self
    }

    /// Set the unprotected headers
    pub fn unprotected_headers(mut self, headers: &'a [CoseHeaderPair<'a>]) -> Self {
        self.unprotected_headers = Some(headers);
        self
    }

    /// Set the payload
    pub fn payload(mut self, payload: &'a [u8]) -> Self {
        self.payload = Some(payload);
        self
    }

    /// Set the signature
    pub fn signature(mut self, signature: &'a [u8]) -> Self {
        self.signature = Some(signature);
        self
    }

    /// Encode the COSE_Sign1 structure with optional outer tags
    /// Always encodes tag 18 (COSE_Sign1). Additional outer tags can be provided.
    /// If additional_tags is Some, they are encoded before tag 18.
    pub fn encode(mut self, additional_tags: Option<&[u64]>) -> Result<usize, EatError> {
        // Encode additional tags first if provided
        if let Some(tags) = additional_tags {
            for tag in tags {
                self.encoder.encode_tag(*tag)?;
            }
        }

        // Always encode COSE_Sign1 tag (18)
        self.encoder.encode_cose_sign1_tag()?;

        // Then encode the COSE_Sign1 array
        self.encoder.encode_array_header(4)?;

        // Encode protected header to temporary buffer
        let protected_buffer = self.encode_protected_header_to_buffer()?;
        self.encoder.encode_bytes(&protected_buffer)?;

        // Unprotected header as map
        let unprotected = self.unprotected_headers.unwrap_or(&[]);
        Self::encode_unprotected_header(&mut self.encoder, unprotected)?;

        // Payload as byte string
        let payload = self.payload.ok_or(EatError::MissingMandatoryClaim)?;
        self.encoder.encode_bytes(payload)?;

        // Signature as byte string
        let signature = self.signature.ok_or(EatError::MissingMandatoryClaim)?;
        self.encoder.encode_bytes(signature)?;

        Ok(self.encoder.len())
    }
}
