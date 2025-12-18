// Licensed under the Apache-2.0 license

use coset::{cbor::value::Value, CborSerializable, CoseSign1, Header};
use openssl::{hash::MessageDigest, pkey::PKey, sign::Verifier, x509::X509};

use crate::error::{OcpEatError, OcpEatResult};

pub struct Evidence {
    pub signed_eat: Option<CoseSign1>,
}

impl Default for Evidence {
    fn default() -> Self {
        Evidence { signed_eat: None }
    }
}

impl Evidence {
    pub fn new(signed_eat: CoseSign1) -> Self {
        Evidence {
            signed_eat: Some(signed_eat),
        }
    }

    /// Decode a CBOR-encoded COSE_Sign1, extract the signing certificate
    /// from unprotected header (label 33), and verify the  signature.
    pub fn decode(slice: &[u8]) -> OcpEatResult<Self> {
        // 1️ Decode CBOR → COSE_Sign1
        let cose = CoseSign1::from_slice(slice)?;

        //  Payload must be present
        cose.payload.as_deref().ok_or_else(|| {
            OcpEatError::CoseSign1(coset::CoseError::UnexpectedItem("nil", "bstr payload"))
        })?;

        // 2 Extract certificate from unprotected header
        let cert_der = extract_cert(&cose.unprotected)?;

        //  Parse cert → public key
        let pubkey = extract_pubkey_from_cert(cert_der)?;

        // 3 Verify signature using COSE API
        cose.verify_signature(&[], |sig_structure, signature| {
            verify_ecdsa_p384(&pubkey, sig_structure, signature)
        })?;

        Ok(Evidence::new(cose))
    }
}

/// Extract DER-encoded certificate from  COSE x5chain header (label 33)
fn extract_cert(unprotected: &Header) -> OcpEatResult<&[u8]> {
    unprotected
        .rest
        .iter()
        .find_map(|(label, value)| {
            if *label == coset::Label::Int(33) {
                match value {
                    Value::Bytes(bytes) => Some(bytes.as_slice()),
                    _ => None,
                }
            } else {
                None
            }
        })
        .ok_or_else(|| {
            OcpEatError::CoseSign1(coset::CoseError::UnexpectedItem(
                "x5chain missing",
                "x5chain (label 33) in unprotected header",
            ))
        })
}

/// Parse X.509 cert and extract public key
fn extract_pubkey_from_cert(cert_der: &[u8]) -> OcpEatResult<PKey<openssl::pkey::Public>> {
    let cert = X509::from_der(cert_der).map_err(|e| OcpEatError::Certificate(e.to_string()))?;

    cert.public_key()
        .map_err(|e| OcpEatError::Certificate(e.to_string()))
}

/// OpenSSL-backed ECDSA-P384 verification
fn verify_ecdsa_p384(
    pubkey: &PKey<openssl::pkey::Public>,
    sig_structure: &[u8],
    signature: &[u8],
) -> OcpEatResult<()> {
    let mut verifier = Verifier::new(MessageDigest::sha384(), pubkey)
        .map_err(|e| OcpEatError::Crypto(e.to_string()))?;

    verifier
        .update(sig_structure)
        .map_err(|e| OcpEatError::Crypto(e.to_string()))?;

    let verified = verifier
        .verify(signature)
        .map_err(|e| OcpEatError::Crypto(e.to_string()))?;

    if verified {
        Ok(())
    } else {
        Err(OcpEatError::SignatureVerification)
    }
}
