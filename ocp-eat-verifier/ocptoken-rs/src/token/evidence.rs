// Licensed under the Apache-2.0 license

use crate::error::{OcpEatError, OcpEatResult};
use coset::{
    cbor::value::Value, iana::Algorithm, CborSerializable, CoseSign1, Header,
    TaggedCborSerializable,
};
use openssl::{
    bn::{BigNum, BigNumContext},
    ec::{EcGroup, EcKey, EcPoint},
    nid::Nid,
    pkey::PKey,
    x509::X509,
};

pub const OCP_EAT_CLAIMS_KEY_ID: &str = "";
pub const CBOR_TAG_CBOR: u64 = 55799;
pub const CBOR_TAG_CWT: u64 = 61;
pub const CBOR_TAG_COSE_SIGN1: u64 = 18;

/// COSE header parameter: x5chain (label 33)
const COSE_HDR_PARAM_X5CHAIN: i64 = 33;

/// Parsed and verified EAT evidence
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

    /// Decode and structurally validate a COSE_Sign1
    /// (Steps 1–3)
    pub fn decode(slice: &[u8]) -> OcpEatResult<Self> {
        /* ==========================================================
         *  Verify tags & decode COSE_Sign1
         * ========================================================== */
        let cose = parse_tagged_evidence(slice)?;

        /* ==========================================================
         *  Verify protected header
         * ========================================================== */
        verify_protected_header(&cose.protected.header)?;

        Ok(Evidence {
            signed_eat: Some(cose),
        })
    }

    /// Cryptographically verify the decoded COSE_Sign1

    pub fn verify(&self) -> OcpEatResult<()> {
        let cose = self
            .signed_eat
            .as_ref()
            .ok_or_else(|| OcpEatError::InvalidToken("Missing COSE_Sign1"))?;

        /* ----------------------------------------------------------
         *  Extract leaf cert from unprotected header
         * ---------------------------------------------------------- */
        let cert_der = extract_leaf_cert_der(&cose.unprotected)?;
        let (pubkey_x, pubkey_y) = extract_pubkey_xy(&cert_der)?;

        /* ----------------------------------------------------------
         *  Verify ES384 signature
         * ---------------------------------------------------------- */
        cose.verify_signature(&[], |signature, to_be_signed| {
            verify_signature_es384(signature, pubkey_x, pubkey_y, to_be_signed)
        })?;

        Ok(())
    }
}

/* -------------------------------------------------------------------------- */
/*                               Helper functions                              */
/* -------------------------------------------------------------------------- */

fn parse_tagged_evidence(slice: &[u8]) -> OcpEatResult<CoseSign1> {
    let mut value = Value::from_slice(slice).map_err(OcpEatError::CoseSign1)?;

    // Expected tag order
    let mut expected_tags = [CBOR_TAG_CBOR, CBOR_TAG_CWT, CBOR_TAG_COSE_SIGN1].into_iter();

    loop {
        match value {
            Value::Tag(tag, boxed) => {
                let expected = expected_tags
                    .next()
                    .ok_or(OcpEatError::InvalidToken("Unexpected extra CBOR tag"))?;

                if tag != expected {
                    return Err(OcpEatError::InvalidToken(
                        "CBOR tags are not in required order (55799 → 61 → 18)",
                    ));
                }

                value = *boxed;
            }

            // Tagged COSE_Sign1
            Value::Bytes(bytes) => {
                return CoseSign1::from_tagged_slice(&bytes).map_err(OcpEatError::CoseSign1);
            }

            // Bare COSE_Sign1 array
            Value::Array(_) => {
                let bytes = value.to_vec().map_err(OcpEatError::CoseSign1)?;

                return CoseSign1::from_slice(&bytes).map_err(OcpEatError::CoseSign1);
            }

            _ => {
                return Err(OcpEatError::InvalidToken(
                    "Invalid tagged COSE_Sign1 structure",
                ));
            }
        }
    }
}

/// Extract leaf certificate DER from x5chain (label 33)
fn extract_leaf_cert_der(unprotected: &Header) -> OcpEatResult<Vec<u8>> {
    let value = unprotected
        .rest
        .iter()
        .find_map(|(label, value)| {
            if *label == coset::Label::Int(COSE_HDR_PARAM_X5CHAIN) {
                Some(value)
            } else {
                None
            }
        })
        .ok_or(OcpEatError::InvalidToken(
            "Missing x5chain in COSE protected header",
        ))?;

    match value {
        Value::Array(arr) => arr.first(),
        Value::Bytes(_) => Some(value),
        _ => None,
    }
    .and_then(|v| match v {
        Value::Bytes(bytes) => Some(bytes.clone()),
        _ => None,
    })
    .ok_or(OcpEatError::InvalidToken(
        "Missing or invalid x5chain: expected DER-encoded certificate bytes",
    ))
}

/// Extract raw P-384 public key coordinates (x, y) from DER X.509 cert
fn extract_pubkey_xy(cert_der: &[u8]) -> OcpEatResult<([u8; 48], [u8; 48])> {
    // Parse X.509 certificate using OpenSSL
    let cert = X509::from_der(cert_der)
        .map_err(|e| OcpEatError::Certificate(format!("OpenSSL X509 parse failed: {}", e)))?;

    // Extract public key
    let pubkey: PKey<openssl::pkey::Public> = cert
        .public_key()
        .map_err(|e| OcpEatError::Certificate(format!("Failed to extract public key: {}", e)))?;

    // Ensure EC key
    let ec_key = pubkey
        .ec_key()
        .map_err(|_| OcpEatError::Certificate("Public key is not an EC key".into()))?;

    let group = ec_key.group();
    let point = ec_key.public_key();

    let mut ctx = BigNumContext::new().map_err(|e| OcpEatError::Crypto(e.to_string()))?;

    let mut ctx_x = BigNum::new().map_err(|e| OcpEatError::Crypto(e.to_string()))?;
    let mut ctx_y = BigNum::new().map_err(|e| OcpEatError::Crypto(e.to_string()))?;

    point
        .affine_coordinates_gfp(group, &mut ctx_x, &mut ctx_y, &mut ctx)
        .map_err(|e| OcpEatError::Crypto(e.to_string()))?;

    let x_bytes = ctx_x
        .to_vec_padded(48)
        .map_err(|_| OcpEatError::Certificate("Failed to pad X coordinate".into()))?;

    let y_bytes = ctx_y
        .to_vec_padded(48)
        .map_err(|_| OcpEatError::Certificate("Failed to pad Y coordinate".into()))?;

    let mut x = [0u8; 48];
    let mut y = [0u8; 48];

    x.copy_from_slice(&x_bytes);
    y.copy_from_slice(&y_bytes);

    Ok((x, y))
}

/// Verify ES384 COSE signature using raw EC public key
fn verify_signature_es384(
    signature: &[u8],
    pubkey_x: [u8; 48],
    pubkey_y: [u8; 48],
    message: &[u8],
) -> OcpEatResult<()> {
    if signature.len() != 96 {
        return Err(OcpEatError::SignatureVerification);
    }

    let r = BigNum::from_slice(&signature[..48]).map_err(|_| OcpEatError::SignatureVerification)?;
    let s = BigNum::from_slice(&signature[48..]).map_err(|_| OcpEatError::SignatureVerification)?;

    let sig = openssl::ecdsa::EcdsaSig::from_private_components(r, s)
        .map_err(|_| OcpEatError::SignatureVerification)?;

    let group =
        EcGroup::from_curve_name(Nid::SECP384R1).map_err(|e| OcpEatError::Crypto(e.to_string()))?;

    let mut ctx = BigNumContext::new().map_err(|e| OcpEatError::Crypto(e.to_string()))?;

    let px = BigNum::from_slice(&pubkey_x).unwrap();
    let py = BigNum::from_slice(&pubkey_y).unwrap();

    let mut point = EcPoint::new(&group).map_err(|e| OcpEatError::Crypto(e.to_string()))?;

    point
        .set_affine_coordinates_gfp(&group, &px, &py, &mut ctx)
        .map_err(|e| OcpEatError::Crypto(e.to_string()))?;

    let ec_key =
        EcKey::from_public_key(&group, &point).map_err(|e| OcpEatError::Crypto(e.to_string()))?;

    let digest = openssl::hash::hash(openssl::hash::MessageDigest::sha384(), message)
        .map_err(|e| OcpEatError::Crypto(e.to_string()))?;

    let verified = sig
        .verify(&digest, &ec_key)
        .map_err(|e| OcpEatError::Crypto(e.to_string()))?;

    if verified {
        Ok(())
    } else {
        Err(OcpEatError::SignatureVerification)
    }
}

fn verify_protected_header(protected: &Header) -> OcpEatResult<()> {
    /* ----------------------------------------------------------
     *  * Algorithm must be ES384 or ESP384
     * ---------------------------------------------------------- */

    let alg_ok = matches!(
        protected.alg,
        Some(coset::RegisteredLabelWithPrivate::Assigned(
            Algorithm::ES384
        )) | Some(coset::RegisteredLabelWithPrivate::Assigned(
            Algorithm::ESP384
        ))
    );
    if !alg_ok {
        return Err(OcpEatError::InvalidToken(
            "Unexpected algorithm in protected header",
        ));
    }

    /* ----------------------------------------------------------
     * Content-Type
     * ---------------------------------------------------------- */
    match &protected.content_type {
        Some(coset::RegisteredLabel::Assigned(coset::iana::CoapContentFormat::EatCwt)) => {
            // Accept EAT CWT
        }
        None => {
            // Accept missing content-type
        }

        _other => {
            return Err(OcpEatError::InvalidToken(
                "Content format mismatch in protected header",
            ));
        }
    }
    Ok(())
}
