// Licensed under the Apache-2.0 license

use crate::error::{OcpEatError, OcpEatResult};
use coset::{cbor::value::Value, sig_structure_data, CborSerializable, CoseSign1, Header};

use openssl::{
    bn::{BigNum, BigNumContext},
    ec::{EcGroup, EcKey, EcPoint},
    nid::Nid,
    pkey::PKey,
    x509::X509,
};

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

    /// Decode and verify a COSE_Sign1
    pub fn decode(slice: &[u8]) -> OcpEatResult<Self> {
        /* ----------------------------------------------------------
         * 1. Skip CBOR tags / bstr
         * ---------------------------------------------------------- */
        let value = skip_cbor_tags(slice)?;
        let cose_bytes = value.to_vec().map_err(OcpEatError::CoseSign1)?;

        /* ----------------------------------------------------------
         * 2. Strict COSE decode
         * ---------------------------------------------------------- */
        let cose = match CoseSign1::from_slice(&cose_bytes) {
            Ok(cose) => cose,
            Err(e) => {
                return Err(OcpEatError::CoseSign1(e));
            }
        };

        /* ----------------------------------------------------------
         * 3. Verify protected header
         * ---------------------------------------------------------- */
        verify_protected_header(&cose.protected.header)?;

        //  Extract payload

        let payload = cose
            .payload
            .as_deref()
            .ok_or_else(|| OcpEatError::InvalidToken("Payload missing"))?;

        /* ----------------------------------------------------------
         * 4. Extract leaf cert from unprotected header
         * ---------------------------------------------------------- */

        let cert_der = extract_leaf_cert_der(&cose.unprotected)?;
        let (pubkey_x, pubkey_y) = extract_pubkey_xy(&cert_der)?;

        /* ----------------------------------------------------------
         * 5. Reconstruct Sig_structure
         * ---------------------------------------------------------- */

        let sig_structure = sig_structure_data(
            coset::SignatureContext::CoseSign1,
            cose.protected.clone(), // uses original_data internally
            None,
            &[],
            payload,
        );

        /* ----------------------------------------------------------
         * 6. Verify ES384 signature using pubkey and
         * ---------------------------------------------------------- */
        verify_signature_es384(&cose.signature, pubkey_x, pubkey_y, &sig_structure)?;

        Ok(Evidence {
            signed_eat: Some(cose),
        })
    }
}

/* -------------------------------------------------------------------------- */
/*                               Helper functions                              */
/* -------------------------------------------------------------------------- */

fn skip_cbor_tags(slice: &[u8]) -> OcpEatResult<Value> {
    let mut value = Value::from_slice(slice).map_err(OcpEatError::CoseSign1)?;

    loop {
        match value {
            Value::Tag(_, boxed) => value = *boxed,
            Value::Bytes(bytes) => {
                value = Value::from_slice(&bytes).map_err(OcpEatError::CoseSign1)?
            }
            Value::Array(_) => break,
            _ => {
                return Err(OcpEatError::CoseSign1(coset::CoseError::UnexpectedItem(
                    "tag / bstr / array",
                    "unexpected CBOR wrapper",
                )));
            }
        }
    }

    Ok(value)
}

/// Extract leaf certificate DER from x5chain (label 33)
fn extract_leaf_cert_der(unprotected: &Header) -> OcpEatResult<Vec<u8>> {
    let value = unprotected
        .rest
        .iter()
        .find_map(|(label, value)| {
            if *label == coset::Label::Int(33) {
                Some(value)
            } else {
                None
            }
        })
        .ok_or_else(|| {
            OcpEatError::CoseSign1(coset::CoseError::UnexpectedItem("x5chain", "present"))
        })?;

    match value {
        Value::Array(arr) => arr.first(),
        Value::Bytes(_) => Some(value),
        _ => None,
    }
    .and_then(|v| match v {
        Value::Bytes(bytes) => Some(bytes.clone()), // 👈 CLONE
        _ => None,
    })
    .ok_or_else(|| {
        OcpEatError::CoseSign1(coset::CoseError::UnexpectedItem(
            "x5chain",
            "DER cert bytes",
        ))
    })
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
    match &protected.alg {
        Some(coset::RegisteredLabelWithPrivate::Assigned(_alg)) => {}
        Some(coset::RegisteredLabelWithPrivate::PrivateUse(_v)) => {}
        Some(coset::RegisteredLabelWithPrivate::Text(_t)) => {}
        None => {
            return Err(OcpEatError::CoseSign1(coset::CoseError::UnexpectedItem(
                "alg", "present",
            )));
        }
    }
    Ok(())
}
