// Licensed under the Apache-2.0 license

use coset::{cbor::value::Value, sig_structure_data, CborSerializable, CoseSign1, Header};
use openssl::{
    bn::{BigNum, BigNumContext},
    ec::{EcGroup, EcKey, EcPoint},
    nid::Nid,
};

use crate::error::{OcpEatError, OcpEatResult};

use x509_parser::prelude::*;

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
            Ok(cose) => {
                println!("coset strict decode succeeded");
                cose
            }
            Err(e) => {
                println!("coset strict decode failed: {:?}", e);
                println!("Dumping CBOR structure to identify offending tag/value:");
                debug_dump_cbor(slice);
                return Err(OcpEatError::CoseSign1(e));
            }
        };

        /* ----------------------------------------------------------
         * 3. Verify protected header
         * ---------------------------------------------------------- */
        verify_protected_header(&cose.protected.header)?;

        //  Extract payload

        let payload = cose.payload.as_deref().ok_or_else(|| {
            OcpEatError::CoseSign1(coset::CoseError::UnexpectedItem("nil", "bstr payload"))
        })?;

        /* ----------------------------------------------------------
         * 4. Extract leaf cert from unprotected header
         * ---------------------------------------------------------- */

        let cert_der = extract_leaf_cert_der(&cose.unprotected)?;
        dump_cert_der(&cert_der);
        let (pubkey_x, pubkey_y) = extract_pubkey_xy(&cert_der)?;

        /* ----------------------------------------------------------
         * 5. Reconstruct Sig_structure (SPEC-CORRECT)
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

        println!("success decoded");

        Ok(Evidence {
            signed_eat: Some(cose),
        })
    }
}

/* -------------------------------------------------------------------------- */
/*                               Helper functions                              */
/* -------------------------------------------------------------------------- */

use std::fs::File;
use std::io::Write;

fn debug_dump_cbor(slice: &[u8]) {
    match Value::from_slice(slice) {
        Ok(v) => {
            println!("Top-level CBOR value: {:?}", v);
            dump_cbor_value(&v, 0);
        }
        Err(e) => {
            println!("CBOR parse failed before COSE: {:?}", e);
        }
    }
}

fn dump_cbor_value(v: &Value, indent: usize) {
    let pad = "  ".repeat(indent);

    match v {
        Value::Tag(tag, inner) => {
            println!("{pad}CBOR Tag: {}", tag);
            dump_cbor_value(inner, indent + 1);
        }
        Value::Map(map) => {
            println!("{pad}CBOR Map:");
            for (k, v) in map {
                println!("{pad}  Key: {:?}", k);
                println!("{pad}  Value:");
                dump_cbor_value(v, indent + 2);
            }
        }
        Value::Array(arr) => {
            println!("{pad}CBOR Array (len={}):", arr.len());
            for (i, item) in arr.iter().enumerate() {
                println!("{pad}  [{i}]");
                dump_cbor_value(item, indent + 2);
            }
        }
        other => {
            println!("{pad}{:?}", other);
        }
    }
}

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

    println!("done Unwrap CBOR tags / bstr (Python skip_cbor_tags)");
    Ok(value)
}

fn dump_cert_der(cert_der: &[u8]) {
    let mut f = File::create("x5chain_cert.der").expect("failed to create x5chain_cert.der");
    f.write_all(cert_der).expect("failed to write cert DER");
    println!(
        "Wrote x5chain cert to x5chain_cert.der ({} bytes)",
        cert_der.len()
    );
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
    // Parse X.509 certificate (pure Rust, lenient)
    let cert = match X509Certificate::from_der(cert_der) {
        Ok((rem, cert)) => {
            println!("X509Certificate::from_der OK");
            println!("Remaining bytes after parse: {}", rem.len());
            cert
        }
        Err(e) => {
            println!("X509Certificate::from_der FAILED");
            println!("Error: {:?}", e);

            return Err(OcpEatError::Certificate(format!(
                "X509 parse error: {:?}",
                e
            )));
        }
    };

    println!(" X509Certificate::from_der");

    let spki = &cert.tbs_certificate.subject_pki;

    // subject_public_key is a BIT STRING
    let pubkey_bytes = spki.subject_public_key.data.as_ref();

    // Expect uncompressed EC point: 04 || X || Y (P-384)
    if pubkey_bytes.len() != 1 + 48 + 48 {
        return Err(OcpEatError::Certificate(format!(
            "unexpected EC public key length: {}",
            pubkey_bytes.len()
        )));
    }

    if pubkey_bytes[0] != 0x04 {
        return Err(OcpEatError::Certificate(
            "EC public key is not uncompressed".into(),
        ));
    }

    let mut x = [0u8; 48];
    let mut y = [0u8; 48];

    x.copy_from_slice(&pubkey_bytes[1..49]);
    y.copy_from_slice(&pubkey_bytes[49..97]);

    println!("extract_pubkey_xy: success");

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
        Some(coset::RegisteredLabelWithPrivate::Assigned(alg)) => {
            println!("protected.alg (IANA) = {:?}", alg);
        }
        Some(coset::RegisteredLabelWithPrivate::PrivateUse(v)) => {
            println!("protected.alg (private-use) = {}", v);
        }
        Some(coset::RegisteredLabelWithPrivate::Text(t)) => {
            println!("protected.alg (text) = {}", t);
        }
        None => {
            return Err(OcpEatError::CoseSign1(coset::CoseError::UnexpectedItem(
                "alg", "present",
            )));
        }
    }
    Ok(())
}
