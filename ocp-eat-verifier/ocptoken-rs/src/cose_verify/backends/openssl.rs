// Licensed under the Apache-2.0 license

use crate::cose_verify::{CoseSign1Error, CryptoBackend, SigningAlgorithm};

use openssl::{
    bn::BigNum,
    ecdsa::EcdsaSig,
    hash::MessageDigest,
    nid::Nid,
    pkey::{Id, PKey},
    sign::Verifier,
    x509::X509,
};

/// OpenSSL-based implementation of `CryptoBackend`.
///
/// Algorithm-agnostic: detects key type from the certificate and
/// dispatches to the appropriate verification path.
///
/// - ECDSA (ES384): converts COSE raw r||s signature to DER, then
///   verifies via EVP.
/// - ML-DSA-87: passes the signature directly to EVP (no conversion
///   needed).
#[derive(Debug, Clone, Copy, Default)]
pub struct OpenSslBackend;

impl CryptoBackend for OpenSslBackend {
    fn verify_signature(
        &self,
        _algorithm: SigningAlgorithm,
        cert_der: &[u8],
        signature: &[u8],
        to_be_signed: &[u8],
    ) -> Result<(), CoseSign1Error> {
        // Parse X.509 certificate and extract public key
        let cert = X509::from_der(cert_der).map_err(|e| {
            CoseSign1Error::CertificateError(format!("Failed to parse X.509 certificate: {}", e))
        })?;

        let pubkey: PKey<openssl::pkey::Public> = cert.public_key().map_err(|e| {
            CoseSign1Error::CertificateError(format!("Failed to extract public key: {}", e))
        })?;

        // Detect key type and prepare the signature for OpenSSL
        let key_id = pubkey.id();
        let (der_sig, digest) = match key_id {
            Id::EC => {
                let ec_key = pubkey.ec_key().map_err(|e| {
                    CoseSign1Error::CertificateError(format!("Failed to read EC key: {}", e))
                })?;

                // Determine coordinate size from the EC curve
                let group = ec_key.group();
                let nid = group
                    .curve_name()
                    .ok_or_else(|| CoseSign1Error::CertificateError("Unknown EC curve".into()))?;
                let (coord_size, md) = ec_curve_params(nid)?;

                // Convert COSE raw r||s to DER-encoded ECDSA signature
                let expected_len = coord_size * 2;
                if signature.len() != expected_len {
                    return Err(CoseSign1Error::SignatureVerification);
                }

                let r = BigNum::from_slice(&signature[..coord_size])
                    .map_err(|_| CoseSign1Error::SignatureVerification)?;
                let s = BigNum::from_slice(&signature[coord_size..])
                    .map_err(|_| CoseSign1Error::SignatureVerification)?;

                let ecdsa_sig = EcdsaSig::from_private_components(r, s)
                    .map_err(|_| CoseSign1Error::SignatureVerification)?;

                let der = ecdsa_sig
                    .to_der()
                    .map_err(|_| CoseSign1Error::SignatureVerification)?;

                (der, Some(md))
            }
            // ML-DSA and other non-EC algorithms: signature is used as-is,
            // no digest (signing is internal to the algorithm).
            _ => (signature.to_vec(), None),
        };

        // Verify using the EVP API (algorithm-agnostic)
        let mut verifier = match digest {
            Some(md) => Verifier::new(md, &pubkey),
            None => Verifier::new_without_digest(&pubkey),
        }
        .map_err(|e| CoseSign1Error::CryptoError(format!("Verifier init failed: {}", e)))?;

        verifier
            .update(to_be_signed)
            .map_err(|e| CoseSign1Error::CryptoError(e.to_string()))?;

        let valid = verifier
            .verify(&der_sig)
            .map_err(|e| CoseSign1Error::CryptoError(e.to_string()))?;

        if valid {
            Ok(())
        } else {
            Err(CoseSign1Error::SignatureVerification)
        }
    }
}

/// Get the ECDSA coordinate size and digest for a given EC curve NID.
fn ec_curve_params(nid: Nid) -> Result<(usize, MessageDigest), CoseSign1Error> {
    match nid {
        Nid::X9_62_PRIME256V1 => Ok((32, MessageDigest::sha256())),
        Nid::SECP384R1 => Ok((48, MessageDigest::sha384())),
        Nid::SECP521R1 => Ok((66, MessageDigest::sha512())),
        _ => Err(CoseSign1Error::UnsupportedAlgorithm(format!(
            "Unsupported EC curve: {:?}",
            nid
        ))),
    }
}
