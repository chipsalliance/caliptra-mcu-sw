// Licensed under the Apache-2.0 license

use crate::cose_verify::decode::{DecodedCoseSign1, VerifiedCoseSign1};
use crate::cose_verify::{CoseSign1Error, CoseSign1Result, CryptoBackend, SigningAlgorithm};

/// The main entry point for COSE_Sign1 signature verification.
///
/// `CoseSign1Verifier` is generic over a `CryptoBackend`, which
/// provides the actual cryptographic operations. The caller is
/// responsible for authenticating and providing the signing certificate.
///
/// # Usage
///
/// ```rust,ignore
/// use ocptoken::cose_verify::{CoseSign1Verifier, DecodedCoseSign1, OpenSslBackend};
/// use ocptoken::token::evidence::OCP_EAT_TAGS;
///
/// let verifier = CoseSign1Verifier::new(OpenSslBackend);
/// let decoded = DecodedCoseSign1::decode(&bytes, OCP_EAT_TAGS)?;
/// let verified = verifier.verify(decoded, &signing_cert_der)?;
/// let payload = verified.payload();
/// ```
pub struct CoseSign1Verifier<C: CryptoBackend> {
    crypto: C,
}

impl<C: CryptoBackend> CoseSign1Verifier<C> {
    /// Create a new verifier with the given crypto backend.
    pub fn new(crypto: C) -> Self {
        Self { crypto }
    }

    /// Verify the signature on a decoded COSE_Sign1, consuming the
    /// `DecodedCoseSign1` and returning a `VerifiedCoseSign1` on success.
    pub fn verify(
        &self,
        decoded: DecodedCoseSign1,
        cert_der: &[u8],
    ) -> CoseSign1Result<VerifiedCoseSign1> {
        self.verify_inner(&decoded, cert_der)?;
        Ok(VerifiedCoseSign1::new(decoded.inner))
    }

    /// Verify the signature without consuming the decoded token.
    /// Returns `Ok(())` on success.
    pub fn verify_ref(&self, decoded: &DecodedCoseSign1, cert_der: &[u8]) -> CoseSign1Result<()> {
        self.verify_inner(decoded, cert_der)
    }

    fn verify_inner(&self, decoded: &DecodedCoseSign1, cert_der: &[u8]) -> CoseSign1Result<()> {
        // 1. Extract and validate algorithm
        let cose_alg = decoded
            .protected_header()
            .alg
            .as_ref()
            .ok_or(CoseSign1Error::MissingAlgorithm)?;
        let algorithm = SigningAlgorithm::from_cose_algorithm(cose_alg)?;

        // 2. Verify signature using coset's Sig_structure construction
        let crypto = &self.crypto;
        decoded
            .inner
            .verify_signature(&[], |signature, tbs| {
                crypto
                    .verify_signature(algorithm, cert_der, signature, tbs)
                    .map_err(|_| {
                        coset::CoseError::UnexpectedItem("invalid signature", "valid signature")
                    })
            })
            .map_err(|_| CoseSign1Error::SignatureVerification)?;

        Ok(())
    }
}
