// Licensed under the Apache-2.0 license

use crate::cose_verify::authenticate::{HeaderSelection, SignerIdMethod};
use crate::cose_verify::{
    authenticate_signer, AuthenticateOptions, CoseSign1Verifier, CryptoBackend, DecodedCoseSign1,
};
use crate::error::{OcpEatError, OcpEatResult};
use crate::ta_store::TrustAnchorStore;
use coset::iana::Algorithm;

pub const OCP_EAT_CLAIMS_KEY_ID: &str = "";
pub const CBOR_TAG_CBOR: u64 = 55799;
pub const CBOR_TAG_CWT: u64 = 61;
pub const CBOR_TAG_COSE_SIGN1: u64 = 18;

/// OCP EAT profile: CBOR self-describe (55799) -> CWT (61) -> COSE_Sign1 (18)
pub const OCP_EAT_TAGS: &[u64] = &[CBOR_TAG_CBOR, CBOR_TAG_CWT, CBOR_TAG_COSE_SIGN1];

/// Parsed and verified EAT evidence.
///
/// Wraps a `DecodedCoseSign1` from the common verification module,
/// adding OCP EAT-specific header validation and certificate chain
/// authentication via a [`TrustAnchorStore`].
pub struct Evidence<'a> {
    decoded: DecodedCoseSign1,
    ta_store: &'a dyn TrustAnchorStore,
}

impl<'a> Evidence<'a> {
    /// Decode and structurally validate a COSE_Sign1 with OCP EAT
    /// tag wrapping (55799 -> 61 -> 18).
    pub fn decode(slice: &[u8], ta_store: &'a dyn TrustAnchorStore) -> OcpEatResult<Self> {
        let decoded = DecodedCoseSign1::decode(slice, OCP_EAT_TAGS)?;

        verify_eat_protected_header(decoded.protected_header())?;

        Ok(Evidence { decoded, ta_store })
    }

    /// Authenticate the signing key against the Trust Anchor Store.
    ///
    /// `cert_chain_blob` is a concatenated DER certificate chain from
    /// the device (e.g. from SPDM GET_CERTIFICATE), ordered root-first:
    /// `[root | intermediate(s) | device_leaf]`.
    ///
    /// The device leaf (last cert in the blob) is dropped and replaced
    /// with the leaf certificate(s) from the x5chain in the evidence
    /// unprotected header. The resulting chain is passed to the Trust
    /// Anchor Store in leaf-first order for validation.
    ///
    /// Pass an empty slice if the x5chain already contains the full chain.
    ///
    /// Returns the DER-encoded authenticated leaf certificate on success.
    pub fn authenticate(&self, cert_chain_blob: &[u8]) -> OcpEatResult<Vec<u8>> {
        let options = AuthenticateOptions {
            header: HeaderSelection::Unprotected,
            method: SignerIdMethod::X5chain,
        };
        Ok(authenticate_signer(
            &self.decoded,
            self.ta_store,
            cert_chain_blob,
            &options,
        )?)
    }

    /// Authenticate the signing key and cryptographically verify
    /// the COSE_Sign1 signature.
    ///
    /// Equivalent to calling [`authenticate`](Self::authenticate)
    /// followed by signature verification with the returned leaf cert.
    pub fn verify(
        &self,
        cert_chain_blob: &[u8],
        verifier: &CoseSign1Verifier<impl CryptoBackend>,
    ) -> OcpEatResult<()> {
        let authenticated_leaf = self.authenticate(cert_chain_blob)?;
        verifier.verify_ref(&self.decoded, &authenticated_leaf)?;
        Ok(())
    }
}

/// EAT-specific protected header checks (algorithm + content-type).
fn verify_eat_protected_header(protected: &coset::Header) -> OcpEatResult<()> {
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

    match &protected.content_type {
        Some(coset::RegisteredLabel::Assigned(coset::iana::CoapContentFormat::EatCwt)) => {}
        None => {}
        _other => {
            return Err(OcpEatError::InvalidToken(
                "Content format mismatch in protected header",
            ));
        }
    }

    Ok(())
}
