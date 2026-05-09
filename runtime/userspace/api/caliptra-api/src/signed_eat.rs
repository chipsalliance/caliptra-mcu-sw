// Licensed under the Apache-2.0 license

use crate::certificate::{CertContext, KEY_LABEL_SIZE};
use crate::crypto::asym::{AsymAlgo, ECC_P384_SIGNATURE_SIZE};
use crate::crypto::hash::{HashAlgoType, HashContext, SHA384_HASH_SIZE};
use crate::error::{CaliptraApiError, CaliptraApiResult};
use crate::mailbox_api::MAX_ECC_CERT_SIZE;
use ocp_eat::{cbor_tags, header_params, CoseHeaderPair, CoseSign1, ProtectedHeader};

const MAX_SIG_CONTEXT_SIZE: usize = 2048;

pub struct SignedEat<'a> {
    asym_algo: AsymAlgo,
    leaf_cert_label: &'a [u8; KEY_LABEL_SIZE],
}

impl<'a> SignedEat<'a> {
    pub fn new(
        asym_algo: AsymAlgo,
        leaf_cert_label: &'a [u8; KEY_LABEL_SIZE],
    ) -> CaliptraApiResult<SignedEat<'a>> {
        if asym_algo != AsymAlgo::EccP384 {
            return Err(CaliptraApiError::AsymAlgoUnsupported);
        }
        Ok(SignedEat {
            asym_algo,
            leaf_cert_label,
        })
    }

    pub async fn generate(
        &self,
        payload: &[u8],
        eat_buffer: &mut [u8],
    ) -> CaliptraApiResult<usize> {
        // Prepare protected header
        let protected_header = ProtectedHeader::new_es384();

        // Prepare unprotected header with certificate chain
        let mut ecc_cert: [u8; MAX_ECC_CERT_SIZE] = [0; MAX_ECC_CERT_SIZE];
        let cert_size = self.get_leaf_cert(&mut ecc_cert).await?;
        let x5chain_header = CoseHeaderPair {
            key: header_params::X5CHAIN,
            value: &ecc_cert[..cert_size],
        };
        let unprotected_headers = [x5chain_header];

        // Initialize COSE_Sign1 encoder with protected header, unprotected headers, and payload
        let cose_sign1 = CoseSign1::new(eat_buffer)
            .protected_header(&protected_header)
            .unprotected_headers(&unprotected_headers)
            .payload(payload);

        // Get signature context for signing
        let mut sig_context_buffer = [0u8; MAX_SIG_CONTEXT_SIZE];
        let sig_context_len = cose_sign1
            .get_signature_context(&mut sig_context_buffer)
            .map_err(CaliptraApiError::Eat)?;

        // Generate signature from context
        let signature = self
            .sign_context(&sig_context_buffer[..sig_context_len])
            .await?;

        // Complete encoding with signature and EAT tags
        cose_sign1
            .signature(&signature[..])
            .encode(Some(&[cbor_tags::SELF_DESCRIBED_CBOR, cbor_tags::CWT]))
            .map_err(CaliptraApiError::Eat)
    }

    async fn get_leaf_cert(&self, cert_buf: &mut [u8]) -> CaliptraApiResult<usize> {
        if self.asym_algo != AsymAlgo::EccP384 {
            return Err(CaliptraApiError::AsymAlgoUnsupported);
        }

        let mut cert_context = CertContext::new();
        let cert_size = cert_context
            .certify_key(cert_buf, Some(self.leaf_cert_label), None, None)
            .await?;
        Ok(cert_size)
    }

    async fn sign_context(
        &self,
        sig_context: &[u8],
    ) -> CaliptraApiResult<[u8; ECC_P384_SIGNATURE_SIZE]> {
        if self.asym_algo != AsymAlgo::EccP384 {
            Err(CaliptraApiError::AsymAlgoUnsupported)?;
        }

        // Hash the signature context
        let mut hash = [0u8; SHA384_HASH_SIZE];
        HashContext::hash_all(HashAlgoType::SHA384, sig_context, &mut hash).await?;

        // Sign the hash
        let mut cert_context = CertContext::new();
        let mut sig = [0u8; ECC_P384_SIGNATURE_SIZE];
        cert_context
            .sign(Some(self.leaf_cert_label), &hash, &mut sig)
            .await?;

        Ok(sig)
    }
}
