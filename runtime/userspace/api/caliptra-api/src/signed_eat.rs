// Licensed under the Apache-2.0 license

use crate::certificate::{CertContext, KEY_LABEL_SIZE, MAX_ECC_CERT_SIZE};
use crate::crypto::asym::{AsymAlgo, ECC_P384_SIGNATURE_SIZE};
use crate::crypto::hash::{HashAlgoType, HashContext, SHA384_HASH_SIZE};
use crate::error::{CaliptraApiError, CaliptraApiResult};
use ocp_eat::eat_encoder;
use ocp_eat::eat_encoder::{
    cose_headers, CborEncoder, CoseHeaderPair, EatEncoder, ProtectedHeader,
};

const MAX_HEADER_SIZE: usize = 256;
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
        // prepare COSE headers

        // prepare protected header
        let protected_header = ProtectedHeader::new_es384();

        // prepare unprotected header
        let mut ecc_cert: [u8; MAX_ECC_CERT_SIZE] = [0; MAX_ECC_CERT_SIZE];
        let cert_size = self.get_leaf_cert(&mut ecc_cert).await?;
        let x5chain_header = CoseHeaderPair {
            key: cose_headers::X5CHAIN,
            value: &ecc_cert[..cert_size],
        };
        let unprotected_headers = [x5chain_header];

        let mut protected_hdr_buf = [0u8; MAX_HEADER_SIZE];

        // Encode protected header
        let protected_hdr_len = {
            let mut encoder = CborEncoder::new(&mut protected_hdr_buf);
            encoder
                .encode_protected_header(&protected_header)
                .map_err(CaliptraApiError::Eat)?;
            encoder.len()
        };

        // Generate ECC signature
        let signature = self
            .generate_ecc_signature(&protected_hdr_buf[..protected_hdr_len], payload)
            .await?;

        // Now encode the complete COSE Sign1 structure
        EatEncoder::encode_cose_sign1_eat(
            eat_buffer,
            &protected_header,
            &unprotected_headers,
            payload,
            &signature[..],
        )
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

    async fn generate_ecc_signature(
        &self,
        protected_hdr: &[u8],
        payload: &[u8],
    ) -> CaliptraApiResult<[u8; ECC_P384_SIGNATURE_SIZE]> {
        if self.asym_algo != AsymAlgo::EccP384 {
            Err(CaliptraApiError::AsymAlgoUnsupported)?;
        }

        let mut sig_context_buffer = [0u8; MAX_SIG_CONTEXT_SIZE];
        let sig_context_len =
            eat_encoder::create_sign1_context(&mut sig_context_buffer, protected_hdr, payload)
                .map_err(CaliptraApiError::Eat)?;

        let tbs = &sig_context_buffer[..sig_context_len];

        let mut hash = [0u8; SHA384_HASH_SIZE];
        HashContext::hash_all(HashAlgoType::SHA384, tbs, &mut hash).await?;
        let mut cert_context = CertContext::new();
        let mut sig = [0u8; ECC_P384_SIGNATURE_SIZE];

        cert_context
            .sign(Some(self.leaf_cert_label), &hash, &mut sig)
            .await?;

        Ok(sig)
    }
}
