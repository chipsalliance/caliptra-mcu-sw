// Licensed under the Apache-2.0 license

extern crate alloc;

use crate::certificate::{CertContext, KEY_LABEL_SIZE};
use crate::crypto::asym::AsymAlgo;
use crate::crypto::hash::{HashAlgoType, HashContext, SHA384_HASH_SIZE};
use crate::error::{CaliptraApiError, CaliptraApiResult};
use alloc::vec::Vec;
use coset::{cbor::value::Value, iana, CborSerializable, Header};

// Temp value, to be replaced with actual max size
const OCP_MIN_EAT_NONCE_SIZE: usize = 8;
const OCP_MAX_EAT_NONCE_SIZE: usize = 64;

pub enum OcpEatType {
    EatClaims,
    EnvelopeCsr,
}

pub struct OcpEatCwt {
    eat_type: OcpEatType,
    asym_algo: AsymAlgo,
    eat_nonce: Vec<u8>,
    leaf_cert_label: [u8; KEY_LABEL_SIZE],
}

impl OcpEatCwt {
    pub fn new(
        eat_type: OcpEatType,
        asym_algo: AsymAlgo,
        eat_nonce: &[u8],
        leaf_cert_label: &[u8; KEY_LABEL_SIZE],
    ) -> CaliptraApiResult<Self> {
        if eat_nonce.len() < OCP_MIN_EAT_NONCE_SIZE || eat_nonce.len() > OCP_MAX_EAT_NONCE_SIZE {
            return Err(CaliptraApiError::InvalidArgument("eat_nonce"));
        }
        let mut leaf_label = [0u8; KEY_LABEL_SIZE];
        leaf_label.copy_from_slice(leaf_cert_label);
        Ok(OcpEatCwt {
            eat_type,
            asym_algo,
            eat_nonce: eat_nonce.to_vec(),
            leaf_cert_label: leaf_label,
        })
    }

    pub async fn generate_ocp_eat(&self, ocp_cwt_slice: &mut [u8]) -> CaliptraApiResult<usize> {
        let protected = self.protected_header()?;
        let unprotected = self.unprotected_header(Some(&self.leaf_cert_label)).await?;
        let payload = self.generate_payload(&self.eat_nonce)?;
        let aad = b"";

        let protected_hdr = coset::ProtectedHeader {
            original_data: None,
            header: protected.clone(),
        };

        let tbs = coset::sig_structure_data(
            coset::SignatureContext::CoseSign1,
            protected_hdr.clone(),
            None,
            aad,
            &payload,
        );

        let mut hash = [0u8; SHA384_HASH_SIZE];
        HashContext::hash_all(HashAlgoType::SHA384, &tbs, &mut hash).await?;
        let mut cert_ctx = CertContext::new();
        let mut sig = [0u8; 96];
        cert_ctx
            .sign(Some(&self.leaf_cert_label), &hash, &mut sig)
            .await?;

        let sign1 = coset::CoseSign1Builder::new()
            .protected(protected)
            .unprotected(unprotected)
            .payload(payload)
            .create_signature(aad, |_tbs| sig.to_vec())
            .build();

        let sign1_data = sign1
            .to_vec()
            .map_err(|_| CaliptraApiError::CosetSerializeError)?;

        ocp_cwt_slice.copy_from_slice(&sign1_data);
        Ok(sign1_data.len())
    }

    fn key_id(&self) -> &'static str {
        match self.eat_type {
            OcpEatType::EatClaims => "OCP EAT Claims",
            OcpEatType::EnvelopeCsr => "OCP Envelope CSR",
        }
    }

    fn protected_header(&self) -> CaliptraApiResult<Header> {
        let algo = match self.asym_algo {
            AsymAlgo::EccP384 => iana::Algorithm::ESP384,
        };

        let kid = self.key_id().as_bytes().to_vec();

        let protected = coset::HeaderBuilder::new()
            .algorithm(algo)
            .content_format(iana::CoapContentFormat::EatCwt)
            .key_id(kid)
            .build();

        Ok(protected)
    }

    async fn unprotected_header(
        &self,
        label: Option<&[u8; KEY_LABEL_SIZE]>,
    ) -> CaliptraApiResult<Header> {
        let mut cert_ctx = CertContext::new();
        let mut cert_buf = [0u8; 1024];
        let cert_size = cert_ctx
            .certify_key(&mut cert_buf, label, None, None)
            .await?;
        let cert = &cert_buf[..cert_size];
        let x5_chain = Value::Bytes(cert.to_vec());

        let unprotected = coset::HeaderBuilder::new().value(33, x5_chain).build();

        Ok(unprotected)
    }

    fn generate_payload(&self, eat_nonce: &[u8]) -> CaliptraApiResult<Vec<u8>> {
        if eat_nonce.len() < OCP_MIN_EAT_NONCE_SIZE || eat_nonce.len() > OCP_MAX_EAT_NONCE_SIZE {
            return Err(CaliptraApiError::InvalidArgument("eat_nonce"));
        }
        Ok(Vec::new())
    }
}
