// Licensed under the Apache-2.0 license

extern crate alloc;

use crate::profile_config::*;
use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;
use coset::{cbor::value::Value, cwt::ClaimsSetBuilder, iana, CborSerializable, Header};
use libapi_caliptra::certificate::{CertContext, KEY_LABEL_SIZE};
use libapi_caliptra::crypto::asym::AsymAlgo;
use libapi_caliptra::crypto::hash::{HashAlgoType, HashContext, SHA384_HASH_SIZE};
use libapi_caliptra::crypto::rng::Rng;
use libapi_caliptra::error::{CaliptraApiError, CaliptraApiResult};
use libapi_caliptra::evidence::concise_evidence::generate_concise_evidence;

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
        let payload = self.generate_payload(&self.eat_nonce).await?;
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

        ocp_cwt_slice[..sign1_data.len()].copy_from_slice(&sign1_data);
        Ok(sign1_data.len())
    }

    fn key_id(&self) -> &'static str {
        match self.eat_type {
            OcpEatType::EatClaims => OCP_EAT_CLAIMS_KEY_ID,
            OcpEatType::EnvelopeCsr => OCP_ENVELOPE_CSR_KEY_ID,
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

    async fn generate_payload(&self, eat_nonce: &[u8]) -> CaliptraApiResult<Vec<u8>> {
        if eat_nonce.len() < OCP_MIN_EAT_NONCE_SIZE || eat_nonce.len() > OCP_MAX_EAT_NONCE_SIZE {
            return Err(CaliptraApiError::InvalidArgument("eat_nonce"));
        }
        match self.eat_type {
            OcpEatType::EatClaims => self.generate_eat_claims(eat_nonce).await,
            OcpEatType::EnvelopeCsr => self.generate_envelope_csr(eat_nonce).await,
        }
    }

    async fn generate_envelope_csr(&self, _eat_nonce: &[u8]) -> CaliptraApiResult<Vec<u8>> {
        Ok(Vec::new())
    }

    async fn generate_eat_claims(&self, eat_nonce: &[u8]) -> CaliptraApiResult<Vec<u8>> {
        let eat_nonce = eat_nonce.to_vec();
        let measurements = generate_concise_evidence().await?;
        let mut cti: Vec<u8> = vec![0; eat_nonce.len()];
        let debug_state: u8 = DEFAULT_DEBUG_STATE; //TODO: Update based on actual debug state
        Rng::generate_random_number(cti.as_mut_slice()).await?;
        let claims = ClaimsSetBuilder::new()
            .issuer("Caliptra EAT Leaf Attestation Key".to_string())
            .cwt_id(cti)
            .claim(iana::CwtClaimName::EatNonce, Value::Bytes(eat_nonce))
            .claim(
                iana::CwtClaimName::Dbgstat,
                Value::Integer(debug_state.into()),
            )
            .claim(iana::CwtClaimName::Measurements, Value::Bytes(measurements))
            .claim(
                iana::CwtClaimName::EatProfile,
                Value::Bytes(OCP_SECURITY_OID.to_vec()),
            )
            .private_claim(
                -70_000,
                Value::Array(vec![Value::Text(DEFAULT_RIM_LOCATOR.to_string())]),
            )
            // .claim(
            // iana::CwtClaimName::Dloas,
            // Value::Array(vec![Value::Text("US".to_string())]),
            // )
            // .claim(iana::CwtClaimName::Ueid, Value::Bytes(DUMMY_UEID.to_vec()))
            // .claim(iana::CwtClaimName::Oemid, Value::Bytes(OEM_ID.to_vec()))
            // .claim(iana::CwtClaimName::Hwmodel, Value::Bytes(HW_MODEL.to_vec()))
            // .claim(iana::CwtClaimName::Uptime, Value::Integer(123456.into()))
            // .claim(iana::CwtClaimName::Bootcount, Value::Integer(1.into()))
            // .claim(
            //     iana::CwtClaimName::Bootseed,
            //     Value::Bytes([0xABu8; 32].to_vec()),
            // )
            .build();
        let claims_bytes = claims
            .to_vec()
            .map_err(|_| CaliptraApiError::CosetSerializeError)?;
        Ok(claims_bytes)
    }
}
