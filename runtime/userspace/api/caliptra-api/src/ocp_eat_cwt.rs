// use coset::{cbor::value::Value, cwt::ClaimsSetBuilder, iana, CborSerializable, Header};
use crate::certificate::{CertContext, KEY_LABEL_SIZE, MAX_ECC_CERT_SIZE};
use crate::crypto::asym::{AsymAlgo, ECC_P384_SIGNATURE_SIZE};
use crate::crypto::hash::{HashAlgoType, HashContext, SHA384_HASH_SIZE};
use crate::crypto::rng::Rng;
use crate::error::{CaliptraApiError, CaliptraApiResult};
use crate::evidence::concise_evidence::generate_concise_evidence;
use ocp_eat::eat_encoder;
use ocp_eat::eat_encoder::{
    cose_headers, CborEncoder, ConciseEvidence, ConciseEvidenceMap, CoseHeaderPair, DebugStatus,
    EatEncoder, EvTriplesMap, MeasurementFormat, OcpEatClaims, ProtectedHeader,
    TaggedConciseEvidence,
};

const OCP_SECURITY_OID: &str = "1.3.6.1.4.1.42623.1";
const MAX_HEADER_SIZE: usize = 256;
const MAX_PAYLOAD_SIZE: usize = 1024;
const MAX_SIG_CONTEXT_SIZE: usize = 2048;

pub enum OcpEatType {
    EatClaims,
    EnvelopeCsr,
}

pub struct OcpEatCwt<'a> {
    eat_type: OcpEatType,
    asym_algo: AsymAlgo,
    eat_nonce: &'a [u8],
    leaf_cert_label: &'a [u8; KEY_LABEL_SIZE],
    issuer: &'a str,
}

impl<'a> OcpEatCwt<'a> {
    pub fn new(
        eat_type: OcpEatType,
        asym_algo: AsymAlgo,
        eat_nonce: &'a [u8],
        leaf_cert_label: &'a [u8; KEY_LABEL_SIZE],
        issuer: &'a str,
    ) -> CaliptraApiResult<OcpEatCwt<'a>> {
        Ok(OcpEatCwt {
            eat_type,
            asym_algo,
            eat_nonce,
            leaf_cert_label,
            issuer,
        })
    }

    pub async fn generate(&self, eat_buffer: &mut [u8]) -> CaliptraApiResult<usize> {
        match self.eat_type {
            OcpEatType::EatClaims => self.generate_evidence_claims(eat_buffer).await,
            OcpEatType::EnvelopeCsr => unimplemented!("Envelope CSR not implemented"),
        }
    }

    fn initialize_concise_evidence(&self, tagged: bool) -> ConciseEvidence {
        let ev_triples_map = EvTriplesMap {
            evidence_triples: None,
            identity_triples: None,
            dependency_triples: None,
            membership_triples: None,
            coswid_triples: None,
            attest_key_triples: None,
        };
        let evidence_map = ConciseEvidenceMap {
            ev_triples: ev_triples_map,
            evidence_id: None,
            profile: None,
        };

        let evidence_map = match tagged {
            true => ConciseEvidence::Tagged(TaggedConciseEvidence {
                concise_evidence: evidence_map,
            }),
            false => ConciseEvidence::Map(evidence_map),
        };

        evidence_map
    }

    async fn generate_evidence_claims(&self, eat_buffer: &mut [u8]) -> CaliptraApiResult<usize> {
        // Measurements - tagged concise evidence
        let mut concise_evidence = self.initialize_concise_evidence(true);

        generate_concise_evidence(&mut concise_evidence).await?;
        let measurement = MeasurementFormat::new(&concise_evidence);
        let measurements_array = [measurement];

        // cti - unique identifier for the token
        let mut cti = [0u8; 64];
        let cti_len = self.eat_nonce.len().min(64);
        Rng::generate_random_number(&mut cti[..cti_len]).await?;

        // Debug status - placeholder for actual status
        let debug_status = DebugStatus::Disabled;

        // prepare EAT claims
        let eat_claims = OcpEatClaims::new(
            self.issuer,
            &cti[..cti_len],
            self.eat_nonce,
            debug_status,
            &OCP_SECURITY_OID,
            &measurements_array,
        );

        EatEncoder::validate_claims(&eat_claims).map_err(CaliptraApiError::Eat)?;

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
        let mut payload_buf = [0u8; MAX_PAYLOAD_SIZE];

        // Encode protected header
        let protected_hdr_len = {
            let mut encoder = CborEncoder::new(&mut protected_hdr_buf);
            encoder
                .encode_protected_header(&protected_header)
                .map_err(CaliptraApiError::Eat)?;
            encoder.len()
        };

        // Encode payload
        let payload_len = {
            let mut encoder = CborEncoder::new(&mut payload_buf);
            encoder
                .encode_ocp_eat_claims(&eat_claims)
                .map_err(CaliptraApiError::Eat)?;
            encoder.len()
        };

        // Generate ECC signature
        let signature = self
            .generate_ecc_signature(
                &protected_hdr_buf[..protected_hdr_len],
                &payload_buf[..payload_len],
            )
            .await?;

        // Now encode the complete COSE Sign1 structure
        EatEncoder::encode_cose_sign1_eat(
            eat_buffer,
            &protected_header,
            &unprotected_headers,
            &payload_buf[..payload_len],
            &signature[..],
        )
        .map_err(CaliptraApiError::Eat)
    }

    async fn get_leaf_cert(&self, cert_buf: &mut [u8]) -> CaliptraApiResult<usize> {
        if self.asym_algo != AsymAlgo::EccP384 {
            return Err(CaliptraApiError::UnsupportedAlgorithm);
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
            Err(CaliptraApiError::UnsupportedAlgorithm)?;
        }

        let mut sig_context_buffer = [0u8; MAX_SIG_CONTEXT_SIZE];
        let sig_context_len =
            eat_encoder::create_sign1_context(&mut sig_context_buffer, &protected_hdr, &payload)
                .map_err(CaliptraApiError::Eat)?;

        let tbs = &sig_context_buffer[..sig_context_len];

        let mut hash = [0u8; SHA384_HASH_SIZE];
        HashContext::hash_all(HashAlgoType::SHA384, &tbs, &mut hash).await?;
        let mut cert_context = CertContext::new();
        let mut sig = [0u8; ECC_P384_SIGNATURE_SIZE];

        cert_context
            .sign(Some(&self.leaf_cert_label), &hash, &mut sig)
            .await?;

        Ok(sig)
    }
}
