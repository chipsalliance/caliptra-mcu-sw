// Licensed under the Apache-2.0 license

use coset::{
    cbor::value::Value, iana::Algorithm, CborSerializable, CoseSign1Builder, HeaderBuilder,
};

use openssl::{
    ec::{EcGroup, EcKey},
    ecdsa::EcdsaSig,
    hash::MessageDigest,
    nid::Nid,
    pkey::PKey,
    sign::Signer,
    x509::{X509NameBuilder, X509},
};

use ocptoken::cose_verify::{CoseSign1Verifier, OpenSslBackend};
use ocptoken::ta_store::{TrustAnchorError, TrustAnchorStore};
use ocptoken::token::evidence::Evidence;

/// In-memory Trust Anchor Store for tests.
/// Holds a set of trusted root certs (DER-encoded) and authenticates
/// chains by checking the chain root against them.
struct TestTrustAnchorStore {
    roots: Vec<Vec<u8>>,
}

impl TestTrustAnchorStore {
    fn new(roots: Vec<Vec<u8>>) -> Self {
        Self { roots }
    }
}

impl TrustAnchorStore for TestTrustAnchorStore {
    fn authenticate_by_kid(&self, _kid: &[u8]) -> Result<Vec<u8>, TrustAnchorError> {
        Err(TrustAnchorError::UnknownKid("not implemented".into()))
    }

    fn authenticate_chain(&self, chain: &[Vec<u8>]) -> Result<Vec<u8>, TrustAnchorError> {
        if chain.is_empty() {
            return Err(TrustAnchorError::EmptyChain);
        }
        // Check if the chain root is one of our trusted roots
        let chain_root = &chain[chain.len() - 1];
        if self.roots.iter().any(|r| r == chain_root) {
            Ok(chain[0].clone())
        } else {
            Err(TrustAnchorError::UntrustedRoot)
        }
    }
}

#[test]
fn decode_and_verify_ecc_p384_cose_sign1() {
    // 1 Generate ECC P-384 key pair
    let group = EcGroup::from_curve_name(Nid::SECP384R1).unwrap();
    let ec_key = EcKey::generate(&group).unwrap();
    let pkey = PKey::from_ec_key(ec_key).unwrap();

    use openssl::asn1::Asn1Time;
    use openssl::bn::BigNum;

    // 2 Create self-signed X.509 certificate
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "test-cert").unwrap();
    let name = name.build();

    let mut cert_builder = X509::builder().unwrap();

    cert_builder.set_version(2).unwrap();

    // serial number
    let mut serial = BigNum::new().unwrap();
    serial
        .rand(64, openssl::bn::MsbOption::MAYBE_ZERO, false)
        .unwrap();
    let serial = serial.to_asn1_integer().unwrap();
    cert_builder.set_serial_number(&serial).unwrap();

    // Subject / issuer
    cert_builder.set_subject_name(&name).unwrap();
    cert_builder.set_issuer_name(&name).unwrap();

    // validity
    let not_before = Asn1Time::days_from_now(0).unwrap();
    let not_after = Asn1Time::days_from_now(365).unwrap();
    cert_builder.set_not_before(&not_before).unwrap();
    cert_builder.set_not_after(&not_after).unwrap();

    // Public key
    cert_builder.set_pubkey(&pkey).unwrap();

    // Sign certificate
    cert_builder.sign(&pkey, MessageDigest::sha384()).unwrap();

    let cert = cert_builder.build();
    let cert_der = cert.to_der().unwrap();

    // 3 Create Trust Anchor Store with the self-signed cert as root
    let ta_store = TestTrustAnchorStore::new(vec![cert_der.clone()]);

    // Dummy payload
    let payload = b"dummy payload for COSE signature";

    // 4 Create COSE_Sign1 structure
    let cose = CoseSign1Builder::new()
        .payload(payload.to_vec())
        .protected(HeaderBuilder::new().algorithm(Algorithm::ES384).build())
        .unprotected(
            HeaderBuilder::new()
                // x5chain = label 33
                .value(33, Value::Array(vec![Value::Bytes(cert_der.clone())]))
                .build(),
        )
        .create_signature(&[], |msg| {
            let mut signer = Signer::new(MessageDigest::sha384(), &pkey).unwrap();
            signer.update(msg).unwrap();

            let der_sig = signer.sign_to_vec().unwrap();

            // DER → raw r||s (COSE format)
            let sig = EcdsaSig::from_der(&der_sig).unwrap();
            let r = sig.r().to_vec_padded(48).unwrap();
            let s = sig.s().to_vec_padded(48).unwrap();
            [r, s].concat()
        })
        .build();

    // 5 Encode to CBOR
    let encoded = cose.to_vec().unwrap();

    // 6 Decode
    let evidence =
        Evidence::decode(&encoded, &ta_store).expect("Evidence::decode should succeed");

    // 7 Verify
    let verifier = CoseSign1Verifier::new(OpenSslBackend);
    evidence
        .verify(&[], &verifier)
        .expect("COSE_Sign1 signature verification should succeed");
}

#[test]
fn reject_untrusted_cert_chain() {
    // Generate a key + self-signed cert
    let group = EcGroup::from_curve_name(Nid::SECP384R1).unwrap();
    let ec_key = EcKey::generate(&group).unwrap();
    let pkey = PKey::from_ec_key(ec_key).unwrap();

    use openssl::asn1::Asn1Time;
    use openssl::bn::BigNum;

    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "untrusted-cert").unwrap();
    let name = name.build();

    let mut cert_builder = X509::builder().unwrap();
    cert_builder.set_version(2).unwrap();
    let mut serial = BigNum::new().unwrap();
    serial
        .rand(64, openssl::bn::MsbOption::MAYBE_ZERO, false)
        .unwrap();
    cert_builder
        .set_serial_number(&serial.to_asn1_integer().unwrap())
        .unwrap();
    cert_builder.set_subject_name(&name).unwrap();
    cert_builder.set_issuer_name(&name).unwrap();
    cert_builder
        .set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    cert_builder
        .set_not_after(&Asn1Time::days_from_now(365).unwrap())
        .unwrap();
    cert_builder.set_pubkey(&pkey).unwrap();
    cert_builder.sign(&pkey, MessageDigest::sha384()).unwrap();

    let cert = cert_builder.build();
    let cert_der = cert.to_der().unwrap();

    // TA store has NO trusted roots -- empty
    let ta_store = TestTrustAnchorStore::new(vec![]);

    let cose = CoseSign1Builder::new()
        .payload(b"payload".to_vec())
        .protected(HeaderBuilder::new().algorithm(Algorithm::ES384).build())
        .unprotected(
            HeaderBuilder::new()
                .value(33, Value::Array(vec![Value::Bytes(cert_der.clone())]))
                .build(),
        )
        .create_signature(&[], |msg| {
            let mut signer = Signer::new(MessageDigest::sha384(), &pkey).unwrap();
            signer.update(msg).unwrap();
            let der_sig = signer.sign_to_vec().unwrap();
            let sig = EcdsaSig::from_der(&der_sig).unwrap();
            let r = sig.r().to_vec_padded(48).unwrap();
            let s = sig.s().to_vec_padded(48).unwrap();
            [r, s].concat()
        })
        .build();

    let encoded = cose.to_vec().unwrap();
    let evidence = Evidence::decode(&encoded, &ta_store).unwrap();

    // Verify should fail because the cert is not trusted
    let verifier = CoseSign1Verifier::new(OpenSslBackend);
    assert!(
        evidence.verify(&[], &verifier).is_err(),
        "Verification should fail with untrusted certificate chain"
    );
}

mod tag_order_tests {
    use super::*;
    use coset::cbor::value::Value;
    use ocptoken::error::OcpEatError;
    use ocptoken::token::evidence::{CBOR_TAG_CBOR, CBOR_TAG_COSE_SIGN1, CBOR_TAG_CWT};

    /// Dummy TA store for tag order tests (these tests only exercise decode, not verify)
    fn dummy_ta_store() -> TestTrustAnchorStore {
        TestTrustAnchorStore::new(vec![])
    }

    fn wrap_with_tags(mut inner: Value, tags: &[u64]) -> Vec<u8> {
        for &tag in tags.iter().rev() {
            inner = Value::Tag(tag, Box::new(inner));
        }
        inner.to_vec().unwrap()
    }

    fn dummy_cose_array() -> Value {
        Value::Array(vec![
            Value::Bytes(vec![]),
            Value::Map(vec![]),
            Value::Bytes(vec![]),
            Value::Bytes(vec![]),
        ])
    }

    #[test]
    fn reject_incorrect_cbor_tag_order() {
        let encoded = wrap_with_tags(
            dummy_cose_array(),
            &[CBOR_TAG_CWT, CBOR_TAG_CBOR, CBOR_TAG_COSE_SIGN1],
        );
        let ta_store = dummy_ta_store();

        match Evidence::decode(&encoded, &ta_store) {
            Err(OcpEatError::Verification(ocptoken::cose_verify::CoseSign1Error::InvalidTag {
                ..
            })) => {
                // Tag mismatch correctly detected
            }
            Err(OcpEatError::InvalidToken(msg)) => {
                assert!(
                    msg.contains("CBOR tags are not in required order"),
                    "unexpected error message: {msg}"
                );
            }
            Ok(_) => panic!("Unexpected success"),
            Err(e) => panic!("Unexpected error variant: {:?}", e),
        }
    }

    #[test]
    fn accept_correct_cbor_tag_order() {
        let encoded = wrap_with_tags(
            dummy_cose_array(),
            &[CBOR_TAG_CBOR, CBOR_TAG_CWT, CBOR_TAG_COSE_SIGN1],
        );
        let ta_store = dummy_ta_store();

        match Evidence::decode(&encoded, &ta_store) {
            Err(OcpEatError::Verification(ocptoken::cose_verify::CoseSign1Error::InvalidTag {
                ..
            })) => {
                panic!("Tag order was rejected unexpectedly");
            }
            Err(OcpEatError::InvalidToken(msg))
                if msg.contains("CBOR tags are not in required order") =>
            {
                panic!("Tag order was rejected unexpectedly");
            }
            Err(_) => {} // expected (other validation errors)
            Ok(_) => panic!("Unexpected success"),
        }
    }

    #[test]
    fn reject_missing_required_cbor_tag() {
        // Missing CWT tag (61)
        let encoded = wrap_with_tags(dummy_cose_array(), &[CBOR_TAG_CBOR, CBOR_TAG_COSE_SIGN1]);
        let ta_store = dummy_ta_store();

        match Evidence::decode(&encoded, &ta_store) {
            Err(OcpEatError::Verification(ocptoken::cose_verify::CoseSign1Error::InvalidTag {
                ..
            })) => {
                // Tag mismatch correctly detected (expected CWT=61, found COSE_Sign1=18)
            }
            Err(OcpEatError::InvalidToken(msg)) => {
                assert!(
                    msg.contains("CBOR tags are not in required order"),
                    "unexpected error message for missing tag: {msg}"
                );
            }
            Ok(_) => panic!("Unexpected success with missing required CBOR tag"),
            Err(e) => panic!("Unexpected error variant: {:?}", e),
        }
    }
}
