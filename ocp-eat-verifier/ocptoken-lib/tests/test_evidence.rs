// Licensed under the Apache-2.0 license

use coset::{
    cbor::value::Value, iana::Algorithm, CborSerializable, CoseSign1Builder, HeaderBuilder,
};

use openssl::{
    asn1::Asn1Time,
    bn::BigNum,
    ec::{EcGroup, EcKey},
    ecdsa::EcdsaSig,
    hash::MessageDigest,
    nid::Nid,
    pkey::PKey,
    sign::Signer,
    x509::{X509NameBuilder, X509},
};

use ocptoken::cose_verify::{CoseSign1Verifier, OpenSslBackend};
use ocptoken::error::OcpEatError;
use ocptoken::ta_store::{TrustAnchorError, TrustAnchorStore};
use ocptoken::token::claims::{
    CLAIM_KEY_DEBUG_STATUS, CLAIM_KEY_EAT_PROFILE, CLAIM_KEY_MEASUREMENTS, CLAIM_KEY_NONCE,
    OCP_EAT_PROFILE_OID_STR,
};
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

// ── Helpers ────────────────────────────────────────────────────────

/// Build a valid OCP EAT CWT ClaimsSet payload (CBOR bytes).
///
/// Contains all four mandatory claims with sensible defaults.
/// Use `build_claims_set_custom` to override individual claims.
fn build_valid_cwt_payload() -> Vec<u8> {
    build_cwt_payload_with(None, None, None, None)
}

/// Build a CWT payload (CBOR map) with optional overrides for each mandatory claim.
/// Pass `Some(value)` to override, `None` for the default.
fn build_cwt_payload_with(
    nonce: Option<Value>,
    debug_status: Option<Value>,
    eat_profile: Option<Value>,
    measurements: Option<Value>,
) -> Vec<u8> {
    let nonce_val = nonce.unwrap_or_else(|| Value::Bytes(vec![0xAA; 32]));
    let debug_val = debug_status.unwrap_or_else(|| Value::Integer(1.into())); // disabled
    let profile_val =
        eat_profile.unwrap_or_else(|| Value::Bytes(OCP_EAT_PROFILE_OID_STR.as_bytes().to_vec()));
    let meas_val = measurements.unwrap_or_else(|| Value::Bytes(vec![0xBB; 16]));

    let map = Value::Map(vec![
        (Value::Integer(CLAIM_KEY_NONCE.into()), nonce_val),
        (Value::Integer(CLAIM_KEY_DEBUG_STATUS.into()), debug_val),
        (Value::Integer(CLAIM_KEY_EAT_PROFILE.into()), profile_val),
        (Value::Integer(CLAIM_KEY_MEASUREMENTS.into()), meas_val),
    ]);

    let mut buf = Vec::new();
    ciborium::into_writer(&map, &mut buf).unwrap();
    buf
}

/// Build a CWT payload that omits a specific claim key.
fn build_cwt_payload_without(omit_key: i64) -> Vec<u8> {
    let all_claims: Vec<(i64, Value)> = vec![
        (CLAIM_KEY_NONCE, Value::Bytes(vec![0xAA; 32])),
        (CLAIM_KEY_DEBUG_STATUS, Value::Integer(1.into())),
        (
            CLAIM_KEY_EAT_PROFILE,
            Value::Bytes(OCP_EAT_PROFILE_OID_STR.as_bytes().to_vec()),
        ),
        (CLAIM_KEY_MEASUREMENTS, Value::Bytes(vec![0xBB; 16])),
    ];

    let map = Value::Map(
        all_claims
            .into_iter()
            .filter(|(k, _)| *k != omit_key)
            .map(|(k, v)| (Value::Integer(k.into()), v))
            .collect(),
    );

    let mut buf = Vec::new();
    ciborium::into_writer(&map, &mut buf).unwrap();
    buf
}

/// Generate an ECC P-384 key pair and self-signed X.509 certificate.
/// Returns (PKey, DER-encoded cert).
fn generate_key_and_cert(cn: &str) -> (PKey<openssl::pkey::Private>, Vec<u8>) {
    let group = EcGroup::from_curve_name(Nid::SECP384R1).unwrap();
    let ec_key = EcKey::generate(&group).unwrap();
    let pkey = PKey::from_ec_key(ec_key).unwrap();

    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", cn).unwrap();
    let name = name.build();

    let mut builder = X509::builder().unwrap();
    builder.set_version(2).unwrap();
    let mut serial = BigNum::new().unwrap();
    serial
        .rand(64, openssl::bn::MsbOption::MAYBE_ZERO, false)
        .unwrap();
    builder
        .set_serial_number(&serial.to_asn1_integer().unwrap())
        .unwrap();
    builder.set_subject_name(&name).unwrap();
    builder.set_issuer_name(&name).unwrap();
    builder
        .set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    builder
        .set_not_after(&Asn1Time::days_from_now(365).unwrap())
        .unwrap();
    builder.set_pubkey(&pkey).unwrap();
    builder.sign(&pkey, MessageDigest::sha384()).unwrap();

    let cert_der = builder.build().to_der().unwrap();
    (pkey, cert_der)
}

/// Build a COSE_Sign1 (CBOR bytes) with the given payload, signed with `pkey`,
/// and the cert in the x5chain unprotected header.
fn build_signed_cose(
    payload: &[u8],
    pkey: &PKey<openssl::pkey::Private>,
    cert_der: &[u8],
) -> Vec<u8> {
    let cose = CoseSign1Builder::new()
        .payload(payload.to_vec())
        .protected(HeaderBuilder::new().algorithm(Algorithm::ES384).build())
        .unprotected(
            HeaderBuilder::new()
                .value(33, Value::Array(vec![Value::Bytes(cert_der.to_vec())]))
                .build(),
        )
        .create_signature(&[], |msg| {
            let mut signer = Signer::new(MessageDigest::sha384(), pkey).unwrap();
            signer.update(msg).unwrap();
            let der_sig = signer.sign_to_vec().unwrap();
            let sig = EcdsaSig::from_der(&der_sig).unwrap();
            let r = sig.r().to_vec_padded(48).unwrap();
            let s = sig.s().to_vec_padded(48).unwrap();
            [r, s].concat()
        })
        .build();
    cose.to_vec().unwrap()
}

mod cose_verify_tests {
    use super::*;

    #[test]
    fn decode_and_verify_ecc_p384_cose_sign1() {
        let (pkey, cert_der) = generate_key_and_cert("test-cert");
        let ta_store = TestTrustAnchorStore::new(vec![cert_der.clone()]);
        let payload = build_valid_cwt_payload();
        let encoded = build_signed_cose(&payload, &pkey, &cert_der);

        let evidence =
            Evidence::decode(&encoded, &ta_store).expect("Evidence::decode should succeed");

        let verifier = CoseSign1Verifier::new(OpenSslBackend);
        evidence
            .verify(&[], &verifier)
            .expect("COSE_Sign1 signature verification should succeed");
    }

    #[test]
    fn reject_untrusted_cert_chain() {
        let (pkey, cert_der) = generate_key_and_cert("untrusted-cert");

        // TA store has NO trusted roots -- empty
        let ta_store = TestTrustAnchorStore::new(vec![]);
        let payload = build_valid_cwt_payload();
        let encoded = build_signed_cose(&payload, &pkey, &cert_der);
        let evidence = Evidence::decode(&encoded, &ta_store).unwrap();

        // Verify should fail because the cert is not trusted
        let verifier = CoseSign1Verifier::new(OpenSslBackend);
        assert!(
            evidence.verify(&[], &verifier).is_err(),
            "Verification should fail with untrusted certificate chain"
        );
    }
}

mod eat_tag_order_tests {
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

// ── Claims validation corner-case tests ────────────────────────────

mod eat_claims_tests {
    use super::*;
    use ocptoken::token::claims::DebugStatus;

    fn ta_store_for(cert_der: &[u8]) -> TestTrustAnchorStore {
        TestTrustAnchorStore::new(vec![cert_der.to_vec()])
    }

    // ── Happy path ──

    #[test]
    fn decode_valid_claims_mandatory_only() {
        let (pkey, cert_der) = generate_key_and_cert("valid-claims");
        let ta = ta_store_for(&cert_der);
        let payload = build_valid_cwt_payload();
        let encoded = build_signed_cose(&payload, &pkey, &cert_der);

        let ev = Evidence::decode(&encoded, &ta).expect("decode should succeed");
        let c = ev.claims();
        assert_eq!(c.nonce, vec![0xAA; 32]);
        assert_eq!(c.debug_status, DebugStatus::Disabled);
        assert_eq!(c.eat_profile, "1.3.6.1.4.1.42623.1.3");
        assert_eq!(c.measurements.len(), 16);
    }

    #[test]
    fn measurements_as_cbor_array_accepted() {
        let meas_array = Value::Array(vec![Value::Integer(1.into()), Value::Bytes(vec![0xCC; 8])]);
        let (pkey, cert_der) = generate_key_and_cert("meas-array");
        let ta = ta_store_for(&cert_der);
        let payload = build_cwt_payload_with(None, None, None, Some(meas_array));
        let encoded = build_signed_cose(&payload, &pkey, &cert_der);

        let ev = Evidence::decode(&encoded, &ta).expect("array measurements should decode");
        assert!(!ev.claims().measurements.is_empty());
    }

    // ── Missing mandatory claims ──

    #[test]
    fn reject_missing_nonce() {
        let (pkey, cert_der) = generate_key_and_cert("no-nonce");
        let ta = ta_store_for(&cert_der);
        let payload = build_cwt_payload_without(CLAIM_KEY_NONCE);
        let encoded = build_signed_cose(&payload, &pkey, &cert_der);

        match Evidence::decode(&encoded, &ta) {
            Err(OcpEatError::InvalidToken(msg)) => {
                assert!(msg.contains("nonce"), "expected nonce error, got: {msg}");
            }
            Err(e) => panic!("Expected missing-nonce error, got: {e}"),
            Ok(_) => panic!("Expected missing-nonce error, got Ok"),
        }
    }

    #[test]
    fn reject_missing_debug_status() {
        let (pkey, cert_der) = generate_key_and_cert("no-dbg");
        let ta = ta_store_for(&cert_der);
        let payload = build_cwt_payload_without(CLAIM_KEY_DEBUG_STATUS);
        let encoded = build_signed_cose(&payload, &pkey, &cert_der);

        match Evidence::decode(&encoded, &ta) {
            Err(OcpEatError::InvalidToken(msg)) => {
                assert!(
                    msg.contains("dbgstat"),
                    "expected dbgstat error, got: {msg}"
                );
            }
            Err(e) => panic!("Expected missing-dbgstat error, got: {e}"),
            Ok(_) => panic!("Expected missing-dbgstat error, got Ok"),
        }
    }

    #[test]
    fn reject_missing_eat_profile() {
        let (pkey, cert_der) = generate_key_and_cert("no-profile");
        let ta = ta_store_for(&cert_der);
        let payload = build_cwt_payload_without(CLAIM_KEY_EAT_PROFILE);
        let encoded = build_signed_cose(&payload, &pkey, &cert_der);

        match Evidence::decode(&encoded, &ta) {
            Err(OcpEatError::InvalidToken(msg)) => {
                assert!(
                    msg.contains("eat_profile"),
                    "expected eat_profile error, got: {msg}"
                );
            }
            Err(e) => panic!("Expected missing-eat_profile error, got: {e}"),
            Ok(_) => panic!("Expected missing-eat_profile error, got Ok"),
        }
    }

    #[test]
    fn reject_missing_measurements() {
        let (pkey, cert_der) = generate_key_and_cert("no-meas");
        let ta = ta_store_for(&cert_der);
        let payload = build_cwt_payload_without(CLAIM_KEY_MEASUREMENTS);
        let encoded = build_signed_cose(&payload, &pkey, &cert_der);

        match Evidence::decode(&encoded, &ta) {
            Err(OcpEatError::InvalidToken(msg)) => {
                assert!(
                    msg.contains("measurements"),
                    "expected measurements error, got: {msg}"
                );
            }
            Err(e) => panic!("Expected missing-measurements error, got: {e}"),
            Ok(_) => panic!("Expected missing-measurements error, got Ok"),
        }
    }

    // ── Wrong eat_profile OID ──

    #[test]
    fn reject_wrong_eat_profile_oid() {
        let wrong_oid = Value::Bytes(b"1.2.3.4.5".to_vec());
        let (pkey, cert_der) = generate_key_and_cert("wrong-oid");
        let ta = ta_store_for(&cert_der);
        let payload = build_cwt_payload_with(None, None, Some(wrong_oid), None);
        let encoded = build_signed_cose(&payload, &pkey, &cert_der);

        match Evidence::decode(&encoded, &ta) {
            Err(OcpEatError::InvalidToken(msg)) => {
                assert!(
                    msg.contains("does not match"),
                    "expected OID mismatch error, got: {msg}"
                );
            }
            Err(e) => panic!("Expected wrong-OID error, got: {e}"),
            Ok(_) => panic!("Expected wrong-OID error, got Ok"),
        }
    }

    // ── Invalid debug_status value ──

    #[test]
    fn reject_invalid_debug_status() {
        let bad_dbg = Value::Integer(99.into());
        let (pkey, cert_der) = generate_key_and_cert("bad-dbg");
        let ta = ta_store_for(&cert_der);
        let payload = build_cwt_payload_with(None, Some(bad_dbg), None, None);
        let encoded = build_signed_cose(&payload, &pkey, &cert_der);

        match Evidence::decode(&encoded, &ta) {
            Err(OcpEatError::InvalidToken(msg)) => {
                assert!(
                    msg.contains("debug-status"),
                    "expected debug-status error, got: {msg}"
                );
            }
            Err(e) => panic!("Expected bad debug-status error, got: {e}"),
            Ok(_) => panic!("Expected bad debug-status error, got Ok"),
        }
    }

    // ── All five debug-status values accepted ──

    #[test]
    fn all_debug_status_values_accepted() {
        for (val, expected) in [
            (0, DebugStatus::Enabled),
            (1, DebugStatus::Disabled),
            (2, DebugStatus::DisabledSinceBoot),
            (3, DebugStatus::DisabledPermanently),
            (4, DebugStatus::DisabledFullyAndPermanently),
        ] {
            let (pkey, cert_der) = generate_key_and_cert("dbg-val");
            let ta = ta_store_for(&cert_der);
            let payload =
                build_cwt_payload_with(None, Some(Value::Integer(val.into())), None, None);
            let encoded = build_signed_cose(&payload, &pkey, &cert_der);

            let ev = Evidence::decode(&encoded, &ta)
                .unwrap_or_else(|e| panic!("debug_status={val} should succeed: {e}"));
            assert_eq!(ev.claims().debug_status, expected, "debug_status={val}");
        }
    }

    // ── Nonce wrong type ──

    #[test]
    fn reject_nonce_wrong_type() {
        let bad_nonce = Value::Text("not bytes".into());
        let (pkey, cert_der) = generate_key_and_cert("bad-nonce");
        let ta = ta_store_for(&cert_der);
        let payload = build_cwt_payload_with(Some(bad_nonce), None, None, None);
        let encoded = build_signed_cose(&payload, &pkey, &cert_der);

        assert!(
            Evidence::decode(&encoded, &ta).is_err(),
            "nonce with wrong type should fail"
        );
    }

    // ── Measurements wrong type ──

    #[test]
    fn reject_measurements_wrong_type() {
        let bad_meas = Value::Text("not-measurements".into());
        let (pkey, cert_der) = generate_key_and_cert("bad-meas");
        let ta = ta_store_for(&cert_der);
        let payload = build_cwt_payload_with(None, None, None, Some(bad_meas));
        let encoded = build_signed_cose(&payload, &pkey, &cert_der);

        assert!(
            Evidence::decode(&encoded, &ta).is_err(),
            "measurements with wrong type should fail"
        );
    }
}
