// Licensed under the Apache-2.0 license

#[cfg(all(test, not(feature = "fpga_realtime")))]
mod test {
    use crate::test::{start_runtime_hw_model, TestParams, TEST_LOCK};
    use caliptra_mcu_hw_model::McuHwModel;
    use caliptra_mcu_mbox_common::messages::{
        DpeSignerContextCertReq, EndorsementAlgorithm, GetOcpLockEpochKeyReportReq,
        MailboxReqHeader, SekState,
    };
    use caliptra_mcu_romtime::McuBootMilestones;
    use fips204::traits::{SerDes, Verifier as MldsaVerifier};
    use minicbor::data::Type;
    use minicbor::Decoder;
    use sha2::{Digest, Sha384};
    use x509_parser::nom::Parser;
    use x509_parser::prelude::X509CertificateParser;

    const MAP_LABEL_CLAIM: u64 = 0;
    const VERSION_CLAIM: u64 = 1;
    const MAP_LABEL_VAL: &str = "TCG EKP Feature Set Evidence";
    const VERSION_VAL: &str = "1.00";

    fn setup_ekp_test_otp(set_perma: bool) -> Vec<u8> {
        let mut otp = vec![0u8; 4096];
        // Slot 0: Sanitized
        crate::test_hek::test::setup_otp_hek(&mut otp, 0, true, false);
        // Slot 1: Programmed
        crate::test_hek::test::setup_otp_hek(&mut otp, 1, false, false);
        // Slot 2: Unused (all-0s by default)
        // Slot 3: Sanitized
        crate::test_hek::test::setup_otp_hek(&mut otp, 3, true, false);
        // Slot 4: Programmed
        crate::test_hek::test::setup_otp_hek(&mut otp, 4, false, false);
        // Slots 5, 6: Unused (all-0s)
        // Slot 7: Programmed (will be active)
        crate::test_hek::test::setup_otp_hek(&mut otp, 7, false, false);

        if set_perma {
            crate::test_hek::test::set_hek_perma(&mut otp);
        }
        otp
    }

    #[derive(Debug, PartialEq, Eq)]
    enum ClaimValue {
        Text(String),
        Bytes(Vec<u8>),
        Bool(bool),
        Integer(u64),
        Array(Vec<u64>),
    }

    #[derive(Debug, PartialEq, Eq)]
    struct EkpReport {
        protected_hdr: Vec<u8>,
        payload: Vec<u8>,
        tbs_digest: [u8; 48],
        signature: Vec<u8>,
        map_label: String,
        version: String,
        nonce: Vec<u8>,
        ekp_allowed: bool,
        max_hek_sanitizations: u16,
        remaining_hek_sanitizations: u16,
        active_hek_state: u16,
        sek_state: u16,
        hek_state_list: Vec<u16>,
    }

    fn parse_ekp_report(data: &[u8]) -> EkpReport {
        let mut outer_decoder = Decoder::new(data);

        // Outer CBOR Tag 18 (COSE_Sign1)
        let tag = outer_decoder.tag().expect("parse COSE_Sign1 tag");
        assert_eq!(tag.as_u64(), 18, "Expected CBOR Tag 18");

        // Array of 4 elements: [protected, unprotected, payload, signature]
        let array_len = outer_decoder
            .array()
            .expect("parse array")
            .expect("expected fixed size array");
        assert_eq!(array_len, 4);

        let protected_hdr = outer_decoder
            .bytes()
            .expect("parse protected header")
            .to_vec();

        // Unprotected map (empty)
        let map_len = outer_decoder
            .map()
            .expect("parse unprotected map")
            .expect("expected fixed size map");
        assert_eq!(map_len, 0);

        // Payload byte string
        let payload = outer_decoder.bytes().expect("parse payload bytes");

        // Signature byte string
        let signature = outer_decoder.bytes().expect("parse signature").to_vec();

        // Reconstruct COSE_Sign1 Sig_structure: ["Signature1", protected_hdr, external_aad, payload]
        let mut sig_struct_buf = Vec::new();
        let mut encoder = minicbor::Encoder::new(&mut sig_struct_buf);
        encoder.array(4).unwrap();
        encoder.str("Signature1").unwrap();
        encoder.bytes(&protected_hdr).unwrap();
        encoder.bytes(&[]).unwrap();
        encoder.bytes(payload).unwrap();
        let tbs_digest: [u8; 48] = Sha384::digest(&sig_struct_buf).into();

        // Decode EKP evidence map from payload
        let mut payload_decoder = Decoder::new(payload);
        let evidence_map_len = payload_decoder
            .map()
            .expect("parse EKP Evidence map")
            .expect("expected fixed size map");
        assert_eq!(evidence_map_len, 9);

        let mut claims: Vec<(u64, ClaimValue)> = Vec::new();
        for _ in 0..evidence_map_len {
            let key = payload_decoder.u64().expect("parse claim key");
            let value_type = payload_decoder.datatype().expect("parse data type");
            let val = match value_type {
                Type::String => ClaimValue::Text(payload_decoder.str().unwrap().to_string()),
                Type::Bytes => ClaimValue::Bytes(payload_decoder.bytes().unwrap().to_vec()),
                Type::Bool => ClaimValue::Bool(payload_decoder.bool().unwrap()),
                Type::U8
                | Type::U16
                | Type::U32
                | Type::U64
                | Type::I8
                | Type::I16
                | Type::I32
                | Type::I64
                | Type::Int => ClaimValue::Integer(payload_decoder.u64().unwrap()),
                Type::Array => {
                    let arr_len = payload_decoder.array().unwrap().unwrap();
                    let mut arr = Vec::new();
                    for _ in 0..arr_len {
                        arr.push(payload_decoder.u64().unwrap());
                    }
                    ClaimValue::Array(arr)
                }
                _ => panic!("Unexpected type {:?}", value_type),
            };
            claims.push((key, val));
        }

        let get_claim = |key_num: u64| -> &ClaimValue {
            claims
                .iter()
                .find(|(k, _)| *k == key_num)
                .map(|(_, v)| v)
                .expect("claim missing")
        };

        let map_label = match get_claim(MAP_LABEL_CLAIM) {
            ClaimValue::Text(s) => s.clone(),
            _ => panic!("expected text"),
        };
        let version = match get_claim(VERSION_CLAIM) {
            ClaimValue::Text(s) => s.clone(),
            _ => panic!("expected text"),
        };
        let nonce = match get_claim(2) {
            ClaimValue::Bytes(b) => b.clone(),
            _ => panic!("expected bytes"),
        };
        let ekp_allowed = match get_claim(3) {
            ClaimValue::Bool(b) => *b,
            _ => panic!("expected bool"),
        };
        let max_hek_sanitizations = match get_claim(4) {
            ClaimValue::Integer(i) => *i as u16,
            _ => panic!("expected integer"),
        };
        let remaining_hek_sanitizations = match get_claim(5) {
            ClaimValue::Integer(i) => *i as u16,
            _ => panic!("expected integer"),
        };
        let active_hek_state = match get_claim(6) {
            ClaimValue::Integer(i) => *i as u16,
            _ => panic!("expected integer"),
        };
        let sek_state = match get_claim(7) {
            ClaimValue::Integer(i) => *i as u16,
            _ => panic!("expected integer"),
        };
        let hek_state_list = match get_claim(8) {
            ClaimValue::Array(arr) => arr.iter().map(|&v| v as u16).collect(),
            _ => panic!("expected array"),
        };

        EkpReport {
            protected_hdr,
            payload: payload.to_vec(),
            tbs_digest,
            signature,
            map_label,
            version,
            nonce,
            ekp_allowed,
            max_hek_sanitizations,
            remaining_hek_sanitizations,
            active_hek_state,
            sek_state,
            hek_state_list,
        }
    }

    fn verify_dpe_signature(report: &EkpReport, algo: EndorsementAlgorithm, dpe_cert_der: &[u8]) {
        match algo {
            EndorsementAlgorithm::ECDSA_384 => {
                assert_eq!(report.signature.len(), 96);
                let dpe_cert = openssl::x509::X509::from_der(dpe_cert_der)
                    .expect("Failed to parse DPE signer context certificate");
                let dpe_ec_key = dpe_cert
                    .public_key()
                    .expect("DPE cert public key")
                    .ec_key()
                    .expect("DPE cert EC key");
                let r = openssl::bn::BigNum::from_slice(&report.signature[..48]).unwrap();
                let s = openssl::bn::BigNum::from_slice(&report.signature[48..96]).unwrap();
                let sig = openssl::ecdsa::EcdsaSig::from_private_components(r, s).unwrap();
                assert!(
                    sig.verify(&report.tbs_digest, &dpe_ec_key).unwrap(),
                    "EKP report signature must be validly signed by DPE signer context ECDSA public key"
                );
            }
            EndorsementAlgorithm::MLDSA_87 => {
                assert_eq!(report.signature.len(), 4627);
                let mut dpe_parser = X509CertificateParser::new().with_deep_parse_extensions(true);
                let (_, parsed_dpe_cert) = dpe_parser
                    .parse(dpe_cert_der)
                    .expect("Failed to parse ML-DSA DPE signer context certificate");
                let dpe_mldsa_pubkey_bytes = &parsed_dpe_cert
                    .tbs_certificate
                    .public_key()
                    .subject_public_key
                    .data;
                assert_eq!(
                    dpe_mldsa_pubkey_bytes.len(),
                    2592,
                    "ML-DSA-87 public key must be 2592 bytes"
                );
                let dpe_mldsa_pubkey_arr: [u8; 2592] = dpe_mldsa_pubkey_bytes
                    .as_ref()
                    .try_into()
                    .expect("Invalid ML-DSA-87 public key size");
                let mldsa_verifying_key =
                    fips204::ml_dsa_87::PublicKey::try_from_bytes(dpe_mldsa_pubkey_arr)
                        .expect("Failed to construct ML-DSA-87 PublicKey");
                let mldsa_sig: [u8; 4627] = report
                    .signature
                    .as_slice()
                    .try_into()
                    .expect("ML-DSA-87 signature length mismatch");
                assert!(
                    mldsa_verifying_key.verify(&report.tbs_digest, &mldsa_sig, &[]),
                    "EKP report signature must be validly signed by DPE signer context ML-DSA public key"
                );
            }
            _ => panic!("Unsupported endorsement algorithm: {:?}", algo),
        }
    }

    fn verify_ekp_report(
        report: &EkpReport,
        expected_nonce: &[u8; 32],
        expected_ekp_allowed: bool,
        expected_max_sanitizations: u16,
        expected_remaining_sanitizations: u16,
        expected_active_hek_state: u16,
        expected_sek_state: u16,
        expected_hek_state_list: &[u16],
        algo: EndorsementAlgorithm,
        dpe_cert_der: &[u8],
    ) {
        assert_eq!(report.protected_hdr, &[0xA0]);

        verify_dpe_signature(report, algo, dpe_cert_der);

        assert_eq!(report.map_label, MAP_LABEL_VAL);
        assert_eq!(report.version, VERSION_VAL);
        assert_eq!(report.nonce, expected_nonce);
        assert_eq!(report.ekp_allowed, expected_ekp_allowed);
        assert_eq!(report.max_hek_sanitizations, expected_max_sanitizations);
        assert_eq!(
            report.remaining_hek_sanitizations,
            expected_remaining_sanitizations
        );
        assert_eq!(report.active_hek_state, expected_active_hek_state);
        assert_eq!(report.sek_state, expected_sek_state);
        assert_eq!(report.hek_state_list, expected_hek_state_list);
    }

    fn run_ekp_report_test(
        set_perma: bool,
        algo: EndorsementAlgorithm,
    ) -> (Vec<u8>, [u8; 32], Vec<u8>) {
        let _lock = TEST_LOCK.lock().unwrap();
        let otp = setup_ekp_test_otp(set_perma);

        let mut hw = start_runtime_hw_model(TestParams {
            otp_memory: Some(otp),
            rom_only: false,
            ocp_lock_en: true,
            feature: Some("test-ekp"),
            rom_feature: Some("ocp-lock"),
            ..Default::default()
        });

        // Wait for the firmware mailbox to be ready.
        hw.step_until(|hw| {
            hw.mci_boot_milestones()
                .contains(McuBootMilestones::FIRMWARE_MAILBOX_READY)
        });

        // Initialize DPE signer by retrieving the signer context certificate
        let dpe_req = DpeSignerContextCertReq {
            algorithm: algo,
            ..Default::default()
        };
        let dpe_resp = hw
            .mailbox_execute_req(dpe_req)
            .expect("DPE signer context cert request failed");
        let dpe_cert_len = dpe_resp.hdr.data_len as usize;
        let dpe_cert_der = dpe_resp.cert_data[..dpe_cert_len].to_vec();

        let nonce = [0xAAu8; 32];
        let sek_state = SekState::Programmed;

        let req = GetOcpLockEpochKeyReportReq {
            hdr: MailboxReqHeader::default(),
            nonce,
            sek_state: sek_state as u16,
            reserved: 0,
            algorithm: algo,
        };
        let resp = hw
            .mailbox_execute_req(req)
            .expect("GetOcpLockEpochKeyReport mailbox command failed");
        let data_len = resp.hdr.data_len as usize;
        let data = resp.data[..data_len].to_vec();

        (data, nonce, dpe_cert_der)
    }

    #[test]
    fn test_ekp_attested_report_with_perma_bit_set() {
        for algo in [
            EndorsementAlgorithm::ECDSA_384,
            EndorsementAlgorithm::MLDSA_87,
        ] {
            let (data, nonce, dpe_cert_der) = run_ekp_report_test(true, algo);
            let report = parse_ekp_report(&data);
            verify_ekp_report(
                &report,
                &nonce,
                false,
                8,
                0,
                4,
                1,
                &[4, 4, 4, 4, 4, 4, 4, 4],
                algo,
                &dpe_cert_der,
            );
        }
    }

    #[test]
    fn test_ekp_attested_report_without_perma_bit_set() {
        for algo in [
            EndorsementAlgorithm::ECDSA_384,
            EndorsementAlgorithm::MLDSA_87,
        ] {
            let (data, nonce, dpe_cert_der) = run_ekp_report_test(false, algo);
            let report = parse_ekp_report(&data);
            verify_ekp_report(
                &report,
                &nonce,
                false,
                8,
                6,
                1,
                1,
                &[5, 1, 0, 5, 1, 0, 0, 1],
                algo,
                &dpe_cert_der,
            );
        }
    }
}
