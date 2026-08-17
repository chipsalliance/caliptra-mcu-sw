// Licensed under the Apache-2.0 license

#[cfg(all(test, not(feature = "fpga_realtime")))]
mod test {
    use crate::test::{
        mailbox_execute_with_timeout, start_runtime_hw_model, TestParams, TEST_LOCK,
    };
    use caliptra_mcu_hw_model::McuHwModel;
    use caliptra_mcu_mbox_common::messages::{
        DpeSignerContextCertReq, GetOcpLockEpochKeyReportReq, MailboxReqHeader,
        MailboxRespHeaderVarSize, McuMailboxReq, SekState,
    };
    use caliptra_mcu_romtime::McuBootMilestones;
    use minicbor::data::Type;
    use minicbor::Decoder;
    use std::mem::size_of;
    use zerocopy::FromBytes;

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

    fn verify_ekp_report(
        report: &EkpReport,
        expected_nonce: &[u8; 32],
        expected_ekp_allowed: bool,
        expected_max_sanitizations: u16,
        expected_remaining_sanitizations: u16,
        expected_active_hek_state: u16,
        expected_sek_state: u16,
        expected_hek_state_list: &[u16],
    ) {
        assert_eq!(report.protected_hdr, &[0xA0]);
        assert_eq!(report.signature.len(), 96);

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

    fn run_ekp_report_test(set_perma: bool) -> (Vec<u8>, [u8; 32]) {
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
        let dpe_req = DpeSignerContextCertReq::default();
        let _dpe_resp = hw
            .mailbox_execute_req(dpe_req)
            .expect("DPE signer context cert request failed");

        let nonce = [0xAAu8; 32];
        let sek_state = SekState::Programmed;

        let mut req = McuMailboxReq::GetOcpLockEpochKeyReport(GetOcpLockEpochKeyReportReq {
            hdr: MailboxReqHeader::default(),
            nonce,
            sek_state: sek_state as u16,
            reserved: 0,
        });
        req.populate_chksum().expect("populate_chksum");
        let cmd = req.cmd_code().0;
        let payload = req.as_bytes().expect("as_bytes").to_vec();

        let resp_bytes = mailbox_execute_with_timeout(&mut hw, cmd, &payload)
            .expect("GetOcpLockEpochKeyReport mailbox command failed")
            .unwrap_or_default();

        const HDR_LEN: usize = size_of::<MailboxRespHeaderVarSize>();
        assert!(resp_bytes.len() >= HDR_LEN);

        let hdr = MailboxRespHeaderVarSize::read_from_bytes(&resp_bytes[..HDR_LEN])
            .expect("parse response header");
        let data_len = hdr.data_len as usize;
        let data = resp_bytes[HDR_LEN..HDR_LEN + data_len].to_vec();

        (data, nonce)
    }

    #[test]
    fn test_ekp_attested_report_with_perma_bit_set() {
        let (data, nonce) = run_ekp_report_test(true);
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
        );
    }

    #[test]
    fn test_ekp_attested_report_without_perma_bit_set() {
        let (data, nonce) = run_ekp_report_test(false);
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
        );
    }
}
