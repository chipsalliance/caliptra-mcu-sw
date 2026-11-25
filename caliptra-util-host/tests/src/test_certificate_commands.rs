// Licensed under the Apache-2.0 license

use crate::common::MockMailbox;
use caliptra_mcu_core_util_host_command_types::attestation::{AsymAlgo, PkiEntitySlot};
use caliptra_mcu_core_util_host_command_types::certificate::{
    AuthSetCertChainRequest, ProvisionIdevCertMode, ECDSA384_SIGNATURE_SIZE,
    MAX_DPE_SIGNER_SIGN_DATA_SIZE,
};
use caliptra_mcu_core_util_host_transport::{Mailbox, MailboxDriver, Transport};
use caliptra_util_host_commands::api::certificate::{
    caliptra_cmd_auth_set_cert_chain, caliptra_cmd_dpe_signer_context_cert,
    caliptra_cmd_dpe_signer_context_sign, caliptra_cmd_get_cert_chain,
    caliptra_cmd_get_cert_chain_info, caliptra_cmd_provision_idevid_cert,
    caliptra_cmd_set_cert_chain,
};
use caliptra_util_host_session::CaliptraSession;

fn with_session(test: impl FnOnce(&mut CaliptraSession<'_>)) {
    let mut mock_mailbox = MockMailbox::new_default();
    let mut transport = Mailbox::new(&mut mock_mailbox as &mut dyn MailboxDriver);
    let mut session = CaliptraSession::new(1, &mut transport as &mut dyn Transport)
        .expect("failed to create session");
    session.connect().expect("failed to connect session");
    test(&mut session);
}

#[test]
fn certificate_chain_commands_round_trip_through_session() {
    with_session(|session| {
        let vendor_info =
            caliptra_cmd_get_cert_chain_info(session, PkiEntitySlot::Vendor, AsymAlgo::EccP384)
                .expect("GetCertChainInfo(Vendor) failed");
        assert_eq!(vendor_info.common.fips_status, 0);
        assert_eq!(vendor_info.device_key_id, 0);
        assert_eq!(vendor_info.chain_len, 64);
        assert_eq!(vendor_info.chain_digest, [0x5Au8; 48]);

        let owner_info =
            caliptra_cmd_get_cert_chain_info(session, PkiEntitySlot::Owner, AsymAlgo::EccP384)
                .expect("GetCertChainInfo(Owner) failed");
        assert_eq!(owner_info.device_key_id, 1);

        let chunk =
            caliptra_cmd_get_cert_chain(session, PkiEntitySlot::Vendor, AsymAlgo::EccP384, 0, 32)
                .expect("GetCertChain failed");
        assert_eq!(chunk.data_len, 32);
        assert_eq!(chunk.cert_bytes(), &[0x30u8; 32]);

        let set_resp = caliptra_cmd_set_cert_chain(
            session,
            PkiEntitySlot::Owner,
            AsymAlgo::EccP384,
            1,
            0,
            16,
            &[0x30u8; 16],
        )
        .expect("SetCertChain failed");
        assert_eq!(set_resp.common.fips_status, 0);

        let prov_resp = caliptra_cmd_provision_idevid_cert(
            session,
            AsymAlgo::EccP384,
            ProvisionIdevCertMode::PopulateOnly,
            &[0x30u8; 24],
        )
        .expect("ProvisionIdevCert failed");
        assert_eq!(prov_resp.common.fips_status, 0);

        let auth_req = AuthSetCertChainRequest {
            pki_entity_slot: PkiEntitySlot::Owner as u32,
            algorithm: AsymAlgo::EccP384 as u32,
            total_size: 16,
            expected_sha384: [0x5Au8; 48],
            metadata: Default::default(),
            nonce: [0x11; 48],
            ecc_pub_x: [0x22; 48],
            ecc_pub_y: [0x33; 48],
            mldsa_pub: [0x44; 2592],
            sig: Default::default(),
        };
        let auth_resp =
            caliptra_cmd_auth_set_cert_chain(session, &auth_req).expect("AuthSetCertChain failed");
        assert_eq!(auth_resp.common.fips_status, 0);
    });
}

#[test]
fn dpe_signer_context_commands_round_trip_through_session() {
    with_session(|session| {
        let cert_resp = caliptra_cmd_dpe_signer_context_cert(session, 0x10, AsymAlgo::EccP384)
            .expect("DpeSignerContextCert failed");
        assert_eq!(cert_resp.common.fips_status, 0);
        assert_eq!(
            cert_resp.cert_bytes(),
            &[0x30, 0x82, 0x00, 0x04, 0x10, 0x01, 0xAA, 0x55]
        );

        let digest = [0x42u8; 48];
        let sign_resp =
            caliptra_cmd_dpe_signer_context_sign(session, 0, AsymAlgo::EccP384, &digest)
                .expect("DpeSignerContextSign failed");
        assert_eq!(sign_resp.common.fips_status, 0);
        let sig = sign_resp.signature_bytes();
        assert_eq!(sig.len(), ECDSA384_SIGNATURE_SIZE);
        assert_eq!(&sig[..48], &digest);
        assert!(sig[48..].iter().all(|&b| b == (0x42 ^ 0xA5)));

        // Empty and oversized payloads should fail client-side validation.
        assert!(caliptra_cmd_dpe_signer_context_sign(session, 0, AsymAlgo::EccP384, &[]).is_err());
        let oversized = vec![0u8; MAX_DPE_SIGNER_SIGN_DATA_SIZE + 1];
        assert!(
            caliptra_cmd_dpe_signer_context_sign(session, 0, AsymAlgo::EccP384, &oversized)
                .is_err()
        );
    });
}
