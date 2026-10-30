// Licensed under the Apache-2.0 license

use crate::common::MockMailbox;
use caliptra_mcu_core_util_host_command_types::attestation::{AsymAlgo, PkiEntitySlot};
use caliptra_mcu_core_util_host_transport::{Mailbox, MailboxDriver, Transport};
use caliptra_util_host_commands::api::certificate::{
    caliptra_cmd_get_cert_chain, caliptra_cmd_get_cert_chain_info, caliptra_cmd_set_cert_chain,
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
    });
}
