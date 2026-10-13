// Licensed under the Apache-2.0 license

use crate::common::MockMailbox;
use caliptra_mcu_core_util_host_transport::{Mailbox, MailboxDriver, Transport};
use caliptra_util_host_commands::api::device_info::{
    caliptra_cmd_field_entropy_status, caliptra_cmd_hek_status, caliptra_cmd_vendor_pk_hash_status,
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
fn status_commands_return_typed_responses() {
    with_session(|session| {
        let field_entropy =
            caliptra_cmd_field_entropy_status(session).expect("field entropy status failed");
        assert_eq!(field_entropy.common.fips_status, 1);
        assert_eq!(field_entropy.already_provisioned, 1);

        let vendor_pk_hash =
            caliptra_cmd_vendor_pk_hash_status(session).expect("vendor PK hash status failed");
        assert_eq!(vendor_pk_hash.common.fips_status, 1);
        assert_eq!(vendor_pk_hash.used_slots_bitmap, 5);
        assert_eq!(vendor_pk_hash.key_types[0], 1);
        assert_eq!(vendor_pk_hash.key_types[2], 3);
        assert_eq!(&vendor_pk_hash.key_types[3..], &[0; 13]);

        let hek = caliptra_cmd_hek_status(session).expect("HEK status failed");
        assert_eq!(hek.common.fips_status, 1);
        assert_eq!(hek.used_slots_bitmap, 5);
        assert_eq!(hek.total_slots, 8);
    });
}

#[test]
fn status_commands_require_connected_session() {
    let mut mock_mailbox = MockMailbox::new_default();
    let mut transport = Mailbox::new(&mut mock_mailbox as &mut dyn MailboxDriver);
    let mut session = CaliptraSession::new(1, &mut transport as &mut dyn Transport)
        .expect("failed to create session");

    assert!(caliptra_cmd_field_entropy_status(&mut session).is_err());
    assert!(caliptra_cmd_vendor_pk_hash_status(&mut session).is_err());
    assert!(caliptra_cmd_hek_status(&mut session).is_err());
}
