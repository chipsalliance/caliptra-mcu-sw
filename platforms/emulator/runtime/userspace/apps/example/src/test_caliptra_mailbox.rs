// Licensed under the Apache-2.0 license

use caliptra_api::mailbox::{MailboxReqHeader, QuotePcrsEcc384Req, QuotePcrsEcc384Resp, Request};
use core::fmt::Write;
use libsyscall_caliptra::mailbox::{Mailbox, MailboxError};
use romtime::{println, test_exit};
use zerocopy::{FromBytes, IntoBytes};

#[allow(unused)]
pub(crate) async fn test_caliptra_mailbox() {
    println!("Starting mailbox test");

    let mailbox: Mailbox = Mailbox::new();

    let mut req = QuotePcrsEcc384Req {
        hdr: MailboxReqHeader::default(),
        nonce: [0x34; 32],
    };
    let req_data = req.as_mut_bytes();
    mailbox
        .populate_checksum(QuotePcrsEcc384Req::ID.into(), req_data)
        .unwrap();

    let response_buffer = &mut [0u8; core::mem::size_of::<QuotePcrsEcc384Resp>()];

    println!("Sending QUOTE_PCRS command");

    if let Err(err) = mailbox
        .execute(QuotePcrsEcc384Req::ID.0, req_data, response_buffer)
        .await
    {
        println!("Mailbox command failed with err {:?}", err);
        test_exit(1);
    }

    println!("Mailbox command success");

    if response_buffer.iter().all(|&x| x == 0) {
        println!("Mailbox response all 0");
        test_exit(1);
    }

    match QuotePcrsEcc384Resp::ref_from_bytes(response_buffer) {
        Ok(resp) => {
            if resp.nonce != req.nonce {
                println!(
                    "Nonce mismatch: expected {:x?}, got {:x?}",
                    req.nonce, resp.nonce
                );
                test_exit(1);
            }
        }
        Err(err) => {
            println!("Failed to parse response: {:?}", err);
            romtime::test_exit(1);
        }
    }
    println!("Test passed");
}

#[allow(unused)]
pub(crate) async fn test_caliptra_mailbox_bad_command() {
    println!("Starting mailbox bad command test");

    let mailbox: Mailbox = Mailbox::new();

    let mut req: QuotePcrsEcc384Req = QuotePcrsEcc384Req {
        hdr: MailboxReqHeader::default(),
        nonce: [0x34; 32],
    };
    let req_data = req.as_mut_bytes();
    mailbox.populate_checksum(0xffff_ffff, req_data).unwrap();

    let response_buffer = &mut [0u8; core::mem::size_of::<QuotePcrsEcc384Resp>()];

    println!("Sending invalid command with correct checksum");

    match mailbox
        .execute(0xffff_ffff, req_data, response_buffer)
        .await
    {
        Err(MailboxError::MailboxError(err))
            if err == u32::from(caliptra_error::CaliptraError::RUNTIME_UNIMPLEMENTED_COMMAND) =>
        {
            println!("Test passed");
        }
        result => {
            println!("Mailbox command should have failed but got {:?}", result);
            test_exit(1);
        }
    }
}

#[allow(unused)]
pub(crate) async fn test_caliptra_mailbox_fail() {
    println!("Starting mailbox failure test");

    let mailbox: Mailbox = Mailbox::new();

    let mut req = QuotePcrsEcc384Req {
        hdr: MailboxReqHeader::default(),
        nonce: [0x34; 32],
    };
    let req_data = req.as_mut_bytes();
    let len = req_data.len();
    // send a command that is too short, but has the correct checksum
    let req_data = &mut req_data[..len - 4];
    mailbox
        .populate_checksum(QuotePcrsEcc384Req::ID.into(), req_data)
        .unwrap();

    let response_buffer = &mut [0u8; core::mem::size_of::<QuotePcrsEcc384Resp>()];

    println!("Sending bad QUOTE_PCRS command");

    match mailbox
        .execute(QuotePcrsEcc384Req::ID.0, req_data, response_buffer)
        .await
    {
        Err(MailboxError::MailboxError(err))
            if err == u32::from(caliptra_error::CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS) =>
        {
            println!("Test passed");
        }
        result => {
            println!("Mailbox command should have failed but got {:?}", result);
            test_exit(1);
        }
    }
}
