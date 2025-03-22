// Licensed under the Apache-2.0 license

use caliptra_api::mailbox::{MailboxReqHeader, QuotePcrsReq, QuotePcrsResp, Request};
use core::fmt::Write;
use libsyscall_caliptra::mailbox::Mailbox;
use libtock_platform::Syscalls;
use romtime::{println, test_exit};
use zerocopy::{FromBytes, IntoBytes};

#[allow(unused)]
pub(crate) async fn test_caliptra_mailbox<S: Syscalls>() {
    println!("Starting mailbox test");

    let mailbox = Mailbox::<S>::new();

    let mut req = QuotePcrsReq {
        hdr: MailboxReqHeader::default(),
        nonce: [0x34; 32],
    };
    let req_data = req.as_mut_bytes();
    mailbox.populate_checksum(QuotePcrsReq::ID.into(), req_data);

    let response_buffer = &mut [0u8; core::mem::size_of::<QuotePcrsResp>()];

    println!("Sending QUOTE_PCRS command");

    if let Err(err) = mailbox
        .execute(QuotePcrsReq::ID.0, req_data, response_buffer)
        .await
    {
        println!("Mailbox command failed with err {:x}", err as u32);
        test_exit(1);
    }

    println!("Mailbox command success");

    if response_buffer.iter().all(|&x| x == 0) {
        println!("Mailbox response all 0");
        test_exit(1);
    }

    match QuotePcrsResp::ref_from_bytes(response_buffer) {
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
    romtime::test_exit(0);
}
