// Licensed under the Apache-2.0 license

use caliptra_api::mailbox::{CapabilitiesResp, CommandId, HpkeAlgorithms, MailboxReqHeader};
use caliptra_api::Capabilities;
use core::mem::size_of;
use libapi_caliptra::mailbox_api::execute_mailbox_cmd;
use libapi_caliptra::ocp_lock::OcpLock;
use libsyscall_caliptra::mailbox::Mailbox;
use libsyscall_caliptra::system::System;
use romtime::println;
use zerocopy::{FromBytes, IntoBytes};

pub(crate) async fn test_get_algorithms() {
    println!("Starting OCP LOCK get algorithms test");

    let mailbox = Mailbox::new();

    // First check capabilities to ensure OCP LOCK is supported by caliptra-sw
    println!("Checking Caliptra capabilities...");
    let mut cap_req = MailboxReqHeader::default();
    let mut cap_resp_bytes = [0u8; size_of::<CapabilitiesResp>()];

    println!("Executing CAPABILITIES mailbox command");
    match execute_mailbox_cmd(
        &mailbox,
        CommandId::CAPABILITIES.into(),
        cap_req.as_mut_bytes(),
        &mut cap_resp_bytes,
    )
    .await
    {
        Ok(size) => {
            println!("CAPABILITIES command finished with size {}", size);
            if size != size_of::<CapabilitiesResp>() {
                println!("Error: Unexpected capabilities response size {}", size);
                System::exit(1);
            }
            let cap_resp = CapabilitiesResp::read_from_bytes(&cap_resp_bytes).unwrap();
            let caps = Capabilities::try_from(cap_resp.capabilities.as_ref()).unwrap();
            println!("Capabilities: {:?}", caps);
            if !caps.contains(caliptra_api::Capabilities::RT_OCP_LOCK) {
                println!("Error: RT_OCP_LOCK capability not found!");
                System::exit(1);
            }
            println!("RT_OCP_LOCK capability is present");
        }
        Err(err) => {
            println!("Failed to get capabilities: {:?}", err);
            System::exit(1);
        }
    }

    let ocp_lock = OcpLock::new(&mailbox);

    println!("Sending OCP_LOCK_GET_ALGORITHMS command...");

    match ocp_lock.get_algorithms().await {
        Ok(resp) => {
            println!("OCP_LOCK_GET_ALGORITHMS command success");
            // Check that some algorithms are returned.
            // Based on caliptra-sw implementation, it should return all supported ones.
            if resp.hpke_algorithms.is_empty() {
                println!("Error: No HPKE algorithms returned");
                System::exit(1);
            }
            println!("HPKE algorithms: {:?}", resp.hpke_algorithms);
            println!("Access key sizes: {:?}", resp.access_key_sizes);
        }
        Err(err) => {
            println!("OCP_LOCK_GET_ALGORITHMS command failed with err {:?}", err);
            System::exit(1);
        }
    }

    println!("Test passed");
}
pub(crate) async fn test_get_hpke_public_key_x509() {
    println!("Starting OCP LOCK get HPKE public key x509 test");

    let mailbox = Mailbox::new();
    let ocp_lock = OcpLock::new(&mailbox);

    println!("Enumerate HPKE handles...");
    let handles_resp = ocp_lock
        .enumerate_hpke_handles()
        .await
        .unwrap_or_else(|err| {
            println!("OCP_LOCK_ENUMERATE_HPKE_HANDLES failed with err {:?}", err);
            System::exit(1);
            unreachable!();
        });

    let handle = handles_resp.hpke_handles[..handles_resp.hpke_handle_count as usize]
        .iter()
        .find(|handle| handle.hpke_algorithm == HpkeAlgorithms::ECDH_P384_HKDF_SHA384_AES_256_GCM)
        .unwrap();

    let mut cert_buf = [0u8; OcpLock::MAX_ENDORSEMENT_CERT_SIZE];

    let serial_number = 0xAAAA;
    let subject_name = b"Sample Endorsement Cert";
    match ocp_lock
        .get_hpke_public_key_x509(serial_number, subject_name, handle, &mut cert_buf)
        .await
    {
        Ok(cert_len) => {
            println!(
                "OCP LOCK get HPKE public key x509 success, size {}",
                cert_len
            );
        }
        Err(err) => {
            println!(
                "OCP_LOCK_GET_HPKE_PUBLIC_KEY_X509 failed with err {:x?}",
                err
            );
            System::exit(1);
        }
    }

    println!("Test passed");
}
