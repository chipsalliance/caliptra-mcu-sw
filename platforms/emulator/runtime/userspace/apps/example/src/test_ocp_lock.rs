// Licensed under the Apache-2.0 license

use caliptra_api::mailbox::{
    CapabilitiesResp, CommandId, HpkeAlgorithms, MailboxReqHeader, Request,
};
use caliptra_api::Capabilities;
use caliptra_mcu_libapi_caliptra::mailbox_api::execute_mailbox_cmd;
use caliptra_mcu_libapi_caliptra::ocp_lock::{OcpLock, OcpLockEnumerateHpkeHandlesResp};
use caliptra_mcu_libapi_caliptra::signer::CaliptraDpeSigner;
use caliptra_mcu_libsyscall_caliptra::mailbox::Mailbox;
use caliptra_mcu_libsyscall_caliptra::system::System;
use caliptra_mcu_romtime::println;
use core::mem::size_of;
use zerocopy::{FromBytes, FromZeros, IntoBytes, TryFromBytes};

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

    let ocp_lock = OcpLock::new(&mailbox, &crate::ocp_lock_config::EXAMPLE_RUNTIME_CONFIG);

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

    // Derive exported CDI and stash in DPE handle store for CaliptraDpeSigner
    let dpe_store = caliptra_mcu_libsyscall_caliptra::dpe_handle_store::DpeHandleStore::<
        caliptra_mcu_libsyscall_caliptra::DefaultSyscalls,
    >::new(
        caliptra_mcu_libsyscall_caliptra::dpe_handle_store::DPE_HANDLE_STORE_DRIVER_NUM,
    );
    let mut target = caliptra_mcu_libsyscall_caliptra::dpe_handle_store::DpeHandleRecord::default();
    let handle = if dpe_store.read_attestation_target(&mut target).is_ok()
        || dpe_store.read_leaf_record(&mut target).is_ok()
    {
        dpe::context::ContextHandle(target.context_handle)
    } else {
        dpe::context::ContextHandle::default()
    };

    let cmd = dpe::commands::DeriveContextCmd {
        handle,
        data: dpe::tci::TciMeasurement([0u8; 48]),
        flags: dpe::commands::DeriveContextFlags::EXPORT_CDI
            | dpe::commands::DeriveContextFlags::CREATE_CERTIFICATE
            | dpe::commands::DeriveContextFlags::RETAIN_PARENT_CONTEXT,
        tci_type: 0,
        target_locality: 0,
        svn: 0,
    };
    let mut mbox_req = caliptra_api::mailbox::InvokeDpeReq::new_zeroed();
    let cmd_hdr = dpe::commands::CommandHdr::new(
        caliptra_mcu_libapi_caliptra::mailbox_api::DPE_PROFILE,
        dpe::commands::Command::DERIVE_CONTEXT,
    );
    let cmd_hdr_bytes = cmd_hdr.as_bytes();
    let cmd_bytes = cmd.as_bytes();
    mbox_req.data[..cmd_hdr_bytes.len()].copy_from_slice(cmd_hdr_bytes);
    mbox_req.data[cmd_hdr_bytes.len()..cmd_hdr_bytes.len() + cmd_bytes.len()]
        .copy_from_slice(cmd_bytes);
    mbox_req.data_size = (cmd_hdr_bytes.len() + cmd_bytes.len()) as u32;

    let mut mbox_resp = caliptra_api::mailbox::InvokeDpeResp::default();
    execute_mailbox_cmd(
        &mailbox,
        caliptra_api::mailbox::InvokeDpeReq::ID.0,
        mbox_req.as_mut_bytes(),
        mbox_resp.as_mut_bytes(),
    )
    .await
    .unwrap();

    let (resp, _) =
        dpe::response::DeriveContextExportedCdiResp::try_read_from_prefix(&mbox_resp.data).unwrap();
    assert_eq!(resp.resp_hdr.status, 0);

    if target.context_handle != [0u8; 16] {
        target.context_handle = resp.parent_handle.0;
        let _ = dpe_store.write_record(target.fw_id, &target);
    }
    dpe_store.write_exported_cdi(&resp.exported_cdi).unwrap();

    let ocp_lock = OcpLock::new(&mailbox, &crate::ocp_lock_config::EXAMPLE_RUNTIME_CONFIG);
    let signer = CaliptraDpeSigner::new(&mailbox);

    println!("Enumerate HPKE handles...");
    let mut handles_resp = OcpLockEnumerateHpkeHandlesResp::default();
    ocp_lock
        .enumerate_hpke_handles(&mut handles_resp)
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

    match ocp_lock
        .get_hpke_public_key_x509(handle, &mut cert_buf, &signer)
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
