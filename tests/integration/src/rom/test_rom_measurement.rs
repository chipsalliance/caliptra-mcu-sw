// Licensed under the Apache-2.0 license

use crate::test::{get_rom_with_feature, start_runtime_hw_model, TestParams, TEST_LOCK};
use caliptra_api::mailbox::{CommandId, InvokeDpeReq, InvokeDpeResp};
use caliptra_mcu_hw_model::McuHwModel;
use dpe::commands::{CertifyKeyCommand, CertifyKeyFlags, CertifyKeyP384Cmd, Command, CommandHdr};
use dpe::context::ContextHandle;
use dpe::response::{CertifyKeyP384Resp, ResponseHdr};
use dpe::DpeProfile;
use sha2::{Digest, Sha384};
use std::mem::{offset_of, size_of};
use std::sync::atomic::Ordering;
use x509_parser::der_parser::der::parse_der_sequence;
use zerocopy::{IntoBytes, TryFromBytes};

#[test]
fn test_rom_digest_stash_is_optional_and_tagged_without_fe_status() {
    let lock = TEST_LOCK.lock().unwrap();
    lock.fetch_add(1, Ordering::Relaxed);
    let fe_status_digest = Sha384::digest([0u8; 4]);

    for (feature, stash_enabled) in [("", false), ("test-stash-rom-digest", true)] {
        let rom = std::fs::read(get_rom_with_feature(feature)).unwrap();
        let expected_digest = rom[rom.len() - 48..].to_vec();
        let mut hw = start_runtime_hw_model(TestParams {
            custom_mcu_rom: Some(rom),
            // A jump-to-self image keeps userspace from changing ROM's DPE chain.
            custom_mcu_runtime: Some(vec![0x6f, 0, 0, 0, 0x6f, 0, 0, 0]),
            rom_only: true,
            caliptra_soc_axi_user: Some(1),
            ..Default::default()
        });
        let deadline = hw.cycle_count() + 100_000_000;
        hw.step_until(|hw| {
            hw.mci_boot_milestones()
                .contains(caliptra_mcu_romtime::McuBootMilestones::COLD_BOOT_FLOW_COMPLETE)
                || hw.cycle_count() >= deadline
        });
        assert!(hw
            .mci_boot_milestones()
            .contains(caliptra_mcu_romtime::McuBootMilestones::COLD_BOOT_FLOW_COMPLETE));

        let command = CertifyKeyP384Cmd {
            handle: ContextHandle::default(),
            flags: CertifyKeyFlags::empty(),
            format: CertifyKeyCommand::FORMAT_X509,
            label: [1; 48],
        };
        let header = CommandHdr::new(DpeProfile::P384Sha384, Command::CERTIFY_KEY);
        let mut request = InvokeDpeReq {
            data_size: (size_of::<CommandHdr>() + size_of::<CertifyKeyP384Cmd>()) as u32,
            ..Default::default()
        };
        request.data[..size_of::<CommandHdr>()].copy_from_slice(header.as_bytes());
        request.data[size_of::<CommandHdr>()..request.data_size as usize]
            .copy_from_slice(command.as_bytes());
        let command_id = u32::from(CommandId::INVOKE_DPE_ECC384);
        request.hdr.chksum =
            caliptra_api::calc_checksum(command_id, &request.as_bytes_partial().unwrap()[4..]);
        let mut response = None;
        for _ in 0..10 {
            match hw.caliptra_mailbox_execute(command_id, request.as_bytes_partial().unwrap()) {
                Ok(reply) => {
                    response = reply;
                    break;
                }
                Err(caliptra_hw_model::ModelError::UnableToLockMailbox) => {
                    for _ in 0..1_000_000 {
                        hw.step();
                    }
                }
                Err(error) => panic!("CertifyKey failed: {error:?}"),
            }
        }
        let response = response.expect("Core CertifyKey did not return a response");
        let data = &response[offset_of!(InvokeDpeResp, data)..];
        let (response_header, _) = ResponseHdr::try_ref_from_prefix(data).unwrap();
        assert_eq!(response_header.status, 0);
        let size_offset = offset_of!(CertifyKeyP384Resp, cert_size);
        let cert_size =
            u32::from_le_bytes(data[size_offset..size_offset + 4].try_into().unwrap()) as usize;
        let cert_offset = offset_of!(CertifyKeyP384Resp, cert);
        let (_, cert) =
            x509_parser::parse_x509_certificate(&data[cert_offset..cert_offset + cert_size])
                .unwrap();
        let extension = cert
            .extensions()
            .iter()
            .find(|extension| extension.oid.to_id_string() == "2.23.133.5.4.5")
            .unwrap();
        let (remaining, tcbs) = parse_der_sequence(extension.value).unwrap();
        assert!(remaining.is_empty());
        let mut rom_measurements = 0;
        for tcb in tcbs.as_sequence().unwrap() {
            let fields = tcb.as_sequence().unwrap();
            let metadata = fields
                .iter()
                .find(|field| field.header.tag().0 == 9)
                .unwrap()
                .as_slice()
                .unwrap();
            let fwids = fields
                .iter()
                .find(|field| field.header.tag().0 == 6)
                .unwrap()
                .as_slice()
                .unwrap();
            let (remaining, fwid) = parse_der_sequence(fwids).unwrap();
            assert!(remaining.is_empty());
            let digest = fwid.as_sequence().unwrap()[1].as_slice().unwrap();
            assert_ne!(digest, &fe_status_digest[..]);
            if metadata == b"MROM" {
                rom_measurements += 1;
                assert_eq!(digest, expected_digest);
            }
        }
        assert_eq!(rom_measurements, usize::from(stash_enabled));
    }

    lock.fetch_add(1, Ordering::Relaxed);
}
