// Licensed under the Apache-2.0 license

use crate::{
    runtime::{execute_authorized_req_raw, start_command_authorized_runtime},
    test::TestParams,
};
use anyhow::Result;
use caliptra_api::calc_checksum;
use caliptra_mcu_hw_model::McuHwModel;
use caliptra_mcu_mbox_common::messages::{
    FuseLockPartitionReq, FuseReadReq, FuseRevokeVendorPkHashReq, FuseRevokeVendorPubKeyReq,
    FuseWriteReq, MailboxReqHeader, MailboxRespHeader, MailboxRespHeaderVarSize, McuFeProgReq,
    ProvisionOwnerPkHashReq, ProvisionVendorPkHashReq, RevokeVendorPubKeyType,
};
use caliptra_mcu_registers_generated::fuses::{
    OTP_CPTRA_SS_OWNER_PK_HASH, OTP_CPTRA_SS_OWNER_PK_HASH_VALID,
    VENDOR_NON_SECRET_PROD_PARTITION_BYTE_OFFSET, VENDOR_NON_SECRET_PROD_PARTITION_BYTE_SIZE,
};
use caliptra_mcu_romtime::McuBootMilestones;
use core::mem::size_of;
use zerocopy::{FromBytes, IntoBytes};

const VENDOR_NON_SECRET_PROD_PARTITION: u32 = 0x0e;

#[test]
fn test_command_authorized_runtime_installs_owner_key() -> Result<()> {
    use super::{core_request, AsymmetricCommandAuthorizer, TEST_ECC_PRIV_KEY, TEST_MLDSA_SEED};
    use crate::test::TEST_LOCK;
    use caliptra_api::mailbox::{
        AuthManifestSource, GetImageInfoReq, GetImageInfoResp, MailboxReqHeader as CoreReqHeader,
        Request,
    };
    use caliptra_mcu_command_auth_challenge_signer::CommandAuthChallengeSigner;
    use caliptra_mcu_flash_image::O_AUTH_KEY_ID;

    let _lock = TEST_LOCK.lock().unwrap();
    let mut hw = start_command_authorized_runtime(TestParams {
        feature: Some("test-mcu-mbox-cmds"),
        ..Default::default()
    });
    let mut request = GetImageInfoReq {
        hdr: CoreReqHeader::default(),
        fw_id: O_AUTH_KEY_ID.to_le_bytes(),
        flags: AuthManifestSource::Owner.flag_bits(),
    };
    request.hdr.chksum = calc_checksum(
        GetImageInfoReq::ID.into(),
        &request.as_bytes()[size_of::<CoreReqHeader>()..],
    );
    let response = core_request(&mut hw, GetImageInfoReq::ID, request.as_bytes())?;
    assert_response_checksum(&response);
    let response = GetImageInfoResp::read_from_bytes(&response)
        .map_err(|error| anyhow::anyhow!("Invalid Owner key image-info response: {error:?}"))?;
    let signer = AsymmetricCommandAuthorizer::new(&TEST_ECC_PRIV_KEY, &TEST_MLDSA_SEED)?;
    assert_eq!(response.digest, signer.anchor()?);
    Ok(())
}

#[cfg(not(feature = "fpga_realtime"))]
#[test]
fn test_command_authorization_modes_and_scopes() -> Result<()> {
    use super::{
        authorize_cmd_with_context, get_auth_cmd_challenge, install_test_owner_auth_manifest,
    };
    use crate::test::{start_runtime_hw_model, TEST_LOCK};
    use caliptra_image_types::FwVerificationPqcKeyType;
    use caliptra_mcu_config_emulator::EMULATOR_UEID_SERIAL_NUMBER;
    use caliptra_mcu_mbox_common::authorization::{
        AuthorizationMetadata, CommandAuthMode, CommandAuthority,
    };
    use caliptra_mcu_mbox_common::messages::{CommandId, DeviceCapsReq, AUTH_CMD_NONCE_LEN};

    fn signed_read(
        metadata: &AuthorizationMetadata,
        nonce: &[u8; AUTH_CMD_NONCE_LEN],
    ) -> Result<Vec<u8>> {
        let request = FuseReadReq {
            hdr: MailboxReqHeader::default(),
            partition: VENDOR_NON_SECRET_PROD_PARTITION,
            entry: 0,
        };
        let mut packet = authorize_cmd_with_context(
            CommandId::MC_FUSE_READ.0,
            request.as_bytes(),
            metadata,
            nonce,
        )?;
        let checksum = calc_checksum(CommandId::MC_AUTHORIZED_COMMAND.0, &packet[4..]);
        packet[..4].copy_from_slice(&checksum.to_le_bytes());
        Ok(packet)
    }

    let _lock = TEST_LOCK.lock().unwrap();
    let serial_offset =
        caliptra_mcu_registers_generated::fuses::OTP_CPTRA_CORE_IDEVID_CERT_IDEVID_ATTR.byte_offset
            + 12 * size_of::<u32>();
    let mut otp = vec![0; serial_offset + EMULATOR_UEID_SERIAL_NUMBER.len()];
    otp[serial_offset..serial_offset + EMULATOR_UEID_SERIAL_NUMBER.len()]
        .copy_from_slice(&EMULATOR_UEID_SERIAL_NUMBER);
    let mut hw = start_runtime_hw_model(TestParams {
        feature: Some("test-mcu-mbox-cmds"),
        otp_memory: Some(otp),
        caliptra_soc_axi_user: Some(1),
        ..Default::default()
    });
    hw.step_until(|hw| {
        hw.mci_boot_milestones()
            .contains(McuBootMilestones::FIRMWARE_MAILBOX_READY)
    });
    assert_eq!(
        &hw.read_otp_memory()[serial_offset..serial_offset + EMULATOR_UEID_SERIAL_NUMBER.len()],
        &EMULATOR_UEID_SERIAL_NUMBER
    );
    let capabilities = hw.mailbox_execute_req(DeviceCapsReq::default())?;
    assert_eq!(&capabilities.caps[32..48], &[0; 16]);

    for mode in [CommandAuthMode::ChallengeBound, CommandAuthMode::Offline] {
        let nonce = match mode {
            CommandAuthMode::ChallengeBound => get_auth_cmd_challenge(&mut hw)?,
            CommandAuthMode::Offline => [0; AUTH_CMD_NONCE_LEN],
        };
        let unprovisioned = signed_read(&AuthorizationMetadata::default(), &nonce)?;
        assert!(hw
            .mailbox_execute(CommandId::MC_AUTHORIZED_COMMAND.0, &unprovisioned)
            .is_err());
    }
    install_test_owner_auth_manifest(&mut hw, FwVerificationPqcKeyType::LMS, 0)?;

    let authorization_offset = size_of::<FuseReadReq>() + size_of::<u32>();
    for mode in [CommandAuthMode::ChallengeBound, CommandAuthMode::Offline] {
        for ueid in [[0; 16], EMULATOR_UEID_SERIAL_NUMBER] {
            let metadata = AuthorizationMetadata::new(CommandAuthority::Owner, ueid);
            let nonce = match mode {
                CommandAuthMode::ChallengeBound => get_auth_cmd_challenge(&mut hw)?,
                CommandAuthMode::Offline => [0; AUTH_CMD_NONCE_LEN],
            };
            let packet = signed_read(&metadata, &nonce)?;
            let response = hw
                .mailbox_execute(CommandId::MC_AUTHORIZED_COMMAND.0, &packet)?
                .ok_or_else(|| anyhow::anyhow!("Authorized fuse read returned no data"))?;
            assert_response_checksum(&response);
            let (header, body) = MailboxRespHeaderVarSize::ref_from_prefix(&response)
                .map_err(|error| anyhow::anyhow!("Invalid fuse response: {error:?}"))?;
            assert_eq!(header.data_len as usize, body.len());
            assert!(body.len() >= 4);
            let valid_bits = u32::from_le_bytes(body[..4].try_into().unwrap());
            assert!(valid_bits > 0);
            assert_eq!(body.len(), 4 + (valid_bits as usize).div_ceil(8));

            let replay = hw.mailbox_execute(CommandId::MC_AUTHORIZED_COMMAND.0, &packet);
            match mode {
                CommandAuthMode::ChallengeBound => assert!(replay.is_err()),
                CommandAuthMode::Offline => assert_eq!(replay?, Some(response)),
            }
        }

        let wrong_device = AuthorizationMetadata::new(CommandAuthority::Owner, [0x43; 16]);
        let nonce = match mode {
            CommandAuthMode::ChallengeBound => get_auth_cmd_challenge(&mut hw)?,
            CommandAuthMode::Offline => [0; AUTH_CMD_NONCE_LEN],
        };
        let packet = signed_read(&wrong_device, &nonce)?;
        assert!(hw
            .mailbox_execute(CommandId::MC_AUTHORIZED_COMMAND.0, &packet)
            .is_err());

        let device =
            AuthorizationMetadata::new(CommandAuthority::Owner, EMULATOR_UEID_SERIAL_NUMBER);
        let nonce = match mode {
            CommandAuthMode::ChallengeBound => get_auth_cmd_challenge(&mut hw)?,
            CommandAuthMode::Offline => [0; AUTH_CMD_NONCE_LEN],
        };
        let mut packet = signed_read(&device, &nonce)?;
        let target_offset = authorization_offset + 2 * size_of::<u32>();
        packet[target_offset..target_offset + 16].fill(0);
        let checksum = calc_checksum(CommandId::MC_AUTHORIZED_COMMAND.0, &packet[4..]);
        packet[..4].copy_from_slice(&checksum.to_le_bytes());
        assert!(hw
            .mailbox_execute(CommandId::MC_AUTHORIZED_COMMAND.0, &packet)
            .is_err());
    }

    let metadata = AuthorizationMetadata::new(CommandAuthority::Owner, EMULATOR_UEID_SERIAL_NUMBER);
    let pending_nonce = get_auth_cmd_challenge(&mut hw)?;
    let bound = signed_read(&metadata, &pending_nonce)?;
    let offline = signed_read(&metadata, &[0; AUTH_CMD_NONCE_LEN])?;
    let response = hw
        .mailbox_execute(CommandId::MC_AUTHORIZED_COMMAND.0, &offline)?
        .ok_or_else(|| anyhow::anyhow!("Offline fuse read returned no data"))?;
    assert_response_checksum(&response);

    let mut tampered = bound.clone();
    let nonce_offset = authorization_offset + size_of::<AuthorizationMetadata>();
    tampered[nonce_offset..nonce_offset + AUTH_CMD_NONCE_LEN].fill(0);
    let checksum = calc_checksum(CommandId::MC_AUTHORIZED_COMMAND.0, &tampered[4..]);
    tampered[..4].copy_from_slice(&checksum.to_le_bytes());
    assert!(hw
        .mailbox_execute(CommandId::MC_AUTHORIZED_COMMAND.0, &tampered)
        .is_err());

    let response = hw
        .mailbox_execute(CommandId::MC_AUTHORIZED_COMMAND.0, &bound)?
        .ok_or_else(|| anyhow::anyhow!("Pending challenge-bound fuse read returned no data"))?;
    assert_response_checksum(&response);
    assert!(hw
        .mailbox_execute(CommandId::MC_AUTHORIZED_COMMAND.0, &bound)
        .is_err());
    Ok(())
}

fn assert_response_checksum(response: &[u8]) {
    assert!(response.len() >= size_of::<u32>());
    assert_eq!(
        u32::from_le_bytes(response[..size_of::<u32>()].try_into().unwrap()),
        calc_checksum(0, &response[size_of::<u32>()..])
    );
}

fn assert_header_response(response: &[u8]) {
    assert_eq!(response.len(), size_of::<MailboxRespHeader>());
    assert_response_checksum(response);
    let header = MailboxRespHeader::read_from_bytes(response).expect("invalid response header");
    assert_eq!(header.fips_status, MailboxRespHeader::FIPS_STATUS_APPROVED);
}

fn assert_fuse_read_response(response: &[u8], expected_bits: u32, expected_data: &[u8]) {
    assert_response_checksum(response);
    let (header, body) =
        MailboxRespHeaderVarSize::ref_from_prefix(response).expect("invalid fuse read response");
    assert_eq!(
        header.hdr.fips_status,
        MailboxRespHeader::FIPS_STATUS_APPROVED
    );
    assert_eq!(
        header.data_len as usize,
        size_of::<u32>() + expected_data.len()
    );
    assert_eq!(
        response.len(),
        size_of::<MailboxRespHeaderVarSize>() + header.data_len as usize
    );
    assert_eq!(
        u32::from_le_bytes(body[..size_of::<u32>()].try_into().unwrap()),
        expected_bits
    );
    assert_eq!(&body[size_of::<u32>()..], expected_data);
}

#[test]
fn test_provision_owner_pk_hash_mailbox() -> Result<()> {
    let mut hw = start_command_authorized_runtime(TestParams {
        feature: Some("test-mcu-mbox-cmds"),
        ..Default::default()
    });
    hw.step_until(|hw| {
        hw.mci_boot_milestones()
            .contains(McuBootMilestones::FIRMWARE_MAILBOX_READY)
    });

    assert!(execute_authorized_req_raw(
        &mut hw,
        ProvisionOwnerPkHashReq {
            hdr: MailboxReqHeader::default(),
            hash: [0; 48],
        },
    )
    .is_err());

    let hash = [0x5a; 48];
    let response = execute_authorized_req_raw(
        &mut hw,
        ProvisionOwnerPkHashReq {
            hdr: MailboxReqHeader::default(),
            hash,
        },
    )?;
    assert_header_response(&response);

    let otp = hw.read_otp_memory();
    let start = OTP_CPTRA_SS_OWNER_PK_HASH.byte_offset;
    assert_eq!(&otp[start..start + hash.len()], &hash);
    let valid_start = OTP_CPTRA_SS_OWNER_PK_HASH_VALID.byte_offset;
    assert_eq!(
        u32::from_le_bytes(otp[valid_start..valid_start + 4].try_into().unwrap()) & 1,
        1
    );

    let response = execute_authorized_req_raw(
        &mut hw,
        ProvisionOwnerPkHashReq {
            hdr: MailboxReqHeader::default(),
            hash,
        },
    )?;
    assert_header_response(&response);

    assert!(execute_authorized_req_raw(
        &mut hw,
        ProvisionOwnerPkHashReq {
            hdr: MailboxReqHeader::default(),
            hash: [0xa5; 48],
        },
    )
    .is_err());

    Ok(())
}

#[test]
fn test_raw_fuse_read_write_and_lock_mailbox() -> Result<()> {
    let mut hw = start_command_authorized_runtime(TestParams {
        feature: Some("test-mcu-mbox-cmds"),
        ..Default::default()
    });
    hw.step_until(|hw| {
        hw.mci_boot_milestones()
            .contains(McuBootMilestones::FIRMWARE_MAILBOX_READY)
    });
    let word_addr = (VENDOR_NON_SECRET_PROD_PARTITION_BYTE_OFFSET / 4) as u32;
    let data = 0xa5a5_5a5a;

    for _ in 0..2 {
        let response = execute_authorized_req_raw(
            &mut hw,
            FuseWriteReq {
                word_addr,
                data,
                mask: u32::MAX,
                ..Default::default()
            },
        )?;
        assert_header_response(&response);
    }

    let response = execute_authorized_req_raw(
        &mut hw,
        FuseReadReq {
            partition: VENDOR_NON_SECRET_PROD_PARTITION,
            entry: 0,
            ..Default::default()
        },
    )?;
    let otp = hw.read_otp_memory();
    let expected = &otp[VENDOR_NON_SECRET_PROD_PARTITION_BYTE_OFFSET
        ..VENDOR_NON_SECRET_PROD_PARTITION_BYTE_OFFSET + 128];
    assert_fuse_read_response(&response, 128 * 8, expected);
    assert_eq!(&expected[..4], &data.to_le_bytes());

    let repeated_response = execute_authorized_req_raw(
        &mut hw,
        FuseReadReq {
            partition: VENDOR_NON_SECRET_PROD_PARTITION,
            entry: 0,
            ..Default::default()
        },
    )?;
    assert_fuse_read_response(&repeated_response, 128 * 8, expected);
    assert_eq!(repeated_response, response);

    let last_entry = VENDOR_NON_SECRET_PROD_PARTITION_BYTE_SIZE - size_of::<u32>();
    let response = execute_authorized_req_raw(
        &mut hw,
        FuseReadReq {
            partition: VENDOR_NON_SECRET_PROD_PARTITION,
            entry: last_entry as u32,
            ..Default::default()
        },
    )?;
    let start = VENDOR_NON_SECRET_PROD_PARTITION_BYTE_OFFSET + last_entry;
    assert_fuse_read_response(&response, 32, &otp[start..start + 4]);

    for request in [
        FuseReadReq {
            partition: 0x0f,
            entry: 0,
            ..Default::default()
        },
        FuseReadReq {
            partition: 0x01,
            entry: 0,
            ..Default::default()
        },
        FuseReadReq {
            partition: VENDOR_NON_SECRET_PROD_PARTITION,
            entry: 1,
            ..Default::default()
        },
        FuseReadReq {
            partition: VENDOR_NON_SECRET_PROD_PARTITION,
            entry: VENDOR_NON_SECRET_PROD_PARTITION_BYTE_SIZE as u32,
            ..Default::default()
        },
    ] {
        assert!(execute_authorized_req_raw(&mut hw, request).is_err());
    }

    assert!(execute_authorized_req_raw(
        &mut hw,
        FuseWriteReq {
            word_addr,
            data: 0,
            mask: u32::MAX,
            ..Default::default()
        },
    )
    .is_err());

    for _ in 0..2 {
        let response = execute_authorized_req_raw(
            &mut hw,
            FuseLockPartitionReq {
                partition: VENDOR_NON_SECRET_PROD_PARTITION,
                ..Default::default()
            },
        )?;
        assert_header_response(&response);
    }
    assert!(execute_authorized_req_raw(
        &mut hw,
        FuseLockPartitionReq {
            partition: u32::MAX,
            ..Default::default()
        },
    )
    .is_err());

    Ok(())
}

#[test]
fn test_fe_prog_mailbox_validation_and_repetition() -> Result<()> {
    let mut hw = start_command_authorized_runtime(TestParams {
        feature: Some("test-mcu-mbox-cmds"),
        ..Default::default()
    });
    hw.step_until(|hw| {
        hw.mci_boot_milestones()
            .contains(McuBootMilestones::FIRMWARE_MAILBOX_READY)
    });

    assert!(execute_authorized_req_raw(
        &mut hw,
        McuFeProgReq {
            partition: u32::MAX,
            ..Default::default()
        },
    )
    .is_err());

    let response = execute_authorized_req_raw(
        &mut hw,
        McuFeProgReq {
            partition: 0,
            ..Default::default()
        },
    )?;
    assert_header_response(&response);

    let response = execute_authorized_req_raw(
        &mut hw,
        McuFeProgReq {
            partition: 0,
            ..Default::default()
        },
    )?;
    assert_header_response(&response);

    Ok(())
}

#[test]
fn test_vendor_pk_hash_provision_and_revoke_mailbox() -> Result<()> {
    let mut hw = start_command_authorized_runtime(TestParams {
        feature: Some("test-mcu-mbox-cmds"),
        ..Default::default()
    });
    hw.step_until(|hw| {
        hw.mci_boot_milestones()
            .contains(McuBootMilestones::FIRMWARE_MAILBOX_READY)
    });
    let hash = [0xa5; 48];

    for _ in 0..2 {
        let response = execute_authorized_req_raw(
            &mut hw,
            ProvisionVendorPkHashReq {
                hdr: MailboxReqHeader::default(),
                slot: 1,
                hash,
            },
        )?;
        assert_header_response(&response);
    }

    assert!(execute_authorized_req_raw(
        &mut hw,
        ProvisionVendorPkHashReq {
            hdr: MailboxReqHeader::default(),
            slot: 16,
            hash,
        },
    )
    .is_err());
    assert!(execute_authorized_req_raw(
        &mut hw,
        ProvisionVendorPkHashReq {
            hdr: MailboxReqHeader::default(),
            slot: 1,
            hash: [0x5a; 48],
        },
    )
    .is_err());

    for request in [
        FuseRevokeVendorPkHashReq {
            reserved: 1,
            vendor_pk_hash_slot: 1,
            ..Default::default()
        },
        FuseRevokeVendorPkHashReq {
            vendor_pk_hash_slot: 0,
            ..Default::default()
        },
        FuseRevokeVendorPkHashReq {
            vendor_pk_hash_slot: 2,
            ..Default::default()
        },
        FuseRevokeVendorPkHashReq {
            vendor_pk_hash_slot: 16,
            ..Default::default()
        },
    ] {
        assert!(execute_authorized_req_raw(&mut hw, request).is_err());
    }

    for _ in 0..2 {
        let response = execute_authorized_req_raw(
            &mut hw,
            FuseRevokeVendorPkHashReq {
                vendor_pk_hash_slot: 1,
                ..Default::default()
            },
        )?;
        assert_header_response(&response);
    }

    Ok(())
}

#[test]
fn test_revoke_vendor_pub_key_mailbox_validation_and_repetition() -> Result<()> {
    let mut hw = start_command_authorized_runtime(TestParams {
        feature: Some("test-mcu-mbox-cmds"),
        ..Default::default()
    });
    hw.step_until(|hw| {
        hw.mci_boot_milestones()
            .contains(McuBootMilestones::FIRMWARE_MAILBOX_READY)
    });

    for request in [
        FuseRevokeVendorPubKeyReq {
            reserved: 1,
            vendor_pk_hash_slot: 0,
            key_type: RevokeVendorPubKeyType::Ecdsa384.into(),
            key_index: 1,
            ..Default::default()
        },
        FuseRevokeVendorPubKeyReq {
            vendor_pk_hash_slot: 16,
            key_type: RevokeVendorPubKeyType::Ecdsa384.into(),
            key_index: 1,
            ..Default::default()
        },
        FuseRevokeVendorPubKeyReq {
            vendor_pk_hash_slot: 0,
            key_type: u32::MAX,
            key_index: 1,
            ..Default::default()
        },
        FuseRevokeVendorPubKeyReq {
            vendor_pk_hash_slot: 0,
            key_type: RevokeVendorPubKeyType::Ecdsa384.into(),
            key_index: u32::MAX,
            ..Default::default()
        },
        FuseRevokeVendorPubKeyReq {
            vendor_pk_hash_slot: 0,
            key_type: RevokeVendorPubKeyType::Ecdsa384.into(),
            key_index: 0,
            ..Default::default()
        },
    ] {
        assert!(execute_authorized_req_raw(&mut hw, request).is_err());
    }

    for _ in 0..2 {
        let response = execute_authorized_req_raw(
            &mut hw,
            FuseRevokeVendorPubKeyReq {
                vendor_pk_hash_slot: 0,
                key_type: RevokeVendorPubKeyType::Ecdsa384.into(),
                key_index: 1,
                ..Default::default()
            },
        )?;
        assert_header_response(&response);
    }

    Ok(())
}
