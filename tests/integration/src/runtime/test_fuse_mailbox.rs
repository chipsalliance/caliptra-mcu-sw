// Licensed under the Apache-2.0 license

use crate::{
    runtime::execute_authorized_req_raw,
    test::{start_runtime_hw_model, TestParams},
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
use zerocopy::FromBytes;

const VENDOR_NON_SECRET_PROD_PARTITION: u32 = 0x0e;

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
    let mut hw = start_runtime_hw_model(TestParams {
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
    let mut hw = start_runtime_hw_model(TestParams {
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
    let mut hw = start_runtime_hw_model(TestParams {
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
    let mut hw = start_runtime_hw_model(TestParams {
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
    let mut hw = start_runtime_hw_model(TestParams {
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
