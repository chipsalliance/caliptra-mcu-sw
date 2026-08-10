// Licensed under the Apache-2.0 license

use crate::test::{compile_runtime, start_runtime_hw_model, CustomCaliptraFw, TestParams};
use anyhow::Result;
use caliptra_api::{
    calc_checksum,
    mailbox::{CapabilitiesResp, CommandId, MailboxReqHeader},
    SocManager,
};
use caliptra_mcu_config::capabilities::McuRuntimeCapabilities;
use caliptra_mcu_hw_model::{LifecycleControllerState, McuHwModel};
use caliptra_mcu_mbox_common::messages::{
    DeviceCapsReq, DpeSignerContextCertReq, FirmwareVersionReq, GetAuthCmdChallengeReq,
    GetDpeCertChainReq, McuFeProgReq,
};
use caliptra_mcu_romtime::McuBootMilestones;
use zerocopy::{FromBytes, IntoBytes};

fn semantic_version(packed_version: u32) -> String {
    format!(
        "{}.{}.{}",
        (packed_version >> 24) & 0xff,
        (packed_version >> 16) & 0xff,
        packed_version & 0xffff
    )
}

#[test]
fn test_invalid_mailbox_cmd() -> Result<()> {
    let mut hw = start_runtime_hw_model(TestParams {
        feature: Some("test-mcu-mbox-cmds"),
        ..Default::default()
    });

    // wait another little bit for the mailbox to come up after the runtime
    hw.step_until(|hw| {
        hw.mci_boot_milestones()
            .contains(McuBootMilestones::FIRMWARE_MAILBOX_READY)
    });

    // Send an unknown command (0x0) with an invalid checksum.
    // The firmware should reject it with a mailbox failure.
    let cmd: u32 = 0x0;
    let resp = hw.mailbox_execute(cmd, &[0xaau8; 8]);
    let err_msg = format!("{}", resp.unwrap_err());
    assert!(
        !err_msg.contains("timed out"),
        "Mailbox command should fail with error, not time out. Got: {err_msg}"
    );
    Ok(())
}

#[test]
fn test_firmware_version_cmd() -> Result<()> {
    let mut hw = start_runtime_hw_model(TestParams {
        feature: Some("test-mcu-mbox-cmds"),
        ..Default::default()
    });

    // wait another little bit for the mailbox to come up after the runtime
    hw.step_until(|hw| {
        hw.mci_boot_milestones()
            .contains(McuBootMilestones::FIRMWARE_MAILBOX_READY)
    });

    let caliptra_runtime_version = hw
        .caliptra_soc_manager()
        .soc_ifc()
        .cptra_fw_rev_id()
        .at(1)
        .read();
    let expected_versions = [
        semantic_version(caliptra_runtime_version),
        semantic_version(caliptra_mcu_config::version::get_mcu_runtime_version()),
    ];

    for (index, expected_version) in expected_versions.iter().enumerate() {
        let cmd = FirmwareVersionReq {
            index: index as u32,
            ..Default::default()
        };
        let resp = hw.mailbox_execute_req(cmd)?;

        assert_eq!(resp.hdr.data_len, expected_version.len() as u32);
        let resp_version_str = std::str::from_utf8(&resp.version[..resp.hdr.data_len as usize])
            .expect("Version string is not valid UTF-8");
        assert_eq!(resp_version_str, expected_version);
    }

    for index in [2, 99] {
        let cmd = FirmwareVersionReq {
            index,
            ..Default::default()
        };
        assert!(hw.mailbox_execute_req(cmd).is_err());
    }
    Ok(())
}

#[test]
fn test_device_capabilities_cmd() -> Result<()> {
    let mut hw = start_runtime_hw_model(TestParams {
        feature: Some("test-mcu-mbox-cmds"),
        ..Default::default()
    });

    hw.step_until(|hw| {
        hw.mci_boot_milestones()
            .contains(McuBootMilestones::FIRMWARE_MAILBOX_READY)
    });

    let core_req = MailboxReqHeader {
        chksum: calc_checksum(CommandId::CAPABILITIES.into(), &[]),
    };
    let core_resp = hw
        .caliptra_mailbox_execute(CommandId::CAPABILITIES.into(), core_req.as_bytes())?
        .expect("Core CAPABILITIES returned no response");
    let core_caps = CapabilitiesResp::read_from_bytes(&core_resp)
        .expect("invalid Core CAPABILITIES response")
        .capabilities;

    let resp = hw.mailbox_execute_req(DeviceCapsReq::default())?;
    assert_eq!(&resp.caps[..16], &core_caps);
    assert_eq!(u32::from_be_bytes(resp.caps[16..20].try_into().unwrap()), 0);
    assert_eq!(
        u32::from_be_bytes(resp.caps[20..24].try_into().unwrap()),
        McuRuntimeCapabilities::MCI_MAILBOX_SERVICE.bits()
    );
    assert_eq!(u32::from_be_bytes(resp.caps[24..28].try_into().unwrap()), 0);
    assert_eq!(u32::from_be_bytes(resp.caps[28..32].try_into().unwrap()), 0);
    assert_eq!(&resp.caps[32..], &[0; 4]);
    Ok(())
}

#[test]
fn test_get_auth_cmd_challenge_cmd() -> Result<()> {
    let mut hw = start_runtime_hw_model(TestParams {
        feature: Some("test-mcu-mbox-cmds"),
        ..Default::default()
    });

    // wait another little bit for the mailbox to come up after the runtime
    hw.step_until(|hw| {
        hw.mci_boot_milestones()
            .contains(McuBootMilestones::FIRMWARE_MAILBOX_READY)
    });

    let cmd = GetAuthCmdChallengeReq::default();
    let resp = hw.mailbox_execute_req(cmd)?;

    assert_eq!(
        resp.challenge.len(),
        caliptra_mcu_command_auth_challenge_signer::AUTH_CMD_NONCE_LEN
    );
    assert!(
        resp.challenge
            .iter()
            .copied()
            .reduce(|a, b| (a | b))
            .unwrap()
            != 0,
        "Challenge should not be all-zeros"
    );
    Ok(())
}

#[test]
fn test_fe_prog_authorized_req() -> Result<()> {
    use crate::runtime::execute_authorized_req;
    use caliptra_mcu_builder::{CaliptraBuildArgs, CaliptraBuilder, FirmwareBinaries};

    let mcu_runtime_path = compile_runtime(Some("test-mcu-mbox-cmds"), false);
    let (caliptra_fw, vendor_pk_hash_arr, soc_manifest) =
        if let Ok(binaries) = FirmwareBinaries::from_env() {
            let fw = binaries.caliptra_fw.clone();
            let pk_hash = binaries.vendor_pk_hash().unwrap();
            let manifest = binaries.test_soc_manifest("test-mcu-mbox-cmds").unwrap();
            (fw, pk_hash, manifest)
        } else {
            let mut builder = CaliptraBuilder::new(&CaliptraBuildArgs {
                svn: Some(0),
                mcu_firmware: Some(mcu_runtime_path.clone()),
                ..Default::default()
            });
            let fw = std::fs::read(builder.get_caliptra_fw()?).unwrap();
            let pk_hash_str = builder.get_vendor_pk_hash()?.to_string();
            let pk_hash = hex::decode(&pk_hash_str).unwrap();
            let mut pk_hash_arr = [0u8; 48];
            pk_hash_arr.copy_from_slice(&pk_hash);
            let manifest = std::fs::read(builder.get_soc_manifest(None)?).unwrap();
            (fw, pk_hash_arr, manifest)
        };

    let mut hw = start_runtime_hw_model(TestParams {
        feature: Some("test-mcu-mbox-cmds"),
        custom_caliptra_fw: Some(CustomCaliptraFw {
            fw_bytes: caliptra_fw,
            vendor_pk_hash: vendor_pk_hash_arr,
            soc_manifest: soc_manifest,
        }),
        lifecycle_controller_state: Some(LifecycleControllerState::Prod),
        ..Default::default()
    });

    hw.step_until(|hw| {
        hw.mci_boot_milestones()
            .contains(McuBootMilestones::FIRMWARE_MAILBOX_READY)
    });

    // Verify FE_PROG authorized request succeeds
    let cmd = McuFeProgReq {
        partition: 0,
        ..Default::default()
    };
    let result = execute_authorized_req(&mut hw, cmd);
    assert!(
        result.is_ok(),
        "FE_PROG authorized request failed: {result:?}"
    );

    Ok(())
}

#[test]
fn test_dpe_signer_context_cert_cmd() -> Result<()> {
    let mut hw = start_runtime_hw_model(TestParams {
        feature: Some("test-mcu-mbox-cmds"),
        ocp_lock_en: true,
        ..Default::default()
    });

    hw.step_until(|hw| {
        hw.mci_boot_milestones()
            .contains(McuBootMilestones::FIRMWARE_MAILBOX_READY)
    });

    // 1. Fetch DPE Certificate Chain via MC_GET_DPE_CERTIFICATE_CHAIN (looping across chunks)
    let mut chain_der = Vec::new();
    let mut offset = 0u32;
    loop {
        let chain_req = GetDpeCertChainReq {
            offset,
            size: 1024,
            ..Default::default()
        };
        let chain_resp = hw.mailbox_execute_req(chain_req)?;
        let chunk_len = chain_resp.hdr.data_len as usize;
        if chunk_len == 0 {
            break;
        }
        chain_der.extend_from_slice(&chain_resp.cert_data[..chunk_len]);
        offset += chunk_len as u32;
        if chunk_len < 1024 {
            break;
        }
    }
    assert!(
        !chain_der.is_empty(),
        "DPE Certificate Chain response data length should be non-zero"
    );
    assert_eq!(
        chain_der[0], 0x30,
        "DPE Cert Chain should start with ASN.1 SEQUENCE tag 0x30"
    );

    let mut chain_certs = Vec::new();
    let mut remaining: &[u8] = &chain_der;
    while !remaining.is_empty() && remaining[0] == 0x30 {
        if let Ok(c) = openssl::x509::X509::from_der(remaining) {
            if let Ok(der_bytes) = c.to_der() {
                let der_len = der_bytes.len();
                chain_certs.push(c);
                if remaining.len() >= der_len {
                    remaining = &remaining[der_len..];
                    continue;
                }
            }
        }
        break;
    }
    assert!(
        !chain_certs.is_empty(),
        "Parsed DPE certificate chain should not be empty"
    );

    // 2. Fetch DPE Signer Context Certificate via MC_DPE_SIGNER_CONTEXT_CERT
    let req = DpeSignerContextCertReq::default();
    let resp = hw.mailbox_execute_req(req)?;
    let cert_len = resp.hdr.data_len as usize;
    assert!(cert_len > 0, "Response data length should be non-zero");

    let cert_der = &resp.cert_data[..cert_len];
    assert_eq!(
        cert_der[0], 0x30,
        "Certificate should start with ASN.1 SEQUENCE tag 0x30"
    );

    let cert = openssl::x509::X509::from_der(cert_der)
        .expect("Failed to parse DPE derived leaf certificate as DER");

    // Validate Serial Number (SN)
    let serial_bn = cert
        .serial_number()
        .to_bn()
        .expect("Failed to get serial number BigNum");
    let serial_hex = serial_bn
        .to_hex_str()
        .expect("Failed to convert serial number to hex");
    assert!(!serial_hex.is_empty(), "Serial number should not be empty");

    // Validate Subject CN
    let subject_cn = cert
        .subject_name()
        .entries_by_nid(openssl::nid::Nid::COMMONNAME)
        .next()
        .expect("DPE leaf certificate must have a Common Name entry in Subject");
    let subject_cn_str = std::str::from_utf8(subject_cn.data().as_slice())
        .expect("Subject Common Name should be valid UTF-8");
    assert_eq!(
        subject_cn_str, "DPE Exported CDI",
        "DPE leaf certificate Subject CN should match expected 'DPE Exported CDI'"
    );

    let expected_issuer_cn = "Caliptra 2.1 Ecc384 Rt Alias";

    // Validate Issuer CN
    let issuer_cn = cert
        .issuer_name()
        .entries_by_nid(openssl::nid::Nid::COMMONNAME)
        .next()
        .expect("DPE leaf certificate must have a Common Name entry in Issuer");
    let issuer_cn_str = std::str::from_utf8(issuer_cn.data().as_slice())
        .expect("Issuer Common Name should be valid UTF-8");

    assert_eq!(issuer_cn_str, expected_issuer_cn,);

    // Verify leaf certificate was signed by the runtime alias key
    let expected_signer = chain_certs
        .iter()
        .find(|cert| {
            let sn = cert
                .subject_name()
                .entries_by_nid(openssl::nid::Nid::COMMONNAME)
                .last()
                .unwrap();

            let sn = std::str::from_utf8(sn.data().as_slice()).unwrap();
            sn == expected_issuer_cn
        })
        .unwrap();

    let pubkey = expected_signer.public_key().unwrap();
    assert!(cert.verify(&pubkey).is_ok());

    Ok(())
}
