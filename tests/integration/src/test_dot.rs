//! Licensed under the Apache-2.0 license

//! This module tests Device Ownership Transfer.

#[cfg(test)]
mod test {
    use std::{
        collections::HashMap,
        sync::{LazyLock, Mutex},
    };

    use crate::test::{start_runtime_hw_model, TestParams, TEST_LOCK};
    use caliptra_api::{
        calc_checksum,
        mailbox::{
            CmDeriveStableKeyReq, CmDeriveStableKeyResp, CmHashAlgorithm, CmHmacReq, CmHmacResp,
            CmStableKeyType, CommandId, CMB_HMAC_MAX_SIZE,
        },
        SocManager,
    };
    use caliptra_hw_model::HwModel;
    use mcu_error::McuError;
    use mcu_hw_model::McuHwModel;
    use mcu_rom_common::{BootFlow, McuRomBootStatus};
    use zerocopy::{FromBytes, IntoBytes};

    static HMACS: LazyLock<Mutex<HashMap<Vec<u8>, Vec<u8>>>> =
        LazyLock::new(|| Mutex::new(HashMap::new()));

    fn compute_hmac_cached(blob: &[u8]) -> Vec<u8> {
        let mut hmacs = HMACS.lock().unwrap();

        match hmacs.get(blob) {
            Some(h) => h.clone(),
            None => {
                let h = compute_hmac(blob);
                hmacs.insert(blob.to_vec(), h.clone());
                h
            }
        }
    }

    fn compute_hmac(blob: &[u8]) -> Vec<u8> {
        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let mut hw = start_runtime_hw_model(TestParams {
            feature: Some("test-do-nothing"),
            ..Default::default()
        });

        println!("Waiting for caliptra ready for mailbox");
        hw.step_until(|m| {
            (m.mci_flow_status() & 0xffff) as u16
                >= McuRomBootStatus::CaliptraReadyForMailbox.into()
        });
        println!("deriving stable key");

        // TODO: derive stable key
        let mut req = CmDeriveStableKeyReq {
            key_type: CmStableKeyType::IDevId.into(),
            ..Default::default()
        };
        let label = [0u8; 32];
        req.info[..23].copy_from_slice(b"Caliptra DOT stable key");
        let req = req.as_mut_bytes();
        println!("calc_checksum");
        calc_checksum(CommandId::CM_DERIVE_STABLE_KEY.into(), req);

        let mut resp = CmDeriveStableKeyResp::default();
        println!("mailbox_exec");
        hw.caliptra_soc_manager()
            .mailbox_exec(
                CommandId::CM_DERIVE_STABLE_KEY.into(),
                req,
                resp.as_mut_bytes(),
            )
            .unwrap()
            .unwrap();
        let cmk = resp.cmk;

        println!("hmac computation");
        let mut req = CmHmacReq {
            cmk,
            hash_algorithm: CmHashAlgorithm::Sha512.into(),
            data_size: blob.len() as u32,
            ..Default::default()
        };
        req.data[..blob.len()].copy_from_slice(blob);

        let req = req.as_mut_bytes();
        calc_checksum(CommandId::CM_HMAC.into(), req);

        let mut resp = CmHmacResp::default();
        hw.caliptra_soc_manager()
            .mailbox_exec(CommandId::CM_HMAC.into(), req, resp.as_mut_bytes())
            .unwrap()
            .unwrap();

        // force the compiler to keep the lock
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        resp.mac.to_vec()
    }

    #[test]
    fn test_dot_blob_valid() {
        let blob = [0u8; 32]; // TODO: make a valid DOT blob
        let hmac = compute_hmac_cached(&blob);
    }

    #[test]
    fn test_dot_blob_corrupt() {
        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let mut hw = start_runtime_hw_model(TestParams {
            dot_flash_initial_contents: Some(vec![0x12; 4096]),
            rom_only: true,
            ..Default::default()
        });

        hw.step_until(|m| m.cycle_count() > 10_000_000 || m.mci_fw_fatal_error().is_some());

        let status = hw.mci_fw_fatal_error().unwrap_or(0);
        assert_eq!(
            u32::from(McuError::ROM_COLD_BOOT_DOT_BLOB_CORRUPT_ERROR),
            status
        );

        // force the compiler to keep the lock
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}
