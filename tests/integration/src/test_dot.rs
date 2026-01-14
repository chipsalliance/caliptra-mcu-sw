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
            CmStableKeyType, CommandId,
        },
    };
    use mcu_error::McuError;
    use mcu_hw_model::McuHwModel;
    use mcu_rom_common::McuRomBootStatus;
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

    /// Computes an HMAC of the blob using the Caliptra DOT stable key. Used to make HMACs of DOT blobs.
    fn compute_hmac(blob: &[u8]) -> Vec<u8> {
        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let mut hw = start_runtime_hw_model(TestParams {
            feature: Some("test-do-nothing"),
            ..Default::default()
        });

        hw.step_until(|m| {
            (m.mci_flow_status() & 0xffff) as u16
                >= McuRomBootStatus::CaliptraReadyForMailbox.into()
        });

        let mut req = CmDeriveStableKeyReq {
            key_type: CmStableKeyType::IDevId.into(),
            ..Default::default()
        };
        req.info[..23].copy_from_slice(b"Caliptra DOT stable key");
        let req = req.as_mut_bytes();
        let chksum = calc_checksum(CommandId::CM_DERIVE_STABLE_KEY.into(), req);
        req[..4].copy_from_slice(&chksum.to_le_bytes());

        let resp = hw
            .caliptra_mailbox_execute(CommandId::CM_DERIVE_STABLE_KEY.into(), req)
            .unwrap()
            .unwrap();
        let resp = CmDeriveStableKeyResp::read_from_bytes(&resp).unwrap();
        let cmk = resp.cmk;
        let mut req = CmHmacReq {
            cmk,
            hash_algorithm: CmHashAlgorithm::Sha512.into(),
            data_size: blob.len() as u32,
            ..Default::default()
        };
        req.data[..blob.len()].copy_from_slice(blob);

        let req = req.as_mut_bytes();
        let chksum = calc_checksum(CommandId::CM_HMAC.into(), req);
        req[..4].copy_from_slice(&chksum.to_le_bytes());

        let resp = hw
            .caliptra_mailbox_execute(CommandId::CM_HMAC.into(), req)
            .unwrap()
            .unwrap();
        let resp = CmHmacResp::read_from_bytes(&resp).unwrap();

        // force the compiler to keep the lock
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        resp.mac.to_vec()
    }

    #[test]
    fn test_dot_blob_valid() {
        let blob = [0u8; 32]; // TODO: make a valid DOT blob
        let hmac = compute_hmac_cached(&blob);
        assert_eq!(
            &[
                0xa5u8, 0xc9, 0xc4, 0xcf, 0xb8, 0xbc, 0x25, 0x94, 0x57, 0x75, 0x5a, 0x75, 0x16,
                0x54, 0xf8, 0xd6, 0x50, 0x5c, 0xc8, 0xb1, 0xd3, 0xdf, 0x3b, 0xf8, 0x62, 0x72, 0x44,
                0xa6, 0x6d, 0xaa, 0xcd, 0x28, 0x7f, 0x54, 0x69, 0x5d, 0xc1, 0x36, 0x06, 0xb5, 0xae,
                0x09, 0x54, 0x71, 0xed, 0x32, 0xf8, 0xce, 0xbe, 0x2a, 0xf2, 0x7a, 0x7d, 0xc3, 0x44,
                0xab, 0xb5, 0x23, 0xef, 0x45, 0x25, 0x9c, 0x5d, 0xf6
            ][..],
            &hmac
        );
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
