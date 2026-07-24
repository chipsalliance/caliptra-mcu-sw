// Licensed under the Apache-2.0 license

//! Test that the stable owner key CMK derived by ROM is handed off to Runtime
//! via the shared `.handoff` DCCM table.

#[cfg(test)]
mod test {
    use crate::test::{start_runtime_hw_model, TestParams, TEST_LOCK};
    use caliptra_mcu_hw_model::McuHwModel;
    use caliptra_mcu_registers_generated::fuses;

    #[test]
    fn test_cmk_handoff_integrity() {
        let _lock = TEST_LOCK.lock().unwrap();

        let seed_offset = fuses::STABLE_OWNER_KEY_PERSONALIZATION_SEED.byte_offset;
        let seed_size = fuses::STABLE_OWNER_KEY_PERSONALIZATION_SEED.byte_size;
        let mut otp = vec![0u8; 4096];
        for (idx, byte) in otp[seed_offset..][..seed_size].iter_mut().enumerate() {
            *byte = (idx as u8) + 1;
        }

        let mut hw = start_runtime_hw_model(TestParams {
            otp_memory: Some(otp),
            rom_only: false,
            feature: Some("test-cmk-handoff"),
            rom_feature: Some("stable-owner-key"),
            ..Default::default()
        });

        hw.step_until_exit_success()
            .expect("CMK HandOff verification failed in runtime");
    }
}
