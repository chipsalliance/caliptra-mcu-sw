// Licensed under the Apache-2.0 license

#[cfg(test)]
mod test {
    use crate::test::{start_runtime_hw_model, TestParams, TEST_LOCK};
    use caliptra_emu_bus::ReadWriteRegister;
    use caliptra_mcu_hw_model::{McuHwModel, NetworkManager};
    use tock_registers::interfaces::Readable;

    fn create_hw_with_network() -> caliptra_mcu_hw_model::DefaultHwModel {
        start_runtime_hw_model(TestParams {
            include_network_rom: true,
            rom_only: true,
            ..Default::default()
        })
    }

    #[test]
    #[cfg_attr(feature = "fpga_realtime", ignore)]
    fn test_network_mbox_lock_acquire() {
        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let mut hw = create_hw_with_network();
        assert!(hw.has_network_cpu(), "Network CPU should be present");

        let mut mgr = hw.network_manager();
        let mbox = mgr.mbox();

        // First lock read should succeed (return 0 = lock acquired)
        let lock_val = mbox.read_network_mbox_lock();
        assert_eq!(
            lock_val.reg.get(),
            0,
            "First lock read should return 0 (lock acquired)"
        );

        // Second lock read should fail (return non-zero = lock busy)
        let lock_val = mbox.read_network_mbox_lock();
        assert_ne!(
            lock_val.reg.get(),
            0,
            "Second lock read should return non-zero (lock busy)"
        );

        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    #[test]
    #[cfg_attr(feature = "fpga_realtime", ignore)]
    fn test_network_mbox_cmd_write_read() {
        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let mut hw = create_hw_with_network();
        let mut mgr = hw.network_manager();
        let mbox = mgr.mbox();

        let lock_val = mbox.read_network_mbox_lock();
        assert_eq!(lock_val.reg.get(), 0, "Lock should be acquired");

        let cmd_val: u32 = 0xDEAD_BEEF;
        mbox.write_network_mbox_cmd(cmd_val);
        let read_back = mbox.read_network_mbox_cmd();
        assert_eq!(
            read_back, cmd_val,
            "CMD register should match written value"
        );

        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    #[test]
    #[cfg_attr(feature = "fpga_realtime", ignore)]
    fn test_network_mbox_dlen_write_read() {
        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let mut hw = create_hw_with_network();
        let mut mgr = hw.network_manager();
        let mbox = mgr.mbox();

        let lock_val = mbox.read_network_mbox_lock();
        assert_eq!(lock_val.reg.get(), 0, "Lock should be acquired");

        let dlen_val: u32 = 256;
        mbox.write_network_mbox_dlen(dlen_val);
        let read_back = mbox.read_network_mbox_dlen();
        assert_eq!(
            read_back, dlen_val,
            "DLEN register should match written value"
        );

        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    #[test]
    #[cfg_attr(feature = "fpga_realtime", ignore)]
    fn test_network_mbox_sram_write_read() {
        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let mut hw = create_hw_with_network();
        let mut mgr = hw.network_manager();
        let mbox = mgr.mbox();

        let lock_val = mbox.read_network_mbox_lock();
        assert_eq!(lock_val.reg.get(), 0, "Lock should be acquired");

        let test_data: [u32; 4] = [0xCAFE_BABE, 0x1234_5678, 0xA5A5_A5A5, 0x0000_FFFF];
        for (i, &val) in test_data.iter().enumerate() {
            mbox.write_network_mbox_sram(val, i);
        }

        for (i, &expected) in test_data.iter().enumerate() {
            let read_back = mbox.read_network_mbox_sram(i);
            assert_eq!(
                read_back, expected,
                "SRAM word at index {i} should match written value"
            );
        }

        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    #[test]
    #[cfg_attr(feature = "fpga_realtime", ignore)]
    fn test_network_mbox_target_user_write_read() {
        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let mut hw = create_hw_with_network();
        let mut mgr = hw.network_manager();
        let mbox = mgr.mbox();

        let lock_val = mbox.read_network_mbox_lock();
        assert_eq!(lock_val.reg.get(), 0, "Lock should be acquired");

        let target_user_val: u32 = 0x42;
        mbox.write_network_mbox_target_user(target_user_val);
        let read_back = mbox.read_network_mbox_target_user();
        assert_eq!(
            read_back, target_user_val,
            "target_user register should match written value"
        );

        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    #[test]
    #[cfg_attr(feature = "fpga_realtime", ignore)]
    fn test_network_mbox_full_flow() {
        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let mut hw = create_hw_with_network();
        let mut mgr = hw.network_manager();
        let mbox = mgr.mbox();

        // 1. Acquire the lock
        let lock_val = mbox.read_network_mbox_lock();
        assert_eq!(lock_val.reg.get(), 0, "Lock should be acquired");

        // 2. Set CMD
        let cmd: u32 = 0x0001;
        mbox.write_network_mbox_cmd(cmd);
        assert_eq!(mbox.read_network_mbox_cmd(), cmd);

        // 3. Set DLEN
        let dlen: u32 = 16; // 4 words
        mbox.write_network_mbox_dlen(dlen);
        assert_eq!(mbox.read_network_mbox_dlen(), dlen);

        // 4. Write payload to SRAM
        let payload: [u32; 4] = [0x11111111, 0x22222222, 0x33333333, 0x44444444];
        for (i, &word) in payload.iter().enumerate() {
            mbox.write_network_mbox_sram(word, i);
        }

        // 5. Verify SRAM contents
        for (i, &expected) in payload.iter().enumerate() {
            assert_eq!(
                mbox.read_network_mbox_sram(i),
                expected,
                "Payload word {i} mismatch"
            );
        }

        // 6. Set execute
        mbox.write_network_mbox_execute(ReadWriteRegister::new(1));
        let exec = mbox.read_network_mbox_execute();
        assert_eq!(exec.reg.get(), 1, "Execute should be set");

        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}
