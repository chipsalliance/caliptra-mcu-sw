// Licensed under the Apache-2.0 license

#[cfg(test)]
mod test {
    use crate::test::{compile_bare_metal_runtime, run_runtime, ROM, TEST_LOCK};
    use mcu_testing_common::DeviceLifecycle;
    use random_port::PortPicker;

    #[test]
    fn test_bare_metal_runtime_boot() {
        let lock = TEST_LOCK.lock().unwrap();

        let rom_path = ROM.clone();
        let runtime_path = compile_bare_metal_runtime();

        let i3c_port = PortPicker::new().random(true).pick().unwrap().to_string();

        let status = run_runtime(
            "test-bare-metal",
            rom_path,
            runtime_path,
            i3c_port,
            true, // active_mode
            DeviceLifecycle::Production,
            None,                      // soc_images
            None,                      // streaming_boot_package_path
            None,                      // primary_flash_image_path
            None,                      // secondary_flash_image_path
            None,                      // caliptra_builder
            Some("2.1.0".to_string()), // hw_revision
            None,                      // fuse_soc_manifest_svn
            None,                      // fuse_soc_manifest_max_svn
            None,                      // fuse_vendor_test_partition
        );

        assert_eq!(status, 0);
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}
