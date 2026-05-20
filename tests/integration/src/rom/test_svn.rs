// Licensed under the Apache-2.0 license

#[cfg(test)]
mod test {
    use caliptra_api::SocManager;
    use caliptra_mcu_hw_model::McuHwModel;

    use crate::test::{start_runtime_hw_model, TestParams};

    #[test]
    fn test_unprovisioned_max_svn() {
        let mut model = start_runtime_hw_model(TestParams {
            rom_only: true,
            ..Default::default()
        });

        assert_eq!(
            model
                .caliptra_soc_manager()
                .soc_ifc()
                .fuse_soc_manifest_max_svn()
                .read()
                .svn(),
            128
        );
    }
}
