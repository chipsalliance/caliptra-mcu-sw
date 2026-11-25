// Licensed under the Apache-2.0 license

fn main() {
    caliptra_mcu_hw_revision::HardwareRevision::from_env()
        .unwrap_or_else(|error| panic!("{error}"))
        .emit_build_configuration();
}
