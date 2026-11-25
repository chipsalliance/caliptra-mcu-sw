// Licensed under the Apache-2.0 license

fn main() {
    let revision = caliptra_mcu_hw_revision::HardwareRevision::from_env()
        .unwrap_or_else(|error| panic!("{error}"));
    revision.emit_build_configuration();
}
