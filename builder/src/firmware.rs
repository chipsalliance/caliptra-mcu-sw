// Licensed under the Apache-2.0 license

use caliptra_builder::FwId;

pub mod hw_model_tests {
    use super::*;

    const BASE_FWID: FwId = FwId {
        crate_name: "mcu-hw-model-test-fw",
        bin_name: "",
        features: &["emu"],
    };

    pub const MAILBOX_RESPONDER: FwId = FwId {
        bin_name: "mailbox_responder",
        ..BASE_FWID
    };

    pub const AXI_BYPASS: FwId = FwId {
        bin_name: "axi_bypass",
        ..BASE_FWID
    };
}

pub const REGISTERED_FW: &[&FwId] = &[
    &hw_model_tests::MAILBOX_RESPONDER,
    &hw_model_tests::AXI_BYPASS,
];
