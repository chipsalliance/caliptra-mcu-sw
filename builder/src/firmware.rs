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

    pub const HITLESS_UPDATE_FLOW: FwId = FwId {
        bin_name: "hitless_update_flow",
        ..BASE_FWID
    };
}

pub const REGISTERED_FW: &[&FwId] = &[
    &hw_model_tests::MAILBOX_RESPONDER,
    &hw_model_tests::HITLESS_UPDATE_FLOW,
];

pub const CPTRA_REGISTERED_FW: &[&FwId] =
    &[&caliptra_builder::firmware::hw_model_tests::MCU_HITLESS_UPDATE_FLOW];
