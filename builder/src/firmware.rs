// Licensed under the Apache-2.0 license

use caliptra_builder::FwId;

pub mod hw_model_tests {
    use super::*;

    pub const MAILBOX_RESPONDER: FwId = FwId {
        crate_name: "mcu-test-fw-mailbox-responder",
        bin_name: "mcu-test-fw-mailbox-responder",
        features: &["emu"],
    };

    pub const HITLESS_UPDATE_FLOW: FwId = FwId {
        crate_name: "mcu-test-fw-hitless-update-flow",
        bin_name: "mcu-test-fw-hitless-update-flow",
        features: &["emu"],
    };

    pub const AXI_BYPASS: FwId = FwId {
        crate_name: "mcu-test-fw-axi-bypass",
        bin_name: "mcu-test-fw-axi-bypass",
        features: &["emu"],
    };

    pub const EXCEPTION_HANDLER: FwId = FwId {
        crate_name: "mcu-test-fw-exception-handler",
        bin_name: "mcu-test-fw-exception-handler",
        features: &["emu"],
    };

    pub const USB_RESPONDER: FwId = FwId {
        crate_name: "mcu-test-fw-usb-responder",
        bin_name: "mcu-test-fw-usb-responder",
        features: &["emu"],
    };

    pub const USB_OCP_RECOVERY: FwId = FwId {
        crate_name: "mcu-test-fw-usb-ocp-recovery",
        bin_name: "mcu-test-fw-usb-ocp-recovery",
        features: &["emu"],
    };

    pub const SW_DIGEST_LOCK: FwId = FwId {
        crate_name: "mcu-test-fw-sw-digest-lock",
        bin_name: "mcu-test-fw-sw-digest-lock",
        features: &["emu"],
    };

    pub const OTP_BLANK_CHECK: FwId = FwId {
        crate_name: "mcu-test-fw-otp-blank-check",
        bin_name: "mcu-test-fw-otp-blank-check",
        features: &["emu"],
    };

    pub const LC_CTRL: FwId = FwId {
        crate_name: "mcu-test-fw-lc-ctrl",
        bin_name: "mcu-test-fw-lc-ctrl",
        features: &["emu"],
    };
}

pub const REGISTERED_FW: &[&FwId] = &[
    &hw_model_tests::MAILBOX_RESPONDER,
    &hw_model_tests::HITLESS_UPDATE_FLOW,
    &hw_model_tests::AXI_BYPASS,
    &hw_model_tests::EXCEPTION_HANDLER,
    &hw_model_tests::USB_RESPONDER,
    &hw_model_tests::USB_OCP_RECOVERY,
    &hw_model_tests::SW_DIGEST_LOCK,
    &hw_model_tests::OTP_BLANK_CHECK,
    &hw_model_tests::LC_CTRL,
];

pub const CPTRA_REGISTERED_FW: &[&FwId] = &[
    &caliptra_builder::firmware::hw_model_tests::MCU_HITLESS_UPDATE_FLOW,
    &caliptra_builder::firmware::driver_tests::AXI_BYPASS,
];
