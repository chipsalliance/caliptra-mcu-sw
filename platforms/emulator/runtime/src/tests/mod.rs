// Licensed under the Apache-2.0 license

#[cfg(any(feature = "test-log-flash-circular", feature = "test-log-flash-linear",))]
pub(crate) mod circular_log_test;
#[cfg(feature = "test-doe-transport-loopback")]
pub(crate) mod doe_transport_test;
#[cfg(any(
    feature = "test-flash-ctrl-init",
    feature = "test-flash-ctrl-read-write-page",
    feature = "test-flash-ctrl-erase-page",
))]
pub(crate) mod flash_ctrl_test;
#[cfg(any(
    feature = "test-flash-storage-read-write",
    feature = "test-flash-storage-erase",
))]
pub(crate) mod flash_storage_test;
#[cfg(any(feature = "test-i3c-simple", feature = "test-i3c-constant-writes",))]
pub(crate) mod i3c_target_test;
#[cfg(any(feature = "test-log-flash-circular", feature = "test-log-flash-linear",))]
pub(crate) mod linear_log_test;
#[cfg(feature = "test-mctp-capsule-loopback")]
pub(crate) mod mctp_test;
#[cfg(feature = "test-mcu-mbox-soc-requester-loopback")]
pub(crate) mod mcu_mbox_driver_loopback_test;
#[cfg(feature = "test-mcu-mbox-driver")]
pub(crate) mod mcu_mbox_test;
