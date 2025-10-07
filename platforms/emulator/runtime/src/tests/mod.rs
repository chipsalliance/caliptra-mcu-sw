// Licensed under the Apache-2.0 license

pub(crate) mod circular_log_test;
pub(crate) mod doe_transport_test;
pub(crate) mod flash_ctrl_test;
pub(crate) mod flash_storage_test;
pub(crate) mod i3c_target_test;
pub(crate) mod linear_log_test;
#[cfg(feature = "test-mctp-capsule-loopback")]
pub(crate) mod mctp_test;
pub(crate) mod mcu_mbox_driver_loopback_test;
pub(crate) mod mcu_mbox_test;
pub(crate) mod mm_flash_ctrl_test; // mcu mailbox based flash ctrl driver test
pub(crate) mod mm_flash_storage_test; // mcu mailbox based flash storage driver test

pub(crate) fn run_kernel_op_with_timeout<F>(timeout: usize, mut condition: F) -> bool
where
    F: FnMut() -> bool,
{
    for _ in 0..timeout {
        crate::board::run_kernel_op(1);
        if condition() {
            return true;
        }
    }
    false
}
