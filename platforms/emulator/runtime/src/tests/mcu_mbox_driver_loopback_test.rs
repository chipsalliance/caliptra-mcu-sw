// Licensed under the Apache-2.0 license

use crate::run_kernel_op;
use crate::tests::mcu_mbox_test::{get_mailbox_tester, IoState, McuMailboxTester};
use kernel::debug;

pub fn test_mcu_mbox_soc_requester_loopback() {
    let tester = get_mailbox_tester();
    // Reset tester before starting a new test.
    tester.reset();
    loop {
        run_kernel_op(1);
    }
}
