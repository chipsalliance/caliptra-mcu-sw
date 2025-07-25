// Licensed under the Apache-2.0 license

use core::fmt::Write;
use libsyscall_caliptra::mci::Mci;
use libsyscall_caliptra::mci::mci_reg::NOTIF0_INTR_TRIG_R;
use romtime::{println, test_exit};

#[allow(unused)]
pub(crate) async fn test_mci_read_write() {
    println!("Starting test_mci_read_write");

    let mci: Mci = Mci::new();

    let reg_val = mci.read(NOTIF0_INTR_TRIG_R, 0).unwrap();
    if reg_val != 0 {
        println!("Initial value of NOTIF0_INTR_TRIG_R is not zero: {}", reg_val);
        test_exit(1);
    }
    mci.write(NOTIF0_INTR_TRIG_R, 0, 0x2).unwrap();
    let reg_val = mci.read(NOTIF0_INTR_TRIG_R, 0).unwrap();
    if reg_val != 0x2 {
        println!("NOTIF0_INTR_TRIG_R is not 0x2: {}", reg_val);
        test_exit(1);
    }
}