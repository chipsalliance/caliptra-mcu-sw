// Licensed under the Apache-2.0 license

use core::fmt::Write;
use libsyscall_caliptra::mci::mci_reg::{RESET_REASON, WDT_TIMER1_EN};
use libsyscall_caliptra::mci::Mci;
use romtime::{println, test_exit};

#[allow(unused)]
pub(crate) async fn test_mci_read_write() {
    println!("Starting test_mci_read_write");

    let mci: Mci = Mci::new();

    let reg_val = mci.read(WDT_TIMER1_EN, 0).unwrap();
    if reg_val != 0 {
        println!("Initial value of WDT_TIMER1_EN is not zero: {}", reg_val);
        test_exit(1);
    }
    mci.write(WDT_TIMER1_EN, 0, 0x2).unwrap();
    let reg_val = mci.read(WDT_TIMER1_EN, 0).unwrap();
    if reg_val != 0x2 {
        println!("WDT_TIMER1_EN is not 0x2: {}", reg_val);
        test_exit(1);
    }
}

#[allow(unused)]
pub(crate) async fn test_mci_fw_boot_reset() {
    println!("Starting test_mci_fw_boot_reset");

    let mci: Mci = Mci::new();

    // Read reset reason
    let reset_reason = mci.read(RESET_REASON, 0).unwrap();
    println!("Reset reason register: 0x{:08x}", reset_reason);

    // Check if this is a FW boot reset (bit 1)
    const FW_BOOT_RESET_BIT: u32 = 1 << 1;

    if reset_reason & FW_BOOT_RESET_BIT != 0 {
        println!("FW boot reset detected successfully!");
        // Test passed - we assume this warm reset was triggered by our test
        // Note: Without persistent memory accessible from userspace, we can't
        // definitively prove this was our reset vs another warm reset
        return;
    } else {
        println!("Cold boot detected, triggering warm reset...");

        // Set the reason to FW boot reset
        let reset_reason = mci.write(RESET_REASON, 0, FW_BOOT_RESET_BIT).unwrap();
        // Trigger warm reset
        mci.trigger_warm_reset().unwrap();

        // Should never reach here if reset works
        println!("ERROR: Still running after reset request!");
        test_exit(1);
    }
}
