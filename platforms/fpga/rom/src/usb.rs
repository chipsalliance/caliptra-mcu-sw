// Licensed under the Apache-2.0 license

#[cfg(feature = "test-lpcip-usb-enumeration")]
pub fn enumeration_test() -> ! {
    caliptra_mcu_usb_common::enumeration_test(test_parameters())
}

pub fn test_parameters() -> caliptra_mcu_usb_common::UsbParams {
    use caliptra_mcu_registers_generated::{usb_combo, usb_dev0_mem};
    use caliptra_mcu_romtime::StaticRef;
    use caliptra_mcu_usb_common::UsbParams;

    // The board/gateware must release external USB3320 reset and supply its
    // reference/ULPI and CSR/SRAM clocks before entering this test. No PHY
    // reset GPIO is assumed here. Failed startup is reported by the driver.
    // Placeholder identity/power values are gated test policy, not release IDs
    // or an approved board VBUS budget. The driver leaves hub topology alone.
    UsbParams {
        registers: unsafe { StaticRef::new(usb_combo::USB_COMBO_ADDR as *const _) },
        packet_memory: unsafe { StaticRef::new(usb_dev0_mem::USB_DEV0_MEM_ADDR as *const _) },
        vendor_id: 0xffff,
        product_id: 0xffff,
        device_revision: 0x0100,
        self_powered: true,
        max_power_2ma: 0,
        remote_wakeup: false,
        force_full_speed: false,
        poll_limit: 1_000_000,
    }
}
