// Licensed under the Apache-2.0 license

pub fn enumeration_test() -> ! {
    use caliptra_mcu_registers_generated::{usb_combo, usb_dev0_mem};
    use caliptra_mcu_romtime::StaticRef;
    use caliptra_mcu_usb_common::UsbParams;

    // The emulator supplies released PHY reset and a running ULPI clock.
    // These mappings and test-only values are not release device identity.
    caliptra_mcu_usb_common::enumeration_test(UsbParams {
        registers: unsafe { StaticRef::new(usb_combo::USB_COMBO_ADDR as *const _) },
        packet_memory: unsafe { StaticRef::new(usb_dev0_mem::USB_DEV0_MEM_ADDR as *const _) },
        vendor_id: 0xffff,
        product_id: 0xffff,
        device_revision: 0x0100,
        self_powered: true,
        max_power_2ma: 0,
        remote_wakeup: false,
        force_full_speed: false,
        poll_limit: 10_000,
    })
}
