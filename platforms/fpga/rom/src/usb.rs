// Licensed under the Apache-2.0 license

#[cfg(feature = "test-lpcip-usb-enumeration")]
pub fn enumeration_test() -> ! {
    caliptra_mcu_usb_common::enumeration_test(test_parameters())
}

pub const FPGA_USB_COMBO_ADDR: usize = 0xa420_0000;
pub const FPGA_USB_DEV0_MEM_ADDR: usize = 0xa430_0000;

pub fn test_parameters() -> caliptra_mcu_usb_common::UsbParams {
    use caliptra_mcu_romtime::StaticRef;
    use caliptra_mcu_usb_common::UsbParams;

    // VCK190 maps the USB blocks through AXI at these platform addresses, not
    // the subsystem-local addresses in the generated register definitions.
    // The board/gateware must release external USB3320 reset and supply its
    // reference/ULPI and CSR/SRAM clocks before entering this test. No PHY
    // reset GPIO is assumed here. Failed startup is reported by the driver.
    // Placeholder identity/power values are gated test policy, not release IDs
    // or an approved board VBUS budget. Hardware services hub requests; Device 0
    // is port 1 and Device 1 stays disabled at reset.
    UsbParams {
        registers: unsafe { StaticRef::new(FPGA_USB_COMBO_ADDR as *const _) },
        packet_memory: unsafe { StaticRef::new(FPGA_USB_DEV0_MEM_ADDR as *const _) },
        vendor_id: 0x0424,
        product_id: 0x0007,
        device_revision: 0x0100,
        self_powered: true,
        max_power_2ma: 0,
        remote_wakeup: false,
        force_full_speed: false,
        enable_hub: true,
        enable_logs: true,
        poll_limit: 1_000_000,
    }
}
