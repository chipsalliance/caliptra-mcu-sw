// Licensed under the Apache-2.0 license

use crate::{usb_combo, usb_dev0_mem, usb_dev1, usb_dev1_mem};
use core::mem::{offset_of, size_of};

#[test]
fn compound_offsets_and_packet_memory_capacity() {
    type Combo = usb_combo::regs::UsbCombo;
    assert_eq!(usb_combo::USB_COMBO_ADDR, 0x2000_0000);
    assert_eq!(usb_dev1::USB_DEV1_CSR_ADDR, 0x2000_2000);
    assert_eq!(offset_of!(Combo, dev0_csr_intstat), 0x20);
    assert_eq!(offset_of!(Combo, dev0_csr_intsetstat), 0x28);
    assert_eq!(offset_of!(Combo, recovery_prot_cap_0), 0x804);
    assert_eq!(offset_of!(Combo, recovery_window_pad), 0xffc);
    assert_eq!(offset_of!(Combo, hub_control), 0x1030);
    assert_eq!(offset_of!(Combo, hub_ulpidebug), 0x103c);
    assert_eq!(offset_of!(Combo, hub_descriptor_high), 0x1040);
    assert_eq!(size_of::<Combo>(), 0x1310);
    assert_eq!(usb_dev0_mem::USB_DEV0_MEM_ADDR, 0x3000_0000);
    assert_eq!(usb_dev1_mem::USB_DEV1_MEM_ADDR, 0x3001_0000);
    assert_eq!(offset_of!(usb_dev0_mem::regs::UsbDev0Mem, usb_dev0_mem), 0);
    assert_eq!(offset_of!(usb_dev1_mem::regs::UsbDev1Mem, usb_dev1_mem), 0);
    assert_eq!(size_of::<usb_dev0_mem::regs::UsbDev0Mem>(), 0x1_0000);
    assert_eq!(size_of::<usb_dev1_mem::regs::UsbDev1Mem>(), 0x1_0000);
}

#[test]
fn endpoint_overrides_and_ulpi_mode_bit() {
    assert_eq!(
        usb_combo::bits::EpskipT::Skip.val(u32::MAX).value,
        0x3fff_ffff
    );
    assert_eq!(
        usb_combo::bits::IntenT::EpIntEn.val(u32::MAX).value,
        0x3fff_ffff
    );
    assert_eq!(
        usb_combo::bits::IntstatT::EpUpper.val(u32::MAX).value,
        0x3fff_f000
    );
    assert_eq!(
        usb_dev1::bits::EpskipT::Skip.val(u32::MAX).value,
        0x3fff_ffff
    );
    assert_eq!(usb_combo::bits::UlpidebugT::PhyMode::SET.value, 1 << 31);
}
