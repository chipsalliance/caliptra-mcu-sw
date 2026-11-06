// Licensed under the Apache-2.0 license

use crate::{
    root_bus::{AutoRootBus, AutoRootBusOffsets},
    usb_combo::{UsbComboBus, UsbComboGenerated},
    usb_dev0_mem::{UsbDev0MemBus, UsbDev0MemGenerated},
    usb_dev1::{UsbDev1Bus, UsbDev1Generated},
    usb_dev1_mem::{UsbDev1MemBus, UsbDev1MemGenerated},
};
use caliptra_emu_bus::{Bus, BusError};
use caliptra_emu_types::RvSize;

fn fixture() -> AutoRootBus {
    let mut bus = AutoRootBus::new(
        vec![],
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    );
    bus.usb_combo_periph = Some(UsbComboBus {
        periph: Box::new(UsbComboGenerated::new()),
    });
    bus.usb_dev1_periph = Some(UsbDev1Bus {
        periph: Box::new(UsbDev1Generated::new()),
    });
    bus.usb_dev0_mem_periph = Some(UsbDev0MemBus {
        periph: Box::new(UsbDev0MemGenerated::new()),
    });
    bus.usb_dev1_mem_periph = Some(UsbDev1MemBus {
        periph: Box::new(UsbDev1MemGenerated::new()),
    });
    bus
}

#[test]
fn generated_root_bus_routes_usb_windows_and_preserves_holes() {
    let offsets = AutoRootBusOffsets::default();
    assert_eq!(
        (offsets.usb_combo_offset, offsets.usb_combo_size),
        (0x2000_0000, 0x1310)
    );
    assert_eq!(
        (offsets.usb_dev1_offset, offsets.usb_dev1_size),
        (0x2000_2000, 0x38)
    );
    assert_eq!(
        (offsets.usb_dev0_mem_offset, offsets.usb_dev0_mem_size),
        (0x3000_0000, 0x1_0000)
    );
    assert_eq!(
        (offsets.usb_dev1_mem_offset, offsets.usb_dev1_mem_size),
        (0x3001_0000, 0x1_0000)
    );
    let mut bus = fixture();
    for (address, value) in [
        (0x2000_0000, 0x800),
        (0x2000_0004, 0x0200_0000),
        (0x2000_0030, 0x6fc),
        (0x2000_0804, 0x2050_434f),
        (0x2000_0ffc, 0),
        (0x2000_1030, 0x800),
        (0x2000_103c, 0),
        (0x2000_2004, 0x0200_0000),
    ] {
        assert_eq!(bus.read(RvSize::Word, address), Ok(value), "{address:#x}");
    }
    for address in [
        0x2000_0038,
        0x2000_0800,
        0x2000_0904,
        0x2000_1038,
        0x2000_1400,
        0x2000_2038,
        0x3002_0000,
    ] {
        assert_eq!(
            bus.read(RvSize::Word, address),
            Err(BusError::LoadAccessFault),
            "{address:#x}"
        );
        assert_eq!(
            bus.write(RvSize::Word, address, 1),
            Err(BusError::StoreAccessFault),
            "{address:#x}"
        );
    }
}

#[test]
fn packet_memories_are_independent_and_cover_the_last_word() {
    let mut bus = fixture();
    for (address, value) in [
        (0x3000_0000, 0x0123_4567),
        (0x3000_fffc, 0x89ab_cdef),
        (0x3001_0000, 0x7654_3210),
        (0x3001_fffc, 0xfedc_ba98),
    ] {
        bus.write(RvSize::Word, address, value).unwrap();
        assert_eq!(bus.read(RvSize::Word, address), Ok(value));
    }
    assert_eq!(bus.read(RvSize::Word, 0x3000_0000), Ok(0x0123_4567));
    assert_eq!(bus.read(RvSize::Word, 0x3000_fffc), Ok(0x89ab_cdef));
    assert_eq!(
        bus.read(RvSize::Word, 0x3000_0001),
        Err(BusError::LoadAddrMisaligned)
    );
    bus.warm_reset();
    assert_eq!(bus.read(RvSize::Word, 0x3000_fffc), Ok(0));
}

#[test]
fn generated_alias_access_is_write_one_to_set_and_read_only_fields_are_preserved() {
    let mut bus = fixture();
    bus.write(RvSize::Word, 0x2000_0020, u32::MAX).unwrap();
    assert_eq!(bus.read(RvSize::Word, 0x2000_0020), Ok(0));
    bus.write(RvSize::Word, 0x2000_0028, 1).unwrap();
    bus.write(RvSize::Word, 0x2000_0028, 2).unwrap();
    bus.write(RvSize::Word, 0x2000_0028, 0).unwrap();
    assert_eq!(bus.read(RvSize::Word, 0x2000_0028), Ok(3));
    bus.write(RvSize::Word, 0x2000_0004, u32::MAX).unwrap();
    assert_eq!(bus.read(RvSize::Word, 0x2000_0004), Ok(0x0200_7800));
    bus.write(RvSize::Word, 0x2000_0030, 0).unwrap();
    assert_eq!(bus.read(RvSize::Word, 0x2000_0030), Ok(0x6fc));
}
