// Licensed under the Apache-2.0 license

use super::*;
use caliptra_emu_bus::Bus;
use caliptra_emu_types::RvSize;
use caliptra_mcu_emulator_registers_generated::usb_combo::UsbComboBus;

const GATEWAY: u32 = 0x103c;
const MODE: u32 = 1 << 31;
const ACCESS: u32 = 1 << 25;
const WRITE: u32 = 1 << 24;

struct Phy {
    bus: UsbComboBus,
    host: LpcipUsbHostController,
}

impl Phy {
    fn new() -> Self {
        let combo = UsbCombo::new();
        Self {
            host: combo.host_controller(),
            bus: UsbComboBus {
                periph: Box::new(combo),
            },
        }
    }

    fn command(&mut self, value: u32) {
        self.bus.write(RvSize::Word, GATEWAY, value).unwrap();
    }

    fn gateway(&mut self) -> u32 {
        self.bus.read(RvSize::Word, GATEWAY).unwrap()
    }

    fn read(&mut self, address: u8) -> u8 {
        self.command(MODE | ACCESS | u32::from(address));
        let value = self.gateway();
        assert_eq!(value & ACCESS, 0);
        assert_eq!(value & 0xff, u32::from(address));
        (value >> 16) as u8
    }

    fn write(&mut self, address: u8, value: u8) {
        let command = MODE | ACCESS | WRITE | (u32::from(value) << 8) | u32::from(address);
        self.command(command);
        assert_eq!(self.gateway() & !(0xff << 16), command & !ACCESS);
    }
}

#[test]
fn phy_identity_is_read_only_and_distinct_from_hub_descriptors() {
    let mut f = Phy::new();
    for (address, expected) in [(0, 0x24), (1, 4), (2, 7), (3, 0)] {
        assert_eq!(f.read(address), expected);
        f.write(address, 0xff);
        assert_eq!(f.read(address), expected);
    }
    f.bus.write(RvSize::Word, 0x1008, 0x1122_3344).unwrap();
    assert_eq!(f.read(0), 0x24);
    assert_eq!(f.read(2), 7);
    assert!(!f.host.connected());
}

#[test]
fn phy_reset_defaults_and_alias_reads_match_datasheet() {
    let mut f = Phy::new();
    assert_eq!(f.gateway(), 0);
    for (base, expected) in [(4, 0x41), (7, 0), (10, 6), (13, 0x1f), (16, 0x1f), (22, 0)] {
        for alias in 0..3 {
            assert_eq!(f.read(base + alias), expected);
        }
    }
    for address in 0x13..=0x15 {
        assert_eq!(f.read(address), 0);
        f.write(address, 0xff);
        assert_eq!(f.read(address), 0);
    }
}

#[test]
fn phy_control_write_set_clear_and_reserved_masks() {
    let mut f = Phy::new();
    for (base, mask) in [
        (4, 0x5f),
        (7, 0xff),
        (10, 0xff),
        (13, 0x1f),
        (16, 0x1f),
        (22, 0xff),
    ] {
        f.write(base, 0xa5);
        assert_eq!(f.read(base), 0xa5 & mask);
        f.write(base + 1, 0x0f);
        assert_eq!(f.read(base + 1), 0xaf & mask);
        f.write(base + 2, 0xf0);
        assert_eq!(f.read(base + 2), 0x0f & mask);
    }
}

#[test]
fn phy_function_reset_self_clears_and_preserves_register_array() {
    let mut f = Phy::new();
    f.write(4, 0x40);
    f.write(7, 0x80);
    f.write(10, 0);
    f.write(13, 2);
    f.write(16, 4);
    f.write(22, 0xa5);
    f.write(5, 0x20);
    assert_eq!(f.read(4), 0x40);
    for (address, expected) in [(7, 0x80), (10, 0), (13, 2), (16, 4), (22, 0xa5)] {
        assert_eq!(f.read(address), expected);
    }
    f.write(4, 0x61);
    assert_eq!(f.read(4), 0x41);
    assert_eq!(f.read(22), 0xa5);
}

#[test]
fn phy_external_reset_restores_defaults_and_retains_vbus_level() {
    let mut f = Phy::new();
    f.host.set_vbus(true);
    f.write(4, 0x40);
    f.write(10, 0);
    f.write(22, 0xa5);
    f.host.phy().reset();
    assert_eq!(f.read(4), 0x41);
    assert_eq!(f.read(10), 6);
    assert_eq!(f.read(13), 0x1f);
    assert_eq!(f.read(16), 0x1f);
    assert_eq!(f.read(22), 0);
    assert_eq!(f.read(0x13), 6);
    assert_eq!(f.read(0x14), 0);
}

#[test]
fn phy_interrupt_status_edges_and_read_clear_latch() {
    let mut f = Phy::new();
    f.write(13, 2);
    f.write(16, 4);
    f.host.set_vbus(true);
    assert_eq!(f.read(0x13), 6);
    f.write(0x13, 0);
    f.write(0x14, 0);
    assert_eq!(f.read(0x13), 6);
    assert_eq!(f.read(0x14), 2);
    assert_eq!(f.read(0x14), 0);
    f.host.set_vbus(true);
    assert_eq!(f.read(0x14), 0);
    f.host.set_vbus(false);
    assert_eq!(f.read(0x13), 0);
    assert_eq!(f.read(0x14), 4);
    f.write(13, 0);
    f.host.set_vbus(true);
    assert_eq!(f.read(0x14), 0);
}

#[test]
fn gateway_requires_access_and_honors_data_direction_and_address_high_bits() {
    let mut f = Phy::new();
    f.command(MODE | WRITE | (0xa5 << 8) | 0x16);
    assert_eq!(f.host.phy().snapshot().scratch, 0);
    assert_eq!(f.host.phy().snapshot().completed_accesses, 0);
    f.command(MODE | ACCESS | WRITE | (0xa5 << 8) | 0x16);
    assert!(f.host.phy().snapshot().access_pending);
    f.bus.poll();
    let snapshot = f.host.phy().snapshot();
    assert!(!snapshot.access_pending);
    assert_eq!(snapshot.scratch, 0xa5);
    assert_eq!(snapshot.completed_accesses, 1);
    assert_eq!(f.read(0x16), 0xa5);
    assert_eq!(f.read(6), 0x41);
    assert_eq!(f.host.phy().snapshot().completed_accesses, 3);
    for _ in 0..5 {
        assert_eq!(f.gateway() & ACCESS, 0);
    }
    assert_eq!(f.host.phy().snapshot().completed_accesses, 3);
}

#[test]
fn gateway_read_data_is_retained_on_write_completion() {
    let mut f = Phy::new();
    assert_eq!(f.read(0), 0x24);
    f.write(0x16, 0xa5);
    assert_eq!((f.gateway() >> 16) as u8, 0x24);
    f.command(u32::MAX & !ACCESS);
    assert_eq!(f.gateway(), (MODE | 0x03ff_ffff) & !ACCESS);
}

#[test]
fn gateway_unknown_accesses_do_not_fabricate_success() {
    let mut f = Phy::new();
    for write in [false, true] {
        f.command(MODE | ACCESS | if write { WRITE } else { 0 } | 0xfe);
        for _ in 0..8 {
            assert_ne!(f.gateway() & ACCESS, 0);
            f.bus.poll();
        }
        assert_eq!(f.host.phy().snapshot().completed_accesses, 0);
        assert_eq!(
            f.host.phy().snapshot().last_error,
            Some(LpcipUsbPhyError::UnsupportedRegister {
                address: 0xfe,
                write
            })
        );
    }
    // Software can abort a failed access and submit another command.
    f.command(MODE);
    assert_eq!(f.gateway(), MODE);
    assert_eq!(f.read(0), 0x24);
    assert_eq!(f.host.phy().snapshot().last_error, None);
}

#[test]
fn gateway_utmi_mode_does_not_access_the_usb3320() {
    let mut f = Phy::new();
    f.command(ACCESS | WRITE | (0xa5 << 8) | 0x16);
    assert_ne!(f.gateway() & ACCESS, 0);
    assert_eq!(f.host.phy().snapshot().scratch, 0);
    assert_eq!(
        f.host.phy().snapshot().last_error,
        Some(LpcipUsbPhyError::UnsupportedInterface)
    );
    assert_eq!(f.read(0), 0x24);
}

#[test]
fn gateway_fault_injection_holds_access_until_responsive() {
    let mut f = Phy::new();
    f.host.phy().set_access_stalled(true);
    f.command(MODE | ACCESS | WRITE | (0xa5 << 8) | 0x16);
    for _ in 0..8 {
        assert_ne!(f.gateway() & ACCESS, 0);
    }
    assert_eq!(f.host.phy().snapshot().completed_accesses, 0);
    assert_eq!(f.host.phy().snapshot().scratch, 0);
    assert_eq!(
        f.host.phy().snapshot().last_error,
        Some(LpcipUsbPhyError::AccessStalled)
    );
    f.host.phy().set_access_stalled(false);
    assert_eq!(f.gateway() & ACCESS, 0);
    assert_eq!(f.read(0x16), 0xa5);
}

#[test]
fn gateway_bypasses_hub_table_write_lock_and_is_shared_by_devices() {
    let combo = UsbCombo::new();
    let peer = combo.device1_host_controller();
    let mut f = Phy {
        host: combo.host_controller(),
        bus: UsbComboBus {
            periph: Box::new(combo),
        },
    };
    f.bus.write(RvSize::Word, 0x1030, 1 | CONNECT).unwrap();
    f.write(0x16, 0xa5);
    assert_eq!(peer.phy().snapshot().scratch, 0xa5);
    peer.set_vbus(true);
    assert_eq!(f.read(0x13), 6);
}

#[test]
fn bus_and_mcu_resets_do_not_reset_the_external_phy() {
    let mut f = Phy::new();
    f.write(4, 0x40);
    f.write(10, 0);
    f.write(0x16, 0xa5);
    f.host.set_vbus(true);
    f.bus.write(RvSize::Word, 0, DEV_EN | CONNECT).unwrap();
    f.host.bus_reset(LpcipUsbSpeed::Full).unwrap();
    assert_eq!(f.read(0x16), 0xa5);
    for warm in [true, false] {
        f.command(MODE | ACCESS | 0);
        if warm {
            f.bus.warm_reset();
        } else {
            f.bus.update_reset();
        }
        assert_eq!(f.gateway(), 0);
        assert_eq!(f.host.phy().snapshot().completed_accesses, 0);
        assert_eq!(f.read(4), 0x40);
        assert_eq!(f.read(10), 0);
        assert_eq!(f.read(0x16), 0xa5);
        assert_eq!(f.read(0x13), 6);
    }
}
