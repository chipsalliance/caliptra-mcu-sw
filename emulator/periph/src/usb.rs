// Licensed under the Apache-2.0 license.

use caliptra_mcu_emulator_registers_generated::{
    usb_combo::{UsbComboGenerated, UsbComboPeripheral},
    usb_dev0_mem::{UsbDev0MemGenerated, UsbDev0MemPeripheral},
    usb_dev1::{UsbDev1Generated, UsbDev1Peripheral},
    usb_dev1_mem::{UsbDev1MemGenerated, UsbDev1MemPeripheral},
};

pub struct UsbCombo(UsbComboGenerated);

impl UsbCombo {
    pub fn new() -> Self {
        Self(UsbComboGenerated::default())
    }
}

impl Default for UsbCombo {
    fn default() -> Self {
        Self::new()
    }
}

impl UsbComboPeripheral for UsbCombo {
    fn generated(&mut self) -> Option<&mut UsbComboGenerated> {
        Some(&mut self.0)
    }
}

pub struct UsbDev1(UsbDev1Generated);

impl UsbDev1 {
    pub fn new() -> Self {
        Self(UsbDev1Generated::default())
    }
}

impl Default for UsbDev1 {
    fn default() -> Self {
        Self::new()
    }
}

impl UsbDev1Peripheral for UsbDev1 {
    fn generated(&mut self) -> Option<&mut UsbDev1Generated> {
        Some(&mut self.0)
    }
}

pub struct UsbDev0Mem(UsbDev0MemGenerated);

impl UsbDev0Mem {
    pub fn new() -> Self {
        Self(UsbDev0MemGenerated::default())
    }
}

impl Default for UsbDev0Mem {
    fn default() -> Self {
        Self::new()
    }
}

impl UsbDev0MemPeripheral for UsbDev0Mem {
    fn generated(&mut self) -> Option<&mut UsbDev0MemGenerated> {
        Some(&mut self.0)
    }
}

pub struct UsbDev1Mem(UsbDev1MemGenerated);

impl UsbDev1Mem {
    pub fn new() -> Self {
        Self(UsbDev1MemGenerated::default())
    }
}

impl Default for UsbDev1Mem {
    fn default() -> Self {
        Self::new()
    }
}

impl UsbDev1MemPeripheral for UsbDev1Mem {
    fn generated(&mut self) -> Option<&mut UsbDev1MemGenerated> {
        Some(&mut self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use caliptra_emu_bus::Bus;
    use caliptra_emu_types::RvSize;
    use caliptra_mcu_emulator_registers_generated::root_bus::AutoRootBus;

    #[test]
    fn mcu_bus_routes_all_usb_windows() {
        let mut bus = AutoRootBus::new(
            vec![],
            None,
            None,
            Some(Box::new(UsbCombo::new())),
            Some(Box::new(UsbDev1::new())),
            None,
            None,
            None,
            None,
            None,
            None,
            Some(Box::new(UsbDev0Mem::new())),
            Some(Box::new(UsbDev1Mem::new())),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        );

        for address in [0x2000_0008, 0x2000_2008] {
            bus.write(RvSize::Word, address, 0xa5a5_5a5a).unwrap();
            assert_eq!(bus.read(RvSize::Word, address).unwrap(), 0xa5a5_5a00);
        }

        for address in [0x3000_0000, 0x3000_1000] {
            bus.write(RvSize::Word, address, 0xa5a5_5a5a).unwrap();
            assert_eq!(bus.read(RvSize::Word, address).unwrap(), 0xa5a5_5a5a);
        }
    }
}
