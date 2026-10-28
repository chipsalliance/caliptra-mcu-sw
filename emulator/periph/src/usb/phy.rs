// Licensed under the Apache-2.0 license

//! USB3320 register subset (datasheet chapter 7), not ULPI pin timing.
//!
//! ULPIDEBUG at Combo offset 0x103c stages address[7:0], write data[15:8],
//! direction[24] and ULPI mode[31]. ACCESS[25] starts a transaction; polling
//! completes it, returns data[23:16] and clears ACCESS. No PHY initialization
//! occurs without firmware transactions, and existing device connection APIs
//! do not require a PHY initialization shortcut or a model-only enable policy.
//!
//! Identity, Function/Interface/OTG Control, USB interrupt controls/status/latch,
//! Debug and Scratch are implemented. Set/clear aliases also read the base
//! register. Function Reset self-clears without resetting ULPI registers;
//! external RESETB restores the array, while MCU reset resets only the gateway.
//! VBUS drives VbusValid/SessValid and enabled edge latches. Other comparators
//! and Debug line state remain zero; analog, low-power and pin timing are absent.
//!
//! Unsupported registers and UTMI vendor-signal accesses log an error and leave
//! ACCESS set for ordinary bounded firmware timeout handling. Host snapshots
//! expose failures without inventing firmware-visible error bits. Fault
//! injection is available only in unit tests or with the `test-hooks` feature.

use super::{Arc, Mutex};

const ACCESS: u32 = 1 << 25;
const WRITE: u32 = 1 << 24;
const MODE: u32 = 1 << 31;
const REGISTER_MASK: u32 = MODE | 0x03ff_ffff;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LpcipUsbPhyError {
    UnsupportedRegister { address: u8, write: bool },
    UnsupportedInterface,
    AccessStalled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LpcipUsbPhySnapshot {
    pub function_control: u8,
    pub interface_control: u8,
    pub otg_control: u8,
    pub scratch: u8,
    pub completed_accesses: u64,
    pub access_pending: bool,
    pub last_error: Option<LpcipUsbPhyError>,
}

/// Observes the same PHY programmed through ULPIDEBUG; never initializes it.
#[derive(Clone, Default)]
pub struct LpcipUsbPhy {
    state: Arc<Mutex<UlpiGateway>>,
}

impl LpcipUsbPhy {
    pub fn snapshot(&self) -> LpcipUsbPhySnapshot {
        let state = self.state.lock().unwrap();
        LpcipUsbPhySnapshot {
            function_control: state.phy.controls[0],
            interface_control: state.phy.controls[1],
            otg_control: state.phy.controls[2],
            scratch: state.phy.controls[5],
            completed_accesses: state.completed_accesses,
            access_pending: state.register & ACCESS != 0,
            last_error: state.last_error,
        }
    }

    /// Simulates external RESETB. MCU/USB bus resets do not reset this array.
    pub fn reset(&self) {
        let mut state = self.state.lock().unwrap();
        let status = state.phy.interrupt_status;
        state.phy = Usb3320 {
            interrupt_status: status,
            ..Usb3320::default()
        };
    }

    /// Injects an unresponsive PHY for bounded firmware timeout tests only.
    #[cfg(any(test, feature = "test-hooks"))]
    pub fn set_access_stalled(&self, stalled: bool) {
        let mut state = self.state.lock().unwrap();
        state.access_stalled = stalled;
        if state.last_error == Some(LpcipUsbPhyError::AccessStalled) {
            state.last_error = None;
        }
    }

    /// Simulates an unexpected PHY part without making identity USB-writable.
    #[cfg(any(test, feature = "test-hooks"))]
    pub fn set_identity_for_test(&self, identity: [u8; 4]) {
        self.state.lock().unwrap().phy.identity = identity;
    }

    pub(super) fn set_vbus(&self, present: bool) {
        let mut state = self.state.lock().unwrap();
        // VBUS is binary here: model VbusValid and SessValid, not comparators.
        let status = if present { 6 } else { 0 };
        let old = state.phy.interrupt_status;
        state.phy.interrupt_latch |=
            (!old & status & state.phy.controls[3]) | (old & !status & state.phy.controls[4]);
        state.phy.interrupt_status = status;
    }

    pub(super) fn reset_gateway(&self) {
        let mut state = self.state.lock().unwrap();
        state.register = 0;
        state.read_data = 0;
        state.completed_accesses = 0;
        state.last_error = None;
    }

    pub(super) fn read(&self) -> u32 {
        let mut state = self.state.lock().unwrap();
        state.advance();
        state.register
    }

    pub(super) fn write(&self, value: u32) {
        let mut state = self.state.lock().unwrap();
        state.register = value & REGISTER_MASK;
        state.last_error = None;
    }

    pub(super) fn poll(&self) {
        self.state.lock().unwrap().advance();
    }
}

#[derive(Default)]
struct UlpiGateway {
    phy: Usb3320,
    register: u32,
    read_data: u8,
    completed_accesses: u64,
    last_error: Option<LpcipUsbPhyError>,
    access_stalled: bool,
}

impl UlpiGateway {
    fn advance(&mut self) {
        if self.register & ACCESS == 0 || self.last_error.is_some() {
            return;
        }
        let result = if self.access_stalled {
            Err(LpcipUsbPhyError::AccessStalled)
        } else if self.register & MODE == 0 {
            Err(LpcipUsbPhyError::UnsupportedInterface)
        } else {
            let address = self.register as u8;
            if self.register & WRITE != 0 {
                self.phy.write(address, (self.register >> 8) as u8)
            } else {
                self.phy.read(address).map(|data| self.read_data = data)
            }
        };
        match result {
            Ok(()) => {
                self.register =
                    (self.register & !(ACCESS | (0xff << 16))) | (u32::from(self.read_data) << 16);
                self.completed_accesses += 1;
            }
            Err(error) => {
                // There is no hardware error bit. Leave ACCESS asserted so
                // firmware's ordinary bounded polling reports a timeout.
                eprintln!("[EMU] USB ULPI access failed: {error:?}");
                self.last_error = Some(error);
            }
        }
    }
}

struct Usb3320 {
    identity: [u8; 4],
    // Function, Interface, OTG, IRQ rising, IRQ falling, Scratch.
    controls: [u8; 6],
    interrupt_status: u8,
    interrupt_latch: u8,
}

impl Default for Usb3320 {
    fn default() -> Self {
        Self {
            identity: [0x24, 4, 7, 0],
            controls: [0x41, 0, 6, 0x1f, 0x1f, 0],
            interrupt_status: 0,
            interrupt_latch: 0,
        }
    }
}

impl Usb3320 {
    fn control(address: u8) -> Option<(usize, u8)> {
        match address {
            4..=6 => Some((0, 4)),
            7..=9 => Some((1, 7)),
            0x0a..=0x0c => Some((2, 0x0a)),
            0x0d..=0x0f => Some((3, 0x0d)),
            0x10..=0x12 => Some((4, 0x10)),
            0x16..=0x18 => Some((5, 0x16)),
            _ => None,
        }
    }

    fn read(&mut self, address: u8) -> Result<u8, LpcipUsbPhyError> {
        if let Some((index, _)) = Self::control(address) {
            return Ok(self.controls[index]);
        }
        match address {
            0..=3 => Ok(self.identity[usize::from(address)]),
            0x13 => Ok(self.interrupt_status),
            0x14 => Ok(std::mem::take(&mut self.interrupt_latch)),
            0x15 => Ok(0), // No pin-level line-state model.
            _ => Err(LpcipUsbPhyError::UnsupportedRegister {
                address,
                write: false,
            }),
        }
    }

    fn write(&mut self, address: u8, value: u8) -> Result<(), LpcipUsbPhyError> {
        if let Some((index, base)) = Self::control(address) {
            let register = &mut self.controls[index];
            match address - base {
                0 => *register = value,
                1 => *register |= value,
                2 => *register &= !value,
                _ => unreachable!(),
            }
            *register &= match index {
                // Function Reset self-clears without resetting ULPI registers.
                0 => 0x5f,
                3 | 4 => 0x1f,
                _ => 0xff,
            };
            return Ok(());
        }
        match address {
            0..=3 | 0x13..=0x15 => Ok(()), // Read-only registers ignore writes.
            _ => Err(LpcipUsbPhyError::UnsupportedRegister {
                address,
                write: true,
            }),
        }
    }
}
