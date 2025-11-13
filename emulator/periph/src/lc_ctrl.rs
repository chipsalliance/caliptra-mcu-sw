/*++

Licensed under the Apache-2.0 license.

File Name:

    lc_ctrl.rs

Abstract:

    OpenTitan Lifecycle controller emulated device.

--*/

use caliptra_emu_bus::ReadWriteRegister;
use emulator_registers_generated::lc::LcGenerated;
use registers_generated::lc_ctrl;
use tock_registers::interfaces::Readable;

pub struct LcCtrl {
    status: ReadWriteRegister<u32, lc_ctrl::bits::Status::Register>,
    generated: LcGenerated,
}

impl Default for LcCtrl {
    fn default() -> Self {
        Self::new()
    }
}

impl LcCtrl {
    pub fn new() -> Self {
        Self {
            status: 0x3.into(), // initialized and ready
            generated: LcGenerated::default(),
        }
    }
}

impl emulator_registers_generated::lc::LcPeripheral for LcCtrl {
    fn generated(&mut self) -> Option<&mut LcGenerated> {
        Some(&mut self.generated)
    }

    fn read_status(&mut self) -> ReadWriteRegister<u32, lc_ctrl::bits::Status::Register> {
        ReadWriteRegister::new(self.status.reg.get())
    }
}
