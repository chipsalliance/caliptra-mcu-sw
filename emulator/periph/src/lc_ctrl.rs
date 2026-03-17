/*++

Licensed under the Apache-2.0 license.

File Name:

    lc_ctrl.rs

Abstract:

    OpenTitan Lifecycle controller emulated device.
    Reads the lifecycle state and transition count from OTP fuse data.

--*/

use caliptra_emu_bus::ReadWriteRegister;
use emulator_registers_generated::lc::LcGenerated;
use registers_generated::lc_ctrl;
use tock_registers::interfaces::Readable;

/// Compute the 30-bit LC state mnemonic from a 5-bit state index
/// by replicating it 6 times across the 30-bit field.
fn calc_lc_state_mnemonic(state_5bit: u32) -> u32 {
    let s = state_5bit & 0x1F;
    (s << 25) | (s << 20) | (s << 15) | (s << 10) | (s << 5) | s
}

pub struct LcCtrl {
    status: ReadWriteRegister<u32, lc_ctrl::bits::Status::Register>,
    /// 30-bit lifecycle state mnemonic (5-bit state replicated 6×).
    lc_state: u32,
    /// Lifecycle transition count.
    lc_transition_cnt: u32,
    generated: LcGenerated,
}

impl Default for LcCtrl {
    fn default() -> Self {
        Self::with_state(0, 0)
    }
}

impl LcCtrl {
    /// Create a new lifecycle controller with the given raw state index (0-20)
    /// and transition count. The state index is encoded into the 30-bit mnemonic.
    pub fn with_state(lc_state_index: u32, lc_transition_cnt: u32) -> Self {
        Self {
            status: 0x3.into(), // initialized and ready
            lc_state: calc_lc_state_mnemonic(lc_state_index),
            lc_transition_cnt,
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

    fn read_lc_state(&mut self) -> ReadWriteRegister<u32, lc_ctrl::bits::LcState::Register> {
        ReadWriteRegister::new(self.lc_state)
    }

    fn read_lc_transition_cnt(
        &mut self,
    ) -> ReadWriteRegister<u32, lc_ctrl::bits::LcTransitionCnt::Register> {
        ReadWriteRegister::new(self.lc_transition_cnt)
    }
}
