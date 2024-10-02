/*++

Licensed under the Apache-2.0 license.

File Name:

    jal.rs

Abstract:

    File contains implementation of Jump and Link instructions.

--*/

use crate::cpu::Cpu;
use crate::types::{RvInstr32J, RvInstr32Opcode};
use emulator_bus::Bus;
use emulator_types::RvException;

impl<TBus: Bus> Cpu<TBus> {
    /// Execute `jal` Instructions
    ///
    /// # Arguments
    ///
    /// * `instr_tracer` - Instruction tracer
    ///
    /// # Error
    ///
    /// * `RvException` - Exception encountered during instruction execution
    pub fn exec_jal_instr(&mut self, instr: u32) -> Result<(), RvException> {
        // Decode the instruction
        let instr = RvInstr32J(instr);
        assert_eq!(instr.opcode(), RvInstr32Opcode::Jal);

        // Calculate the new program counter
        let next_pc = self.read_pc().wrapping_add(instr.imm());

        // Calculate the return address
        let lr = self.next_pc();

        // Update the registers
        self.set_next_pc(next_pc);
        self.write_xreg(instr.rd(), lr)
    }
}

#[cfg(test)]
mod tests {
    use crate::instr::test_encoder::tests::{addi, jal, nop};
    use crate::xreg_file::XReg;
    use crate::{isa_test, text};

    #[test]
    fn test_jal_2() {
        isa_test!(
            0x0000 => text![
                jal(XReg::X1, 0x0008);
                nop();
                addi(XReg::X2, XReg::X0, 1);
                nop();
            ],
            0x1000 => vec![0],
            {
            },
            {
                XReg::X2 = 0x0001;
                XReg::X1 = 0x0004;
            }
        );
    }
}
