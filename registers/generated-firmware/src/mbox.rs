// Licensed under the Apache-2.0 license.
//
// generated by registers_generator with caliptra-ss repo at 4f006115433f926f4e599bc8718a39168f70ce5f
//
//
// Warning: caliptra-ss was dirty:?? src/integration/rtl/html/
//
pub const MBOX_CSR_ADDR: u32 = 0x3002_0000;
pub mod bits {
    //! Types that represent individual registers (bitfields).
    use tock_registers::register_bitfields;
    register_bitfields! {
        u32,
            pub MboxExecute [
                Execute OFFSET(0) NUMBITS(1) [],
            ],
            pub MboxLock [
                Lock OFFSET(0) NUMBITS(1) [],
            ],
            pub MboxStatus [
                /// Indicates the status of mailbox command
                /// [br]Caliptra Access: RW
                /// [br]SOC Access:      RW
                /// [br]TAP Access [in debug/manuf mode]: RW
                Status OFFSET(0) NUMBITS(4) [
                    CmdBusy = 0,
                    DataReady = 1,
                    CmdComplete = 2,
                    CmdFailure = 3,
                ],
                /// Indicates a correctable ECC single-bit error was
                /// detected and corrected while reading dataout.
                /// Auto-clears when mbox_execute field is cleared.
                /// [br]Caliptra Access: RO
                /// [br]SOC Access:      RO
                /// [br]TAP Access [in debug/manuf mode]: RO
                EccSingleError OFFSET(4) NUMBITS(1) [],
                /// Indicates an uncorrectable ECC double-bit error
                /// was detected while reading dataout.
                /// Firmware developers are advised to set the command
                /// status to CMD_FAILURE in response.
                /// Auto-clears when mbox_execute field is cleared.
                /// [br]Caliptra Access: RO
                /// [br]SOC Access:      RO
                /// [br]TAP Access [in debug/manuf mode]: RO
                EccDoubleError OFFSET(5) NUMBITS(1) [],
                /// Indicates the present state of the mailbox FSM
                /// [br]Caliptra Access: RO
                /// [br]SOC Access:      RO
                /// [br]TAP Access [in debug/manuf mode]: RO
                MboxFsmPs OFFSET(6) NUMBITS(3) [
                    MboxIdle = 0,
                    MboxRdyForCmd = 1,
                    MboxRdyForDlen = 3,
                    MboxRdyForData = 2,
                    MboxExecuteUc = 6,
                    MboxExecuteSoc = 4,
                    MboxError = 7,
                ],
                /// Indicates that the current lock was acquired by the SoC
                /// [br]Caliptra Access: RO
                /// [br]SOC Access:      RO
                /// [br]TAP Access [in debug/manuf mode]: RO
                SocHasLock OFFSET(9) NUMBITS(1) [],
                /// Returns the current read pointer for the mailbox
                /// [br]Caliptra Access: RO
                /// [br]SOC Access:      RO
                /// [br]TAP Access [in debug/manuf mode]: RO
                MboxRdptr OFFSET(10) NUMBITS(16) [],
                /// Indicates that the current lock was acquired by the TAP
                /// [br]Caliptra Access: RO
                /// [br]SOC Access:      RO
                /// [br]TAP Access [in debug/manuf mode]: RO
                TapHasLock OFFSET(26) NUMBITS(1) [],
            ],
            pub MboxUnlock [
                Unlock OFFSET(0) NUMBITS(1) [],
            ],
            pub TapMode [
                Enabled OFFSET(0) NUMBITS(1) [],
            ],
    }
}
pub mod regs {
    //! Types that represent registers.
    use tock_registers::register_structs;
    register_structs! {
        pub Mbox {
            (0x0 => pub mbox_lock: tock_registers::registers::ReadOnly<u32, crate::mbox::bits::MboxLock::Register>),
            (0x4 => pub mbox_user: tock_registers::registers::ReadOnly<u32>),
            (0x8 => pub mbox_cmd: tock_registers::registers::ReadWrite<u32>),
            (0xc => pub mbox_dlen: tock_registers::registers::ReadWrite<u32>),
            (0x10 => pub mbox_datain: tock_registers::registers::ReadWrite<u32>),
            (0x14 => pub mbox_dataout: tock_registers::registers::ReadWrite<u32>),
            (0x18 => pub mbox_execute: tock_registers::registers::ReadWrite<u32, crate::mbox::bits::MboxExecute::Register>),
            (0x1c => pub mbox_status: tock_registers::registers::ReadWrite<u32, crate::mbox::bits::MboxStatus::Register>),
            (0x20 => pub mbox_unlock: tock_registers::registers::ReadWrite<u32, crate::mbox::bits::MboxUnlock::Register>),
            (0x24 => pub tap_mode: tock_registers::registers::ReadWrite<u32, crate::mbox::bits::TapMode::Register>),
            (0x28 => @END),
        }
    }
}
