// Licensed under the Apache-2.0 license.
//
// generated by registers_generator with caliptra-rtl repo at 0e43b8e7011c1c8761e114bc949fcad6cf30538e
// , caliptra-ss repo at 9911c2b0e4bac9e4b48f6c2155c86cb116159734
// , and i3c-core repo at d5c715103f529ade0e5d375a53c5692daaa9c54b
//
pub mod bits {
    //! Types that represent individual registers (bitfields).
    use tock_registers::register_bitfields;
    register_bitfields! {
        u32,
            CaliptraAxiId [
                Id OFFSET(0) NUMBITS(1) [],
            ],
            HwError [
                Rsvd OFFSET(0) NUMBITS(1) [],
            ],
            ResetAck [
                /// Ack. Writable by MCU. Causes MCU reset to assert (if RESET_REQUEST.req is also set)
                Ack OFFSET(0) NUMBITS(1) [],
            ],
            WdtTimer2Ctrl [
                /// WDT timer2 restart
                Timer2Restart OFFSET(0) NUMBITS(1) [],
            ],
            FwSramExecRegionSize [
                /// Size (in multiples of 4KiB)
                Size OFFSET(0) NUMBITS(1) [],
            ],
            WdtTimer1Ctrl [
                /// WDT timer1 restart
                Timer1Restart OFFSET(0) NUMBITS(1) [],
            ],
            WdtTimer2En [
                /// WDT timer2 enable
                Timer2En OFFSET(0) NUMBITS(1) [],
            ],
            Lock [
                Lock OFFSET(0) NUMBITS(1) [],
            ],
            CptraWdtStatus [
                /// Timer1 timed out, timer2 enabled
                T1Timeout OFFSET(0) NUMBITS(1) [],
                /// Timer2 timed out
                T2Timeout OFFSET(1) NUMBITS(1) [],
            ],
            FlowStatus [
                /// Generic Status
                Status OFFSET(0) NUMBITS(24) [],
                /// DEV ID CSR ready
                Rsvd OFFSET(24) NUMBITS(3) [],
                /// Boot FSM State
                BootFsmPs OFFSET(27) NUMBITS(5) [],
            ],
            Capabilities [
                /// Number of Mailboxes in MCI
                NumMbox OFFSET(0) NUMBITS(4) [],
            ],
            CaliptraBootGo [
                /// fixme
                Go OFFSET(0) NUMBITS(1) [],
            ],
            WdtTimer1En [
                /// WDT timer1 enable
                Timer1En OFFSET(0) NUMBITS(1) [],
            ],
            ResetRequest [
                /// Request. Writable by Caliptra. Causes MCU interrupt to assert.
                Req OFFSET(0) NUMBITS(1) [],
                /// Clear. Writable by Caliptra. On set, this bit autoclears, RESET_REQUEST.req clears, and MCU reset deasserts.
                Clr OFFSET(1) NUMBITS(1) [],
            ],
            HwRevId [
                /// Official release version. Bit field encoding is:
                /// [br][lb]15:12[rb] Major version
                /// [br][lb]11: 8[rb] Minor version
                /// [br][lb] 7: 0[rb] Patch version
                McGeneration OFFSET(0) NUMBITS(16) [],
                SocSteppingId OFFSET(16) NUMBITS(16) [],
            ],
            ResetReason [
                /// FW update reset has been executed
                FwUpdReset OFFSET(0) NUMBITS(1) [],
                /// Warm reset has been executed
                WarmReset OFFSET(1) NUMBITS(1) [],
            ],
    }
}
