// Licensed under the Apache-2.0 license.
//
// generated by registers_generator with caliptra-rtl repo at 0e43b8e7011c1c8761e114bc949fcad6cf30538e
// , caliptra-ss repo at 9911c2b0e4bac9e4b48f6c2155c86cb116159734
// , and i3c-core repo at d5c715103f529ade0e5d375a53c5692daaa9c54b
//
pub const MCI_CTRL_ADDR: u32 = 0x2005_0000;
pub mod bits {
    //! Types that represent individual registers (bitfields).
    use tock_registers::register_bitfields;
    register_bitfields! {
        u32,
            pub CaliptraAxiId [
                Id OFFSET(0) NUMBITS(1) [],
            ],
            pub CaliptraBootGo [
                /// fixme
                Go OFFSET(0) NUMBITS(1) [],
            ],
            pub Capabilities [
                /// Number of Mailboxes in MCI
                NumMbox OFFSET(0) NUMBITS(4) [],
            ],
            pub CptraWdtStatus [
                /// Timer1 timed out, timer2 enabled
                T1Timeout OFFSET(0) NUMBITS(1) [],
                /// Timer2 timed out
                T2Timeout OFFSET(1) NUMBITS(1) [],
            ],
            pub FlowStatus [
                /// Generic Status
                Status OFFSET(0) NUMBITS(24) [],
                /// DEV ID CSR ready
                Rsvd OFFSET(24) NUMBITS(3) [],
                /// Boot FSM State
                BootFsmPs OFFSET(27) NUMBITS(5) [],
            ],
            pub FwSramExecRegionSize [
                /// Size (in multiples of 4KiB)
                Size OFFSET(0) NUMBITS(1) [],
            ],
            pub HwError [
                Rsvd OFFSET(0) NUMBITS(1) [],
            ],
            pub HwRevId [
                /// Official release version. Bit field encoding is:
                /// [br][lb]15:12[rb] Major version
                /// [br][lb]11: 8[rb] Minor version
                /// [br][lb] 7: 0[rb] Patch version
                McGeneration OFFSET(0) NUMBITS(16) [],
                SocSteppingId OFFSET(16) NUMBITS(16) [],
            ],
            pub ResetAck [
                /// Ack. Writable by MCU. Causes MCU reset to assert (if RESET_REQUEST.req is also set)
                Ack OFFSET(0) NUMBITS(1) [],
            ],
            pub ResetReason [
                /// FW update reset has been executed
                FwUpdReset OFFSET(0) NUMBITS(1) [],
                /// Warm reset has been executed
                WarmReset OFFSET(1) NUMBITS(1) [],
            ],
            pub ResetRequest [
                /// Request. Writable by Caliptra. Causes MCU interrupt to assert.
                Req OFFSET(0) NUMBITS(1) [],
                /// Clear. Writable by Caliptra. On set, this bit autoclears, RESET_REQUEST.req clears, and MCU reset deasserts.
                Clr OFFSET(1) NUMBITS(1) [],
            ],
            pub WdtTimer1Ctrl [
                /// WDT timer1 restart
                Timer1Restart OFFSET(0) NUMBITS(1) [],
            ],
            pub WdtTimer1En [
                /// WDT timer1 enable
                Timer1En OFFSET(0) NUMBITS(1) [],
            ],
            pub WdtTimer2Ctrl [
                /// WDT timer2 restart
                Timer2Restart OFFSET(0) NUMBITS(1) [],
            ],
            pub WdtTimer2En [
                /// WDT timer2 enable
                Timer2En OFFSET(0) NUMBITS(1) [],
            ],
            pub Lock [
                Lock OFFSET(0) NUMBITS(1) [],
            ],
    }
}
pub mod regs {
    //! Types that represent registers.
    use tock_registers::register_structs;
    register_structs! {
        pub MciCtrl {
            (0x0 => pub capabilities: tock_registers::registers::ReadOnly<u32, crate::mci_ctrl::bits::Capabilities::Register>),
            (0x4 => pub hw_rev_id: tock_registers::registers::ReadOnly<u32, crate::mci_ctrl::bits::HwRevId::Register>),
            (0x8 => pub rom_rev_id: tock_registers::registers::ReadWrite<u32>),
            (0xc => pub fw_rev_id: tock_registers::registers::ReadWrite<u32>),
            (0x10 => _reserved0),
            (0x20 => pub boot_status: tock_registers::registers::ReadWrite<u32>),
            (0x24 => pub flow_status: tock_registers::registers::ReadWrite<u32, crate::mci_ctrl::bits::FlowStatus::Register>),
            (0x28 => pub reset_reason: tock_registers::registers::ReadOnly<u32, crate::mci_ctrl::bits::ResetReason::Register>),
            (0x2c => _reserved1),
            (0x40 => pub hw_error_fatal: tock_registers::registers::ReadWrite<u32, crate::mci_ctrl::bits::HwError::Register>),
            (0x44 => pub hw_error_non_fatal: tock_registers::registers::ReadWrite<u32, crate::mci_ctrl::bits::HwError::Register>),
            (0x48 => pub fw_error_fatal: tock_registers::registers::ReadWrite<u32>),
            (0x4c => pub fw_error_non_fatal: tock_registers::registers::ReadWrite<u32>),
            (0x50 => _reserved2),
            (0x80 => pub wdt_timer1_en: tock_registers::registers::ReadWrite<u32, crate::mci_ctrl::bits::WdtTimer1En::Register>),
            (0x84 => pub wdt_timer1_ctrl: tock_registers::registers::ReadWrite<u32, crate::mci_ctrl::bits::WdtTimer1Ctrl::Register>),
            (0x88 => pub wdt_timer1_timeout_period: [tock_registers::registers::ReadWrite<u32>; 2]),
            (0x90 => pub wdt_timer2_en: tock_registers::registers::ReadWrite<u32, crate::mci_ctrl::bits::WdtTimer2En::Register>),
            (0x94 => pub wdt_timer2_ctrl: tock_registers::registers::ReadWrite<u32, crate::mci_ctrl::bits::WdtTimer2Ctrl::Register>),
            (0x98 => pub wdt_timer2_timeout_period: [tock_registers::registers::ReadWrite<u32>; 2]),
            (0xa0 => pub cptra_wdt_status: tock_registers::registers::ReadWrite<u32, crate::mci_ctrl::bits::CptraWdtStatus::Register>),
            (0xa4 => _reserved3),
            (0xb0 => pub wdt_cfg: [tock_registers::registers::ReadWrite<u32>; 2]),
            (0xb8 => _reserved4),
            (0xc0 => pub mcu_timer_config: tock_registers::registers::ReadWrite<u32>),
            (0xc4 => pub mcu_clk_gating_en: tock_registers::registers::ReadWrite<u32>),
            (0xc8 => _reserved5),
            (0x100 => pub reset_request: tock_registers::registers::ReadWrite<u32, crate::mci_ctrl::bits::ResetRequest::Register>),
            (0x104 => pub reset_ack: tock_registers::registers::ReadWrite<u32, crate::mci_ctrl::bits::ResetAck::Register>),
            (0x108 => pub caliptra_boot_go: tock_registers::registers::ReadWrite<u32, crate::mci_ctrl::bits::CaliptraBootGo::Register>),
            (0x10c => pub caliptra_axi_id: tock_registers::registers::ReadOnly<u32, crate::mci_ctrl::bits::CaliptraAxiId::Register>),
            (0x110 => pub fw_sram_exec_region_size: tock_registers::registers::ReadWrite<u32, crate::mci_ctrl::bits::FwSramExecRegionSize::Register>),
            (0x114 => pub runtime_lock: tock_registers::registers::ReadWrite<u32, crate::mci_ctrl::bits::Lock::Register>),
            (0x118 => _reserved6),
            (0x180 => pub mbox0_valid_axi_id: [tock_registers::registers::ReadWrite<u32>; 5]),
            (0x194 => _reserved7),
            (0x1a0 => pub mbox0_valid_axi_id_lock: [tock_registers::registers::ReadWrite<u32, crate::mci_ctrl::bits::Lock::Register>; 5]),
            (0x1b4 => _reserved8),
            (0x1c0 => pub mbox1_valid_axi_id: [tock_registers::registers::ReadWrite<u32>; 5]),
            (0x1d4 => _reserved9),
            (0x1e0 => pub mbox1_valid_axi_id_lock: [tock_registers::registers::ReadWrite<u32, crate::mci_ctrl::bits::Lock::Register>; 5]),
            (0x1f4 => _reserved10),
            (0x400 => pub generic_input_wires: [tock_registers::registers::ReadOnly<u32>; 2]),
            (0x408 => pub generic_output_wires: [tock_registers::registers::ReadWrite<u32>; 2]),
            (0x410 => pub rsvd_rw_reg: [tock_registers::registers::ReadWrite<u32>; 2]),
            (0x418 => pub rsvd_rw_s_reg: [tock_registers::registers::ReadWrite<u32>; 2]),
            (0x420 => pub rsvd_cptra_rw_reg: [tock_registers::registers::ReadWrite<u32>; 2]),
            (0x428 => pub rsvd_cptra_rw_s_reg: [tock_registers::registers::ReadWrite<u32>; 2]),
            (0x430 => pub rsvd_mcu_rw_reg: [tock_registers::registers::ReadWrite<u32>; 2]),
            (0x438 => pub rsvd_mcu_rw_s_reg: [tock_registers::registers::ReadWrite<u32>; 2]),
            (0x440 => pub rsvd_rw_l_reg: [tock_registers::registers::ReadWrite<u32>; 2]),
            (0x448 => pub rsvd_rw_l_reg_lock: [tock_registers::registers::ReadWrite<u32>; 2]),
            (0x450 => pub rsvd_rw_l_s_reg: [tock_registers::registers::ReadWrite<u32>; 2]),
            (0x458 => pub rsvd_rw_l_s_reg_lock: [tock_registers::registers::ReadWrite<u32>; 2]),
            (0x460 => @END),
        }
    }
}
