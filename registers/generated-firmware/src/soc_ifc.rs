// Licensed under the Apache-2.0 license.
//
// generated by registers_generator with caliptra-ss repo at a621fff9df7015821eda6f7f73265fef74a01375
//
pub const SOC_IFC_REG_ADDR: u32 = 0x3003_0000;
pub mod bits {
    //! Types that represent individual registers (bitfields).
    use tock_registers::register_bitfields;
    register_bitfields! {
        u32,
            pub CptraBootfsmGo [
                Go OFFSET(0) NUMBITS(1) [],
            ],
            pub CptraClkGatingEn [
                /// Clk gating enable
                ClkGatingEn OFFSET(0) NUMBITS(1) [],
            ],
            pub CptraFlowStatus [
                Status OFFSET(0) NUMBITS(24) [],
                /// DEV ID CSR ready
                IdevidCsrReady OFFSET(24) NUMBITS(1) [],
                /// Boot FSM State
                BootFsmPs OFFSET(25) NUMBITS(3) [],
                /// Indicates Caliptra is ready for Firmware Download
                ReadyForFw OFFSET(28) NUMBITS(1) [],
                /// Indicates Caliptra is ready for RT flows
                ReadyForRuntime OFFSET(29) NUMBITS(1) [],
                /// Indicates Caliptra is ready for Fuses to be programmed.
                /// Read-only to both Caliptra and SOC.
                ReadyForFuses OFFSET(30) NUMBITS(1) [],
                /// Indicates Caliptra is has completed Mailbox Flow.
                MailboxFlowDone OFFSET(31) NUMBITS(1) [],
            ],
            pub CptraFuseWrDone [
                Done OFFSET(0) NUMBITS(1) [],
            ],
            pub CptraHwConfig [
                ItrngEn OFFSET(0) NUMBITS(1) [],
                QspiEn OFFSET(1) NUMBITS(1) [],
                I3cEn OFFSET(2) NUMBITS(1) [],
                UartEn OFFSET(3) NUMBITS(1) [],
                LmsAccEn OFFSET(4) NUMBITS(1) [],
            ],
            pub CptraHwErrorFatal [
                IccmEccUnc OFFSET(0) NUMBITS(1) [],
                DccmEccUnc OFFSET(1) NUMBITS(1) [],
                NmiPin OFFSET(2) NUMBITS(1) [],
                CryptoErr OFFSET(3) NUMBITS(1) [],
            ],
            pub CptraHwErrorNonFatal [
                MboxProtNoLock OFFSET(0) NUMBITS(1) [],
                MboxProtOoo OFFSET(1) NUMBITS(1) [],
                MboxEccUnc OFFSET(2) NUMBITS(1) [],
            ],
            pub CptraHwRevId [
                /// Caliptra official release version. Bit field encoding is:
                /// [br][lb]15:8[rb] Patch version
                /// [br][lb] 7:4[rb] Minor version
                /// [br][lb] 3:0[rb] Major version
                CptraGeneration OFFSET(0) NUMBITS(16) [],
                SocSteppingId OFFSET(16) NUMBITS(16) [],
            ],
            pub CptraResetReason [
                /// FW update reset has been executed
                FwUpdReset OFFSET(0) NUMBITS(1) [],
                /// warm reset has been executed
                WarmReset OFFSET(1) NUMBITS(1) [],
            ],
            pub CptraSecurityState [
                /// Device Lifecycle
                DeviceLifecycle OFFSET(0) NUMBITS(2) [
                    Unprovisioned = 0,
                    Manufacturing = 1,
                    Production = 3,
                ],
                /// Debug Locked
                DebugLocked OFFSET(2) NUMBITS(1) [],
                /// scan mode signal observed at caliptra interface - only for debug mode as its used to flush assets -
                /// when truly in scan mode, everything will be BROKEN for functional reads!
                ScanMode OFFSET(3) NUMBITS(1) [],
                /// Reserved field
                Rsvd OFFSET(4) NUMBITS(28) [],
            ],
            pub CptraTrngCtrl [
                /// Indicates that TRNG Data can be cleared
                /// [br]Caliptra Access: RW
                /// [br]SOC Access:      RO
                Clear OFFSET(0) NUMBITS(1) [],
            ],
            pub CptraWdtStatus [
                /// Timer1 timed out, timer2 enabled
                T1Timeout OFFSET(0) NUMBITS(1) [],
                /// Timer2 timed out
                T2Timeout OFFSET(1) NUMBITS(1) [],
            ],
            pub CptraWdtTimer1Ctrl [
                /// WDT timer1 restart
                Timer1Restart OFFSET(0) NUMBITS(1) [],
            ],
            pub CptraWdtTimer1En [
                /// WDT timer1 enable
                Timer1En OFFSET(0) NUMBITS(1) [],
            ],
            pub CptraWdtTimer2Ctrl [
                /// WDT timer2 restart
                Timer2Restart OFFSET(0) NUMBITS(1) [],
            ],
            pub CptraWdtTimer2En [
                /// WDT timer2 enable
                Timer2En OFFSET(0) NUMBITS(1) [],
            ],
            pub CptraXxxxAxiIdLock [
                Lock OFFSET(0) NUMBITS(1) [],
            ],
            pub CptraItrngEntropyConfig0 [
                LowThreshold OFFSET(0) NUMBITS(16) [],
                HighThreshold OFFSET(16) NUMBITS(16) [],
            ],
            pub CptraItrngEntropyConfig1 [
                RepetitionCount OFFSET(0) NUMBITS(16) [],
                Rsvd OFFSET(16) NUMBITS(16) [],
            ],
            pub ErrorIntrEnT [
                /// Enable bit for Internal Errors
                ErrorInternalEn OFFSET(0) NUMBITS(1) [],
                /// Enable bit for Invalid Device in Pauser field
                ErrorInvDevEn OFFSET(1) NUMBITS(1) [],
                /// Enable bit for Failed Commands (invalid protocol or FW Fail Status)
                ErrorCmdFailEn OFFSET(2) NUMBITS(1) [],
                /// Enable bit for Bad Fuse received from SoC
                ErrorBadFuseEn OFFSET(3) NUMBITS(1) [],
                /// Enable bit for ICCM access blocked by lock
                ErrorIccmBlockedEn OFFSET(4) NUMBITS(1) [],
                /// Enable bit for Mailbox ECC Double-bit Error (uncorrectable)
                ErrorMboxEccUncEn OFFSET(5) NUMBITS(1) [],
                /// Enable bit for WDT Timer1 timeout
                ErrorWdtTimer1TimeoutEn OFFSET(6) NUMBITS(1) [],
                /// Enable bit for WDT Timer2 timeout, applicable if timer2 is enabled as an independent timer
                ErrorWdtTimer2TimeoutEn OFFSET(7) NUMBITS(1) [],
            ],
            pub ErrorIntrT [
                /// Internal Errors status bit
                ErrorInternalSts OFFSET(0) NUMBITS(1) [],
                /// Invalid Device in Pauser field status bit
                ErrorInvDevSts OFFSET(1) NUMBITS(1) [],
                /// Failed Commands status bit (invalid protocol or FW Fail Status)
                ErrorCmdFailSts OFFSET(2) NUMBITS(1) [],
                /// Bad Fuse received from SoC status bit
                ErrorBadFuseSts OFFSET(3) NUMBITS(1) [],
                /// ICCM access blocked by lock status bit
                ErrorIccmBlockedSts OFFSET(4) NUMBITS(1) [],
                /// Mailbox ECC Double-bit Error (uncorrectable) status bit
                ErrorMboxEccUncSts OFFSET(5) NUMBITS(1) [],
                /// WDT Timer1 timeout status bit
                ErrorWdtTimer1TimeoutSts OFFSET(6) NUMBITS(1) [],
                /// WDT Timer2 timeout status bit
                ErrorWdtTimer2TimeoutSts OFFSET(7) NUMBITS(1) [],
            ],
            pub ErrorIntrTrigT [
                /// Internal Errors trigger bit
                ErrorInternalTrig OFFSET(0) NUMBITS(1) [],
                /// Invalid Device in Pauser field trigger bit
                ErrorInvDevTrig OFFSET(1) NUMBITS(1) [],
                /// Failed Commands trigger bit
                ErrorCmdFailTrig OFFSET(2) NUMBITS(1) [],
                /// Bad Fuse received from SoC trigger bit
                ErrorBadFuseTrig OFFSET(3) NUMBITS(1) [],
                /// ICCM access blocked by lock trigger bit
                ErrorIccmBlockedTrig OFFSET(4) NUMBITS(1) [],
                /// Mailbox ECC Double-bit Error (uncorrectable) trigger bit
                ErrorMboxEccUncTrig OFFSET(5) NUMBITS(1) [],
                /// WDT Timer1 timeout trigger bit
                ErrorWdtTimer1TimeoutTrig OFFSET(6) NUMBITS(1) [],
                /// WDT Timer2 timeout trigger bit
                ErrorWdtTimer2TimeoutTrig OFFSET(7) NUMBITS(1) [],
            ],
            pub FuseAntiRollbackDisable [
                Dis OFFSET(0) NUMBITS(1) [],
            ],
            pub FuseKeyManifestPkHashMask [
                Mask OFFSET(0) NUMBITS(4) [],
            ],
            pub FuseLifeCycle [
                LifeCycle OFFSET(0) NUMBITS(2) [],
            ],
            pub FuseLmsVerify [
                LmsVerify OFFSET(0) NUMBITS(1) [],
            ],
            pub FuseSocSteppingId [
                SocSteppingId OFFSET(0) NUMBITS(16) [],
            ],
            pub GlobalIntrEnT [
                /// Global enable bit for all events of type 'Error'
                ErrorEn OFFSET(0) NUMBITS(1) [],
                /// Global enable bit for all events of type 'Notification'
                NotifEn OFFSET(1) NUMBITS(1) [],
            ],
            pub GlobalIntrT [
                /// Interrupt Event Aggregation status bit
                AggSts OFFSET(0) NUMBITS(1) [],
            ],
            pub InternalFwUpdateReset [
                /// FW Update reset to reset core
                CoreRst OFFSET(0) NUMBITS(1) [],
            ],
            pub InternalFwUpdateResetWaitCycles [
                /// FW Update reset wait cycles
                WaitCycles OFFSET(0) NUMBITS(8) [],
            ],
            pub InternalHwErrorFatalMask [
                MaskIccmEccUnc OFFSET(0) NUMBITS(1) [],
                MaskDccmEccUnc OFFSET(1) NUMBITS(1) [],
                MaskNmiPin OFFSET(2) NUMBITS(1) [],
                MaskCryptoErr OFFSET(3) NUMBITS(1) [],
            ],
            pub InternalHwErrorNonFatalMask [
                MaskMboxProtNoLock OFFSET(0) NUMBITS(1) [],
                MaskMboxProtOoo OFFSET(1) NUMBITS(1) [],
                MaskMboxEccUnc OFFSET(2) NUMBITS(1) [],
            ],
            pub InternalIccmLock [
                /// Lock bit gates writes to ICCM. Write 1 to set - cannot be cleared by SW.
                Lock OFFSET(0) NUMBITS(1) [],
            ],
            pub IntrCountIncrT [
                /// Pulse mirrors interrupt event occurrence
                Pulse OFFSET(0) NUMBITS(1) [],
            ],
            pub NotifIntrEnT [
                /// Enable bit for Command Available
                NotifCmdAvailEn OFFSET(0) NUMBITS(1) [],
                /// Enable bit for Mailbox ECC Single-bit Error (correctable)
                NotifMboxEccCorEn OFFSET(1) NUMBITS(1) [],
                /// Enable bit for Security State, Debug Locked transition
                NotifDebugLockedEn OFFSET(2) NUMBITS(1) [],
                /// Enable bit for Scan mode
                NotifScanModeEn OFFSET(3) NUMBITS(1) [],
                /// Enable bit for SoC requested the mailbox while locked
                NotifSocReqLockEn OFFSET(4) NUMBITS(1) [],
                /// Enable bit for Generic Input Wires Toggle
                NotifGenInToggleEn OFFSET(5) NUMBITS(1) [],
            ],
            pub NotifIntrT [
                /// Command Available status bit
                NotifCmdAvailSts OFFSET(0) NUMBITS(1) [],
                /// Mailbox ECC Single-bit Error (correctable) status bit
                NotifMboxEccCorSts OFFSET(1) NUMBITS(1) [],
                /// Security State, Debug Locked transition status bit
                NotifDebugLockedSts OFFSET(2) NUMBITS(1) [],
                /// Scan mode status bit
                NotifScanModeSts OFFSET(3) NUMBITS(1) [],
                /// SoC requested the mailbox while locked status bit
                NotifSocReqLockSts OFFSET(4) NUMBITS(1) [],
                /// Generic Input Wires Toggle status bit
                NotifGenInToggleSts OFFSET(5) NUMBITS(1) [],
            ],
            pub NotifIntrTrigT [
                /// Command Available trigger bit
                NotifCmdAvailTrig OFFSET(0) NUMBITS(1) [],
                /// Mailbox ECC Single-bit Error (correctable) trigger bit
                NotifMboxEccCorTrig OFFSET(1) NUMBITS(1) [],
                /// Security State, Debug Locked transition trigger bit
                NotifDebugLockedTrig OFFSET(2) NUMBITS(1) [],
                /// Scan mode trigger bit
                NotifScanModeTrig OFFSET(3) NUMBITS(1) [],
                /// SoC requested the mailbox while locked trigger bit
                NotifSocReqLockTrig OFFSET(4) NUMBITS(1) [],
                /// Generic Input Wires Toggle trigger bit
                NotifGenInToggleTrig OFFSET(5) NUMBITS(1) [],
            ],
    }
}
pub mod regs {
    //! Types that represent registers.
    use tock_registers::register_structs;
    register_structs! {
        pub SocIfc {
            (0x0 => pub cptra_hw_error_fatal: tock_registers::registers::ReadWrite<u32, crate::soc_ifc::bits::CptraHwErrorFatal::Register>),
            (0x4 => pub cptra_hw_error_non_fatal: tock_registers::registers::ReadWrite<u32, crate::soc_ifc::bits::CptraHwErrorNonFatal::Register>),
            (0x8 => pub cptra_fw_error_fatal: tock_registers::registers::ReadWrite<u32>),
            (0xc => pub cptra_fw_error_non_fatal: tock_registers::registers::ReadWrite<u32>),
            (0x10 => pub cptra_hw_error_enc: tock_registers::registers::ReadWrite<u32>),
            (0x14 => pub cptra_fw_error_enc: tock_registers::registers::ReadWrite<u32>),
            (0x18 => pub cptra_fw_extended_error_info: [tock_registers::registers::ReadWrite<u32>; 8]),
            (0x38 => pub cptra_boot_status: tock_registers::registers::ReadWrite<u32>),
            (0x3c => pub cptra_flow_status: tock_registers::registers::ReadWrite<u32, crate::soc_ifc::bits::CptraFlowStatus::Register>),
            (0x40 => pub cptra_reset_reason: tock_registers::registers::ReadOnly<u32, crate::soc_ifc::bits::CptraResetReason::Register>),
            (0x44 => pub cptra_security_state: tock_registers::registers::ReadOnly<u32, crate::soc_ifc::bits::CptraSecurityState::Register>),
            (0x48 => pub cptra_mbox_valid_axi_id: [tock_registers::registers::ReadWrite<u32>; 5]),
            (0x5c => pub cptra_mbox_axi_id_lock: [tock_registers::registers::ReadWrite<u32, crate::soc_ifc::bits::CptraXxxxAxiIdLock::Register>; 5]),
            (0x70 => pub cptra_trng_valid_axi_id: tock_registers::registers::ReadWrite<u32>),
            (0x74 => pub cptra_trng_axi_id_lock: tock_registers::registers::ReadWrite<u32, crate::soc_ifc::bits::CptraXxxxAxiIdLock::Register>),
            (0x78 => _reserved0),
            (0xa8 => pub cptra_trng_ctrl: tock_registers::registers::ReadWrite<u32, crate::soc_ifc::bits::CptraTrngCtrl::Register>),
            (0xac => _reserved1),
            (0xb0 => pub cptra_fuse_wr_done: tock_registers::registers::ReadWrite<u32, crate::soc_ifc::bits::CptraFuseWrDone::Register>),
            (0xb4 => pub cptra_timer_config: tock_registers::registers::ReadWrite<u32>),
            (0xb8 => pub cptra_bootfsm_go: tock_registers::registers::ReadWrite<u32, crate::soc_ifc::bits::CptraBootfsmGo::Register>),
            (0xbc => pub cptra_dbg_manuf_service_reg: tock_registers::registers::ReadWrite<u32>),
            (0xc0 => pub cptra_clk_gating_en: tock_registers::registers::ReadWrite<u32, crate::soc_ifc::bits::CptraClkGatingEn::Register>),
            (0xc4 => pub cptra_generic_input_wires: [tock_registers::registers::ReadOnly<u32>; 2]),
            (0xcc => pub cptra_generic_output_wires: [tock_registers::registers::ReadWrite<u32>; 2]),
            (0xd4 => pub cptra_hw_rev_id: tock_registers::registers::ReadOnly<u32, crate::soc_ifc::bits::CptraHwRevId::Register>),
            (0xd8 => pub cptra_fw_rev_id: [tock_registers::registers::ReadWrite<u32>; 2]),
            (0xe0 => pub cptra_hw_config: tock_registers::registers::ReadOnly<u32, crate::soc_ifc::bits::CptraHwConfig::Register>),
            (0xe4 => pub cptra_wdt_timer1_en: tock_registers::registers::ReadWrite<u32, crate::soc_ifc::bits::CptraWdtTimer1En::Register>),
            (0xe8 => pub cptra_wdt_timer1_ctrl: tock_registers::registers::ReadWrite<u32, crate::soc_ifc::bits::CptraWdtTimer1Ctrl::Register>),
            (0xec => pub cptra_wdt_timer1_timeout_period: [tock_registers::registers::ReadWrite<u32>; 2]),
            (0xf4 => pub cptra_wdt_timer2_en: tock_registers::registers::ReadWrite<u32, crate::soc_ifc::bits::CptraWdtTimer2En::Register>),
            (0xf8 => pub cptra_wdt_timer2_ctrl: tock_registers::registers::ReadWrite<u32, crate::soc_ifc::bits::CptraWdtTimer2Ctrl::Register>),
            (0xfc => pub cptra_wdt_timer2_timeout_period: [tock_registers::registers::ReadWrite<u32>; 2]),
            (0x104 => pub cptra_wdt_status: tock_registers::registers::ReadWrite<u32, crate::soc_ifc::bits::CptraWdtStatus::Register>),
            (0x108 => pub cptra_fuse_valid_axi_id: tock_registers::registers::ReadWrite<u32>),
            (0x10c => pub cptra_fuse_axi_id_lock: tock_registers::registers::ReadWrite<u32, crate::soc_ifc::bits::CptraXxxxAxiIdLock::Register>),
            (0x110 => pub cptra_wdt_cfg: [tock_registers::registers::ReadWrite<u32>; 2]),
            (0x118 => pub cptra_i_trng_entropy_config_0: tock_registers::registers::ReadWrite<u32, crate::soc_ifc::bits::CptraItrngEntropyConfig0::Register>),
            (0x11c => pub cptra_i_trng_entropy_config_1: tock_registers::registers::ReadWrite<u32, crate::soc_ifc::bits::CptraItrngEntropyConfig1::Register>),
            (0x120 => pub cptra_rsvd_reg: [tock_registers::registers::ReadWrite<u32>; 2]),
            (0x128 => _reserved2),
            (0x200 => pub fuse_uds_seed: [tock_registers::registers::WriteOnly<u32>; 12]),
            (0x230 => pub fuse_field_entropy: [tock_registers::registers::WriteOnly<u32>; 8]),
            (0x250 => pub fuse_key_manifest_pk_hash: [tock_registers::registers::ReadWrite<u32>; 12]),
            (0x280 => pub fuse_key_manifest_pk_hash_mask: tock_registers::registers::ReadWrite<u32, crate::soc_ifc::bits::FuseKeyManifestPkHashMask::Register>),
            (0x284 => pub fuse_owner_pk_hash: [tock_registers::registers::ReadWrite<u32>; 12]),
            (0x2b4 => pub fuse_fmc_key_manifest_svn: tock_registers::registers::ReadWrite<u32>),
            (0x2b8 => pub fuse_runtime_svn: [tock_registers::registers::ReadWrite<u32>; 4]),
            (0x2c8 => pub fuse_anti_rollback_disable: tock_registers::registers::ReadWrite<u32, crate::soc_ifc::bits::FuseAntiRollbackDisable::Register>),
            (0x2cc => pub fuse_idevid_cert_attr: [tock_registers::registers::ReadWrite<u32>; 24]),
            (0x32c => pub fuse_idevid_manuf_hsm_id: [tock_registers::registers::ReadWrite<u32>; 4]),
            (0x33c => pub fuse_life_cycle: tock_registers::registers::ReadWrite<u32, crate::soc_ifc::bits::FuseLifeCycle::Register>),
            (0x340 => pub fuse_lms_verify: tock_registers::registers::ReadWrite<u32, crate::soc_ifc::bits::FuseLmsVerify::Register>),
            (0x344 => pub fuse_lms_revocation: tock_registers::registers::ReadWrite<u32>),
            (0x348 => pub fuse_soc_stepping_id: tock_registers::registers::ReadWrite<u32, crate::soc_ifc::bits::FuseSocSteppingId::Register>),
            (0x34c => _reserved3),
            (0x600 => pub internal_obf_key: [tock_registers::registers::WriteOnly<u32>; 8]),
            (0x620 => pub internal_iccm_lock: tock_registers::registers::ReadWrite<u32, crate::soc_ifc::bits::InternalIccmLock::Register>),
            (0x624 => pub internal_fw_update_reset: tock_registers::registers::ReadWrite<u32, crate::soc_ifc::bits::InternalFwUpdateReset::Register>),
            (0x628 => pub internal_fw_update_reset_wait_cycles: tock_registers::registers::ReadWrite<u32, crate::soc_ifc::bits::InternalFwUpdateResetWaitCycles::Register>),
            (0x62c => pub internal_nmi_vector: tock_registers::registers::ReadWrite<u32>),
            (0x630 => pub internal_hw_error_fatal_mask: tock_registers::registers::ReadWrite<u32, crate::soc_ifc::bits::InternalHwErrorFatalMask::Register>),
            (0x634 => pub internal_hw_error_non_fatal_mask: tock_registers::registers::ReadWrite<u32, crate::soc_ifc::bits::InternalHwErrorNonFatalMask::Register>),
            (0x638 => pub internal_fw_error_fatal_mask: tock_registers::registers::ReadWrite<u32>),
            (0x63c => pub internal_fw_error_non_fatal_mask: tock_registers::registers::ReadWrite<u32>),
            (0x640 => pub internal_rv_mtime_l: tock_registers::registers::ReadWrite<u32>),
            (0x644 => pub internal_rv_mtime_h: tock_registers::registers::ReadWrite<u32>),
            (0x648 => pub internal_rv_mtimecmp_l: tock_registers::registers::ReadWrite<u32>),
            (0x64c => pub internal_rv_mtimecmp_h: tock_registers::registers::ReadWrite<u32>),
            (0x650 => _reserved4),
            (0x800 => pub global_intr_en_r: tock_registers::registers::ReadWrite<u32, crate::soc_ifc::bits::GlobalIntrEnT::Register>),
            (0x804 => pub error_intr_en_r: tock_registers::registers::ReadWrite<u32, crate::soc_ifc::bits::ErrorIntrEnT::Register>),
            (0x808 => pub notif_intr_en_r: tock_registers::registers::ReadWrite<u32, crate::soc_ifc::bits::NotifIntrEnT::Register>),
            (0x80c => pub error_global_intr_r: tock_registers::registers::ReadOnly<u32, crate::soc_ifc::bits::GlobalIntrT::Register>),
            (0x810 => pub notif_global_intr_r: tock_registers::registers::ReadOnly<u32, crate::soc_ifc::bits::GlobalIntrT::Register>),
            (0x814 => pub error_internal_intr_r: tock_registers::registers::ReadWrite<u32, crate::soc_ifc::bits::ErrorIntrT::Register>),
            (0x818 => pub notif_internal_intr_r: tock_registers::registers::ReadWrite<u32, crate::soc_ifc::bits::NotifIntrT::Register>),
            (0x81c => pub error_intr_trig_r: tock_registers::registers::ReadWrite<u32, crate::soc_ifc::bits::ErrorIntrTrigT::Register>),
            (0x820 => pub notif_intr_trig_r: tock_registers::registers::ReadWrite<u32, crate::soc_ifc::bits::NotifIntrTrigT::Register>),
            (0x824 => _reserved5),
            (0x900 => pub error_internal_intr_count_r: tock_registers::registers::ReadWrite<u32>),
            (0x904 => pub error_inv_dev_intr_count_r: tock_registers::registers::ReadWrite<u32>),
            (0x908 => pub error_cmd_fail_intr_count_r: tock_registers::registers::ReadWrite<u32>),
            (0x90c => pub error_bad_fuse_intr_count_r: tock_registers::registers::ReadWrite<u32>),
            (0x910 => pub error_iccm_blocked_intr_count_r: tock_registers::registers::ReadWrite<u32>),
            (0x914 => pub error_mbox_ecc_unc_intr_count_r: tock_registers::registers::ReadWrite<u32>),
            (0x918 => pub error_wdt_timer1_timeout_intr_count_r: tock_registers::registers::ReadWrite<u32>),
            (0x91c => pub error_wdt_timer2_timeout_intr_count_r: tock_registers::registers::ReadWrite<u32>),
            (0x920 => _reserved6),
            (0x980 => pub notif_cmd_avail_intr_count_r: tock_registers::registers::ReadWrite<u32>),
            (0x984 => pub notif_mbox_ecc_cor_intr_count_r: tock_registers::registers::ReadWrite<u32>),
            (0x988 => pub notif_debug_locked_intr_count_r: tock_registers::registers::ReadWrite<u32>),
            (0x98c => pub notif_scan_mode_intr_count_r: tock_registers::registers::ReadWrite<u32>),
            (0x990 => pub notif_soc_req_lock_intr_count_r: tock_registers::registers::ReadWrite<u32>),
            (0x994 => pub notif_gen_in_toggle_intr_count_r: tock_registers::registers::ReadWrite<u32>),
            (0x998 => _reserved7),
            (0xa00 => pub error_internal_intr_count_incr_r: tock_registers::registers::ReadOnly<u32, crate::soc_ifc::bits::IntrCountIncrT::Register>),
            (0xa04 => pub error_inv_dev_intr_count_incr_r: tock_registers::registers::ReadOnly<u32, crate::soc_ifc::bits::IntrCountIncrT::Register>),
            (0xa08 => pub error_cmd_fail_intr_count_incr_r: tock_registers::registers::ReadOnly<u32, crate::soc_ifc::bits::IntrCountIncrT::Register>),
            (0xa0c => pub error_bad_fuse_intr_count_incr_r: tock_registers::registers::ReadOnly<u32, crate::soc_ifc::bits::IntrCountIncrT::Register>),
            (0xa10 => pub error_iccm_blocked_intr_count_incr_r: tock_registers::registers::ReadOnly<u32, crate::soc_ifc::bits::IntrCountIncrT::Register>),
            (0xa14 => pub error_mbox_ecc_unc_intr_count_incr_r: tock_registers::registers::ReadOnly<u32, crate::soc_ifc::bits::IntrCountIncrT::Register>),
            (0xa18 => pub error_wdt_timer1_timeout_intr_count_incr_r: tock_registers::registers::ReadOnly<u32, crate::soc_ifc::bits::IntrCountIncrT::Register>),
            (0xa1c => pub error_wdt_timer2_timeout_intr_count_incr_r: tock_registers::registers::ReadOnly<u32, crate::soc_ifc::bits::IntrCountIncrT::Register>),
            (0xa20 => pub notif_cmd_avail_intr_count_incr_r: tock_registers::registers::ReadOnly<u32, crate::soc_ifc::bits::IntrCountIncrT::Register>),
            (0xa24 => pub notif_mbox_ecc_cor_intr_count_incr_r: tock_registers::registers::ReadOnly<u32, crate::soc_ifc::bits::IntrCountIncrT::Register>),
            (0xa28 => pub notif_debug_locked_intr_count_incr_r: tock_registers::registers::ReadOnly<u32, crate::soc_ifc::bits::IntrCountIncrT::Register>),
            (0xa2c => pub notif_scan_mode_intr_count_incr_r: tock_registers::registers::ReadOnly<u32, crate::soc_ifc::bits::IntrCountIncrT::Register>),
            (0xa30 => pub notif_soc_req_lock_intr_count_incr_r: tock_registers::registers::ReadOnly<u32, crate::soc_ifc::bits::IntrCountIncrT::Register>),
            (0xa34 => pub notif_gen_in_toggle_intr_count_incr_r: tock_registers::registers::ReadOnly<u32, crate::soc_ifc::bits::IntrCountIncrT::Register>),
            (0xa38 => @END),
        }
    }
}
