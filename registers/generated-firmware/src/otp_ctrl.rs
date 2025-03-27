// Licensed under the Apache-2.0 license.
//
// generated by registers_generator with caliptra-ss repo at 4f006115433f926f4e599bc8718a39168f70ce5f
//
//
// Warning: caliptra-ss was dirty:?? src/integration/rtl/html/
//
pub const OTP_CTRL_ADDR: u32 = 0x7000_0000;
pub mod bits {
    //! Types that represent individual registers (bitfields).
    use tock_registers::register_bitfields;
    register_bitfields! {
        u32,
            pub AlertTest [
                /// Write 1 to trigger one alert event of this kind.
                FatalMacrError OFFSET(0) NUMBITS(1) [],
                /// Write 1 to trigger one alert event of this kind.
                FatalCheckError OFFSET(1) NUMBITS(1) [],
                /// Write 1 to trigger one alert event of this kind.
                FatalBusIntegError OFFSET(2) NUMBITS(1) [],
                /// Write 1 to trigger one alert event of this kind.
                FatalPrimOtpAlert OFFSET(3) NUMBITS(1) [],
                /// Write 1 to trigger one alert event of this kind.
                RecovPrimOtpAlert OFFSET(4) NUMBITS(1) [],
            ],
            pub CheckRegwen [
                /// When cleared to 0, !!INTEGRITY_CHECK_PERIOD and !!CONSISTENCY_CHECK_PERIOD registers cannot be written anymore.Write 0 to clear this bit.
                Regwen OFFSET(0) NUMBITS(1) [],
            ],
            pub CheckTrigger [
                /// Writing 1 to this bit triggers an integrity check. SW should monitor !!OTP_STATUS.CHECK_PENDING
                /// and wait until the check has been completed. If there are any errors, those will be flagged
                /// in the !!OTP_STATUS and !!ERR_CODE registers, and via the interrupts and alerts.
                Integrity OFFSET(0) NUMBITS(1) [],
                /// Writing 1 to this bit triggers a consistency check. SW should monitor !!OTP_STATUS.CHECK_PENDINGand wait until the check has been completed. If there are any errors, those will be flaggedin the !!OTP_STATUS and !!ERR_CODE registers, and via interrupts and alerts.
                Consistency OFFSET(1) NUMBITS(1) [],
            ],
            pub CheckTriggerRegwen [
                /// When cleared to 0, the !!CHECK_TRIGGER register cannot be written anymore.
                /// Write 0 to clear this bit.
                Regwen OFFSET(0) NUMBITS(1) [],
            ],
            pub Csr0 [
                Field0 OFFSET(0) NUMBITS(1) [],
                Field1 OFFSET(1) NUMBITS(1) [],
                Field2 OFFSET(2) NUMBITS(1) [],
                Field3 OFFSET(4) NUMBITS(10) [],
                Field4 OFFSET(16) NUMBITS(11) [],
            ],
            pub Csr1 [
                Field0 OFFSET(0) NUMBITS(7) [],
                Field1 OFFSET(7) NUMBITS(1) [],
                Field2 OFFSET(8) NUMBITS(7) [],
                Field3 OFFSET(15) NUMBITS(1) [],
                Field4 OFFSET(16) NUMBITS(16) [],
            ],
            pub Csr2 [
                Field0 OFFSET(0) NUMBITS(1) [],
            ],
            pub Csr3 [
                Field0 OFFSET(0) NUMBITS(3) [],
                Field1 OFFSET(4) NUMBITS(10) [],
                Field2 OFFSET(16) NUMBITS(1) [],
                Field3 OFFSET(17) NUMBITS(1) [],
                Field4 OFFSET(18) NUMBITS(1) [],
                Field5 OFFSET(19) NUMBITS(1) [],
                Field6 OFFSET(20) NUMBITS(1) [],
                Field7 OFFSET(21) NUMBITS(1) [],
                Field8 OFFSET(22) NUMBITS(1) [],
            ],
            pub Csr4 [
                Field0 OFFSET(0) NUMBITS(10) [],
                Field1 OFFSET(12) NUMBITS(1) [],
                Field2 OFFSET(13) NUMBITS(1) [],
                Field3 OFFSET(14) NUMBITS(1) [],
            ],
            pub Csr5 [
                Field0 OFFSET(0) NUMBITS(6) [],
                Field1 OFFSET(6) NUMBITS(2) [],
                Field2 OFFSET(8) NUMBITS(1) [],
                Field3 OFFSET(9) NUMBITS(3) [],
                Field4 OFFSET(12) NUMBITS(1) [],
                Field5 OFFSET(13) NUMBITS(1) [],
                Field6 OFFSET(16) NUMBITS(16) [],
            ],
            pub Csr6 [
                Field0 OFFSET(0) NUMBITS(10) [],
                Field1 OFFSET(11) NUMBITS(1) [],
                Field2 OFFSET(12) NUMBITS(1) [],
                Field3 OFFSET(16) NUMBITS(16) [],
            ],
            pub Csr7 [
                Field0 OFFSET(0) NUMBITS(6) [],
                Field1 OFFSET(8) NUMBITS(3) [],
                Field2 OFFSET(14) NUMBITS(1) [],
                Field3 OFFSET(15) NUMBITS(1) [],
            ],
            pub DirectAccessAddress [
                /// This is the address for the OTP word to be read or written thrughthe direct access interface. Note that the address is aligned to the access sizeinternally, hence bits 1:0 are ignored for 32bit accesses, and bits 2:0 are ignoredfor 64bit accesses.For the digest calculation command, set this register to the partition base offset.
                Address OFFSET(0) NUMBITS(12) [],
            ],
            pub DirectAccessCmd [
                /// Initiates a readout sequence that reads the location specifiedby !!DIRECT_ACCESS_ADDRESS. The command places the data read into!!DIRECT_ACCESS_RDATA_0 and !!DIRECT_ACCESS_RDATA_1 (for 64bit partitions).
                Rd OFFSET(0) NUMBITS(1) [],
                /// Initiates a prgramming sequence that writes the data in !!DIRECT_ACCESS_WDATA_0and !!DIRECT_ACCESS_WDATA_1 (for 64bit partitions) to the location specified by!!DIRECT_ACCESS_ADDRESS.
                Wr OFFSET(1) NUMBITS(1) [],
                /// Initiates the digest calculation and locking sequence for the partition specified by!!DIRECT_ACCESS_ADDRESS.
                Digest OFFSET(2) NUMBITS(1) [],
            ],
            pub DirectAccessRegwen [
                /// This bit contrls whether the DAI registers can be written.Write 0 to it in order to clear the bit.Note that the hardware also modulates this bit and sets it to 0 temporarilyduring an OTP operation such that the corresponding address and data registerscannot be modified while an operation is pending. The !!DAI_IDLE status bitwill also be set to 0 in such a case.
                Regwen OFFSET(0) NUMBITS(1) [],
            ],
            pub InterruptState [
                /// A direct access command or digest calculation operation has completed.
                OtpOperationDone OFFSET(0) NUMBITS(1) [],
                /// An error has occurred in the OTP contrller. Check the !!ERR_CODE register to get more information.
                OtpError OFFSET(1) NUMBITS(1) [],
            ],
            pub InterruptTest [
                /// Write 1 to force otp_operation_done to 1.
                OtpOperationDone OFFSET(0) NUMBITS(1) [],
                /// Write 1 to force otp_error to 1.
                OtpError OFFSET(1) NUMBITS(1) [],
            ],
            pub OtpInterruptEnable [
                /// Enable interrupt when otp_operation_done is set.
                OtpOperationDone OFFSET(0) NUMBITS(1) [],
                /// Enable interrupt when otp_error is set.
                OtpError OFFSET(1) NUMBITS(1) [],
            ],
            pub OtpStatus [
                /// Set to 1 if an error occurred in this partition. If set to 1, SW should check the !!ERR_CODE register at the corresponding index.
                SecretTestUnlockPartitionError OFFSET(0) NUMBITS(1) [],
                /// Set to 1 if an error occurred in this partition. If set to 1, SW should check the !!ERR_CODE register at the corresponding index.
                SecretManufPartitionError OFFSET(1) NUMBITS(1) [],
                /// Set to 1 if an error occurred in this partition. If set to 1, SW should check the !!ERR_CODE register at the corresponding index.
                SecretProdPartition0Error OFFSET(2) NUMBITS(1) [],
                /// Set to 1 if an error occurred in this partition. If set to 1, SW should check the !!ERR_CODE register at the corresponding index.
                SecretProdPartition1Error OFFSET(3) NUMBITS(1) [],
                /// Set to 1 if an error occurred in this partition. If set to 1, SW should check the !!ERR_CODE register at the corresponding index.
                SecretProdPartition2Error OFFSET(4) NUMBITS(1) [],
                /// Set to 1 if an error occurred in this partition. If set to 1, SW should check the !!ERR_CODE register at the corresponding index.
                SecretProdPartition3Error OFFSET(5) NUMBITS(1) [],
                /// Set to 1 if an error occurred in this partition. If set to 1, SW should check the !!ERR_CODE register at the corresponding index.
                SwManufPartitionError OFFSET(6) NUMBITS(1) [],
                /// Set to 1 if an error occurred in this partition. If set to 1, SW should check the !!ERR_CODE register at the corresponding index.
                SecretLcTransitionPartitionError OFFSET(7) NUMBITS(1) [],
                /// Set to 1 if an error occurred in this partition. If set to 1, SW should check the !!ERR_CODE register at the corresponding index.
                SvnPartitionError OFFSET(8) NUMBITS(1) [],
                /// Set to 1 if an error occurred in this partition. If set to 1, SW should check the !!ERR_CODE register at the corresponding index.
                VendorTestPartitionError OFFSET(9) NUMBITS(1) [],
                /// Set to 1 if an error occurred in this partition. If set to 1, SW should check the !!ERR_CODE register at the corresponding index.
                VendorHashesManufPartitionError OFFSET(10) NUMBITS(1) [],
                /// Set to 1 if an error occurred in this partition. If set to 1, SW should check the !!ERR_CODE register at the corresponding index.
                VendorHashesProdPartitionError OFFSET(11) NUMBITS(1) [],
                /// Set to 1 if an error occurred in this partition. If set to 1, SW should check the !!ERR_CODE register at the corresponding index.
                VendorRevocationsProdPartitionError OFFSET(12) NUMBITS(1) [],
                /// Set to 1 if an error occurred in this partition. If set to 1, SW should check the !!ERR_CODE register at the corresponding index.
                VendorSecretProdPartitionError OFFSET(13) NUMBITS(1) [],
                /// Set to 1 if an error occurred in this partition. If set to 1, SW should check the !!ERR_CODE register at the corresponding index.
                VendorNonSecretProdPartitionError OFFSET(14) NUMBITS(1) [],
                /// Set to 1 if an error occurred in this partition. If set to 1, SW should check the !!ERR_CODE register at the corresponding index.
                LifeCycleError OFFSET(15) NUMBITS(1) [],
                /// Set to 1 if an error occurred in this partition. If set to 1, SW should check the !!ERR_CODE register at the corresponding index.
                DaiError OFFSET(16) NUMBITS(1) [],
                /// Set to 1 if an error occurred in this partition. If set to 1, SW should check the !!ERR_CODE register at the corresponding index.
                LciError OFFSET(17) NUMBITS(1) [],
                /// Set to 1 if an error occurred in this partition. If set to 1, SW should check the !!ERR_CODE register at the corresponding index.
                TimeoutError OFFSET(18) NUMBITS(1) [],
                /// Set to 1 if the LFSR timer FSM has reached an invalid state. This raises an fatal_check_error alert and is an unrecoverable error condition.
                LfsrFsmError OFFSET(19) NUMBITS(1) [],
                /// Set to 1 if the scrambling datapath FSM has reached an invalid state. This raises an fatal_check_error alert and is an unrecoverable error condition.
                ScramblingFsmError OFFSET(20) NUMBITS(1) [],
                /// This bit is set to 1 if a fatal bus integrity fault is detected. This error triggers a fatal_bus_integ_error alert.
                BusIntegError OFFSET(21) NUMBITS(1) [],
                /// Set to 1 if the DAI is idle and ready to accept commands.
                DaiIdle OFFSET(22) NUMBITS(1) [],
                /// Set to 1 if an integrity or consistency check triggered by the LFSR timer or via !!CHECK_TRIGGER is pending.
                CheckPending OFFSET(23) NUMBITS(1) [],
            ],
            pub SvnPartitionReadLock [
                /// When cleared to 0, read access to the SVN_PARTITION partition is locked.Write 0 to clear this bit.
                ReadLock OFFSET(0) NUMBITS(1) [],
            ],
            pub SwManufPartitionReadLock [
                /// When cleared to 0, read access to the SW_MANUF_PARTITION partition is locked.Write 0 to clear this bit.
                ReadLock OFFSET(0) NUMBITS(1) [],
            ],
            pub VendorHashesManufPartitionReadLock [
                /// When cleared to 0, read access to the VENDOR_HASHES_MANUF_PARTITION partition is locked.Write 0 to clear this bit.
                ReadLock OFFSET(0) NUMBITS(1) [],
            ],
            pub VendorHashesProdPartitionReadLock [
                /// When cleared to 0, read access to the VENDOR_HASHES_PROD_PARTITION partition is locked.Write 0 to clear this bit.
                ReadLock OFFSET(0) NUMBITS(1) [],
            ],
            pub VendorNonSecretProdPartitionReadLock [
                /// When cleared to 0, read access to the VENDOR_NON_SECRET_PROD_PARTITION partition is locked.Write 0 to clear this bit.
                ReadLock OFFSET(0) NUMBITS(1) [],
            ],
            pub VendorRevocationsProdPartitionReadLock [
                /// When cleared to 0, read access to the VENDOR_REVOCATIONS_PROD_PARTITION partition is locked.Write 0 to clear this bit.
                ReadLock OFFSET(0) NUMBITS(1) [],
            ],
            pub VendorTestPartitionReadLock [
                /// When cleared to 0, read access to the VENDOR_TEST_PARTITION partition is locked.Write 0 to clear this bit.
                ReadLock OFFSET(0) NUMBITS(1) [],
            ],
            pub ErrCodeRegT [
                /// This register holds information about error conditions that occurred in the agents interacting with the OTP macro via the internal bus.
                ErrCode OFFSET(0) NUMBITS(3) [],
            ],
    }
}
pub mod regs {
    //! Types that represent registers.
    use tock_registers::register_structs;
    register_structs! {
        pub OtpCtrl {
            (0x0 => pub interrupt_state: tock_registers::registers::ReadWrite<u32, crate::otp_ctrl::bits::InterruptState::Register>),
            (0x4 => pub otp_interrupt_enable: tock_registers::registers::ReadWrite<u32, crate::otp_ctrl::bits::OtpInterruptEnable::Register>),
            (0x8 => pub interrupt_test: tock_registers::registers::WriteOnly<u32, crate::otp_ctrl::bits::InterruptTest::Register>),
            (0xc => pub alert_test: tock_registers::registers::WriteOnly<u32, crate::otp_ctrl::bits::AlertTest::Register>),
            (0x10 => pub otp_status: tock_registers::registers::ReadOnly<u32, crate::otp_ctrl::bits::OtpStatus::Register>),
            (0x14 => pub err_code_rf_err_code_0: tock_registers::registers::ReadOnly<u32, crate::otp_ctrl::bits::ErrCodeRegT::Register>),
            (0x18 => pub err_code_rf_err_code_1: tock_registers::registers::ReadOnly<u32, crate::otp_ctrl::bits::ErrCodeRegT::Register>),
            (0x1c => pub err_code_rf_err_code_2: tock_registers::registers::ReadOnly<u32, crate::otp_ctrl::bits::ErrCodeRegT::Register>),
            (0x20 => pub err_code_rf_err_code_3: tock_registers::registers::ReadOnly<u32, crate::otp_ctrl::bits::ErrCodeRegT::Register>),
            (0x24 => pub err_code_rf_err_code_4: tock_registers::registers::ReadOnly<u32, crate::otp_ctrl::bits::ErrCodeRegT::Register>),
            (0x28 => pub err_code_rf_err_code_5: tock_registers::registers::ReadOnly<u32, crate::otp_ctrl::bits::ErrCodeRegT::Register>),
            (0x2c => pub err_code_rf_err_code_6: tock_registers::registers::ReadOnly<u32, crate::otp_ctrl::bits::ErrCodeRegT::Register>),
            (0x30 => pub err_code_rf_err_code_7: tock_registers::registers::ReadOnly<u32, crate::otp_ctrl::bits::ErrCodeRegT::Register>),
            (0x34 => pub err_code_rf_err_code_8: tock_registers::registers::ReadOnly<u32, crate::otp_ctrl::bits::ErrCodeRegT::Register>),
            (0x38 => pub err_code_rf_err_code_9: tock_registers::registers::ReadOnly<u32, crate::otp_ctrl::bits::ErrCodeRegT::Register>),
            (0x3c => pub err_code_rf_err_code_10: tock_registers::registers::ReadOnly<u32, crate::otp_ctrl::bits::ErrCodeRegT::Register>),
            (0x40 => pub err_code_rf_err_code_11: tock_registers::registers::ReadOnly<u32, crate::otp_ctrl::bits::ErrCodeRegT::Register>),
            (0x44 => pub err_code_rf_err_code_12: tock_registers::registers::ReadOnly<u32, crate::otp_ctrl::bits::ErrCodeRegT::Register>),
            (0x48 => pub err_code_rf_err_code_13: tock_registers::registers::ReadOnly<u32, crate::otp_ctrl::bits::ErrCodeRegT::Register>),
            (0x4c => pub err_code_rf_err_code_14: tock_registers::registers::ReadOnly<u32, crate::otp_ctrl::bits::ErrCodeRegT::Register>),
            (0x50 => pub err_code_rf_err_code_15: tock_registers::registers::ReadOnly<u32, crate::otp_ctrl::bits::ErrCodeRegT::Register>),
            (0x54 => pub err_code_rf_err_code_16: tock_registers::registers::ReadOnly<u32, crate::otp_ctrl::bits::ErrCodeRegT::Register>),
            (0x58 => pub err_code_rf_err_code_17: tock_registers::registers::ReadOnly<u32, crate::otp_ctrl::bits::ErrCodeRegT::Register>),
            (0x5c => pub direct_access_regwen: tock_registers::registers::ReadWrite<u32, crate::otp_ctrl::bits::DirectAccessRegwen::Register>),
            (0x60 => pub direct_access_cmd: tock_registers::registers::WriteOnly<u32, crate::otp_ctrl::bits::DirectAccessCmd::Register>),
            (0x64 => pub direct_access_address: tock_registers::registers::ReadWrite<u32, crate::otp_ctrl::bits::DirectAccessAddress::Register>),
            (0x68 => pub dai_wdata_rf_direct_access_wdata_0: tock_registers::registers::ReadWrite<u32>),
            (0x6c => pub dai_wdata_rf_direct_access_wdata_1: tock_registers::registers::ReadWrite<u32>),
            (0x70 => pub dai_rdata_rf_direct_access_rdata_0: tock_registers::registers::ReadOnly<u32>),
            (0x74 => pub dai_rdata_rf_direct_access_rdata_1: tock_registers::registers::ReadOnly<u32>),
            (0x78 => pub check_trigger_regwen: tock_registers::registers::ReadWrite<u32, crate::otp_ctrl::bits::CheckTriggerRegwen::Register>),
            (0x7c => pub check_trigger: tock_registers::registers::WriteOnly<u32, crate::otp_ctrl::bits::CheckTrigger::Register>),
            (0x80 => pub check_regwen: tock_registers::registers::WriteOnly<u32, crate::otp_ctrl::bits::CheckRegwen::Register>),
            (0x84 => pub check_timeout: tock_registers::registers::ReadWrite<u32>),
            (0x88 => pub integrity_check_period: tock_registers::registers::ReadWrite<u32>),
            (0x8c => pub consistency_check_period: tock_registers::registers::ReadWrite<u32>),
            (0x90 => pub sw_manuf_partition_read_lock: tock_registers::registers::ReadWrite<u32, crate::otp_ctrl::bits::SwManufPartitionReadLock::Register>),
            (0x94 => pub svn_partition_read_lock: tock_registers::registers::ReadWrite<u32, crate::otp_ctrl::bits::SvnPartitionReadLock::Register>),
            (0x98 => pub vendor_test_partition_read_lock: tock_registers::registers::ReadWrite<u32, crate::otp_ctrl::bits::VendorTestPartitionReadLock::Register>),
            (0x9c => pub vendor_hashes_manuf_partition_read_lock: tock_registers::registers::ReadWrite<u32, crate::otp_ctrl::bits::VendorHashesManufPartitionReadLock::Register>),
            (0xa0 => pub vendor_hashes_prod_partition_read_lock: tock_registers::registers::ReadWrite<u32, crate::otp_ctrl::bits::VendorHashesProdPartitionReadLock::Register>),
            (0xa4 => pub vendor_revocations_prod_partition_read_lock: tock_registers::registers::ReadWrite<u32, crate::otp_ctrl::bits::VendorRevocationsProdPartitionReadLock::Register>),
            (0xa8 => pub vendor_non_secret_prod_partition_read_lock: tock_registers::registers::ReadWrite<u32, crate::otp_ctrl::bits::VendorNonSecretProdPartitionReadLock::Register>),
            (0xac => pub vendor_pk_hash_volatile_lock: tock_registers::registers::ReadWrite<u32>),
            (0xb0 => pub secret_test_unlock_partition_digest_digest_0: tock_registers::registers::ReadOnly<u32>),
            (0xb4 => pub secret_test_unlock_partition_digest_digest_1: tock_registers::registers::ReadOnly<u32>),
            (0xb8 => pub secret_manuf_partition_digest_digest_0: tock_registers::registers::ReadOnly<u32>),
            (0xbc => pub secret_manuf_partition_digest_digest_1: tock_registers::registers::ReadOnly<u32>),
            (0xc0 => pub secret_prod_partition_0_digest_digest_0: tock_registers::registers::ReadOnly<u32>),
            (0xc4 => pub secret_prod_partition_0_digest_digest_1: tock_registers::registers::ReadOnly<u32>),
            (0xc8 => pub secret_prod_partition_1_digest_digest_0: tock_registers::registers::ReadOnly<u32>),
            (0xcc => pub secret_prod_partition_1_digest_digest_1: tock_registers::registers::ReadOnly<u32>),
            (0xd0 => pub secret_prod_partition_2_digest_digest_0: tock_registers::registers::ReadOnly<u32>),
            (0xd4 => pub secret_prod_partition_2_digest_digest_1: tock_registers::registers::ReadOnly<u32>),
            (0xd8 => pub secret_prod_partition_3_digest_digest_0: tock_registers::registers::ReadOnly<u32>),
            (0xdc => pub secret_prod_partition_3_digest_digest_1: tock_registers::registers::ReadOnly<u32>),
            (0xe0 => pub sw_manuf_partition_digest_digest_0: tock_registers::registers::ReadOnly<u32>),
            (0xe4 => pub sw_manuf_partition_digest_digest_1: tock_registers::registers::ReadOnly<u32>),
            (0xe8 => pub secret_lc_transition_partition_digest_digest_0: tock_registers::registers::ReadOnly<u32>),
            (0xec => pub secret_lc_transition_partition_digest_digest_1: tock_registers::registers::ReadOnly<u32>),
            (0xf0 => pub vendor_test_partition_digest_digest_0: tock_registers::registers::ReadOnly<u32>),
            (0xf4 => pub vendor_test_partition_digest_digest_1: tock_registers::registers::ReadOnly<u32>),
            (0xf8 => pub vendor_hashes_manuf_partition_digest_digest_0: tock_registers::registers::ReadOnly<u32>),
            (0xfc => pub vendor_hashes_manuf_partition_digest_digest_1: tock_registers::registers::ReadOnly<u32>),
            (0x100 => pub vendor_hashes_prod_partition_digest_digest_0: tock_registers::registers::ReadOnly<u32>),
            (0x104 => pub vendor_hashes_prod_partition_digest_digest_1: tock_registers::registers::ReadOnly<u32>),
            (0x108 => pub vendor_revocations_prod_partition_digest_digest_0: tock_registers::registers::ReadOnly<u32>),
            (0x10c => pub vendor_revocations_prod_partition_digest_digest_1: tock_registers::registers::ReadOnly<u32>),
            (0x110 => pub vendor_secret_prod_partition_digest_digest_0: tock_registers::registers::ReadOnly<u32>),
            (0x114 => pub vendor_secret_prod_partition_digest_digest_1: tock_registers::registers::ReadOnly<u32>),
            (0x118 => pub vendor_non_secret_prod_partition_digest_digest_0: tock_registers::registers::ReadOnly<u32>),
            (0x11c => pub vendor_non_secret_prod_partition_digest_digest_1: tock_registers::registers::ReadOnly<u32>),
            (0x120 => pub csr0: tock_registers::registers::ReadWrite<u32, crate::otp_ctrl::bits::Csr0::Register>),
            (0x124 => pub csr1: tock_registers::registers::ReadWrite<u32, crate::otp_ctrl::bits::Csr1::Register>),
            (0x128 => pub csr2: tock_registers::registers::ReadWrite<u32, crate::otp_ctrl::bits::Csr2::Register>),
            (0x12c => pub csr3: tock_registers::registers::ReadWrite<u32, crate::otp_ctrl::bits::Csr3::Register>),
            (0x130 => pub csr4: tock_registers::registers::ReadWrite<u32, crate::otp_ctrl::bits::Csr4::Register>),
            (0x134 => pub csr5: tock_registers::registers::ReadWrite<u32, crate::otp_ctrl::bits::Csr5::Register>),
            (0x138 => pub csr6: tock_registers::registers::ReadWrite<u32, crate::otp_ctrl::bits::Csr6::Register>),
            (0x13c => pub csr7: tock_registers::registers::ReadOnly<u32, crate::otp_ctrl::bits::Csr7::Register>),
            (0x140 => @END),
        }
    }
}
