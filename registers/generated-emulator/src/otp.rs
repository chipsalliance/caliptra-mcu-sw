// Licensed under the Apache-2.0 license.
//
// generated by registers_generator with caliptra-ss repo at a621fff9df7015821eda6f7f73265fef74a01375
//
#[allow(unused_imports)]
use tock_registers::interfaces::{Readable, Writeable};
pub trait OtpPeripheral {
    fn set_dma_ram(&mut self, _ram: std::rc::Rc<std::cell::RefCell<emulator_bus::Ram>>) {}
    fn poll(&mut self) {}
    fn warm_reset(&mut self) {}
    fn update_reset(&mut self) {}
    fn read_interrupt_state(
        &mut self,
        _size: emulator_types::RvSize,
    ) -> emulator_bus::ReadWriteRegister<
        u32,
        registers_generated::otp_ctrl::bits::InterruptState::Register,
    > {
        emulator_bus::ReadWriteRegister::new(0)
    }
    fn write_interrupt_state(
        &mut self,
        _size: emulator_types::RvSize,
        _val: emulator_bus::ReadWriteRegister<
            u32,
            registers_generated::otp_ctrl::bits::InterruptState::Register,
        >,
    ) {
    }
    fn read_interrupt_enable(
        &mut self,
        _size: emulator_types::RvSize,
    ) -> emulator_bus::ReadWriteRegister<
        u32,
        registers_generated::i3c::bits::InterruptEnable::Register,
    > {
        emulator_bus::ReadWriteRegister::new(0)
    }
    fn write_interrupt_enable(
        &mut self,
        _size: emulator_types::RvSize,
        _val: emulator_bus::ReadWriteRegister<
            u32,
            registers_generated::i3c::bits::InterruptEnable::Register,
        >,
    ) {
    }
    fn write_interrupt_test(
        &mut self,
        _size: emulator_types::RvSize,
        _val: emulator_bus::ReadWriteRegister<
            u32,
            registers_generated::otp_ctrl::bits::InterruptTest::Register,
        >,
    ) {
    }
    fn write_alert_test(
        &mut self,
        _size: emulator_types::RvSize,
        _val: emulator_bus::ReadWriteRegister<
            u32,
            registers_generated::otp_ctrl::bits::AlertTest::Register,
        >,
    ) {
    }
    fn read_status(
        &mut self,
        _size: emulator_types::RvSize,
    ) -> emulator_bus::ReadWriteRegister<u32, registers_generated::otp_ctrl::bits::Status::Register>
    {
        emulator_bus::ReadWriteRegister::new(0)
    }
    fn read_direct_access_regwen(
        &mut self,
        _size: emulator_types::RvSize,
    ) -> emulator_bus::ReadWriteRegister<
        u32,
        registers_generated::otp_ctrl::bits::DirectAccessRegwen::Register,
    > {
        emulator_bus::ReadWriteRegister::new(0)
    }
    fn write_direct_access_regwen(
        &mut self,
        _size: emulator_types::RvSize,
        _val: emulator_bus::ReadWriteRegister<
            u32,
            registers_generated::otp_ctrl::bits::DirectAccessRegwen::Register,
        >,
    ) {
    }
    fn write_direct_access_cmd(
        &mut self,
        _size: emulator_types::RvSize,
        _val: emulator_bus::ReadWriteRegister<
            u32,
            registers_generated::otp_ctrl::bits::DirectAccessCmd::Register,
        >,
    ) {
    }
    fn read_direct_access_address(
        &mut self,
        _size: emulator_types::RvSize,
    ) -> emulator_bus::ReadWriteRegister<
        u32,
        registers_generated::otp_ctrl::bits::DirectAccessAddress::Register,
    > {
        emulator_bus::ReadWriteRegister::new(0)
    }
    fn write_direct_access_address(
        &mut self,
        _size: emulator_types::RvSize,
        _val: emulator_bus::ReadWriteRegister<
            u32,
            registers_generated::otp_ctrl::bits::DirectAccessAddress::Register,
        >,
    ) {
    }
    fn read_check_trigger_regwen(
        &mut self,
        _size: emulator_types::RvSize,
    ) -> emulator_bus::ReadWriteRegister<
        u32,
        registers_generated::otp_ctrl::bits::CheckTriggerRegwen::Register,
    > {
        emulator_bus::ReadWriteRegister::new(0)
    }
    fn write_check_trigger_regwen(
        &mut self,
        _size: emulator_types::RvSize,
        _val: emulator_bus::ReadWriteRegister<
            u32,
            registers_generated::otp_ctrl::bits::CheckTriggerRegwen::Register,
        >,
    ) {
    }
    fn write_check_trigger(
        &mut self,
        _size: emulator_types::RvSize,
        _val: emulator_bus::ReadWriteRegister<
            u32,
            registers_generated::otp_ctrl::bits::CheckTrigger::Register,
        >,
    ) {
    }
    fn write_check_regwen(
        &mut self,
        _size: emulator_types::RvSize,
        _val: emulator_bus::ReadWriteRegister<
            u32,
            registers_generated::otp_ctrl::bits::CheckRegwen::Register,
        >,
    ) {
    }
    fn read_check_timeout(&mut self, _size: emulator_types::RvSize) -> emulator_types::RvData {
        0
    }
    fn write_check_timeout(&mut self, _size: emulator_types::RvSize, _val: emulator_types::RvData) {
    }
    fn read_integrity_check_period(
        &mut self,
        _size: emulator_types::RvSize,
    ) -> emulator_types::RvData {
        0
    }
    fn write_integrity_check_period(
        &mut self,
        _size: emulator_types::RvSize,
        _val: emulator_types::RvData,
    ) {
    }
    fn read_consistency_check_period(
        &mut self,
        _size: emulator_types::RvSize,
    ) -> emulator_types::RvData {
        0
    }
    fn write_consistency_check_period(
        &mut self,
        _size: emulator_types::RvSize,
        _val: emulator_types::RvData,
    ) {
    }
    fn read_vendor_test_read_lock(
        &mut self,
        _size: emulator_types::RvSize,
    ) -> emulator_bus::ReadWriteRegister<
        u32,
        registers_generated::otp_ctrl::bits::VendorTestReadLock::Register,
    > {
        emulator_bus::ReadWriteRegister::new(0)
    }
    fn write_vendor_test_read_lock(
        &mut self,
        _size: emulator_types::RvSize,
        _val: emulator_bus::ReadWriteRegister<
            u32,
            registers_generated::otp_ctrl::bits::VendorTestReadLock::Register,
        >,
    ) {
    }
    fn read_non_secret_fuses_read_lock(
        &mut self,
        _size: emulator_types::RvSize,
    ) -> emulator_bus::ReadWriteRegister<
        u32,
        registers_generated::otp_ctrl::bits::NonSecretFusesReadLock::Register,
    > {
        emulator_bus::ReadWriteRegister::new(0)
    }
    fn write_non_secret_fuses_read_lock(
        &mut self,
        _size: emulator_types::RvSize,
        _val: emulator_bus::ReadWriteRegister<
            u32,
            registers_generated::otp_ctrl::bits::NonSecretFusesReadLock::Register,
        >,
    ) {
    }
    fn read_csr0(
        &mut self,
        _size: emulator_types::RvSize,
    ) -> emulator_bus::ReadWriteRegister<u32, registers_generated::otp_ctrl::bits::Csr0::Register>
    {
        emulator_bus::ReadWriteRegister::new(0)
    }
    fn write_csr0(
        &mut self,
        _size: emulator_types::RvSize,
        _val: emulator_bus::ReadWriteRegister<
            u32,
            registers_generated::otp_ctrl::bits::Csr0::Register,
        >,
    ) {
    }
    fn read_csr1(
        &mut self,
        _size: emulator_types::RvSize,
    ) -> emulator_bus::ReadWriteRegister<u32, registers_generated::otp_ctrl::bits::Csr1::Register>
    {
        emulator_bus::ReadWriteRegister::new(0)
    }
    fn write_csr1(
        &mut self,
        _size: emulator_types::RvSize,
        _val: emulator_bus::ReadWriteRegister<
            u32,
            registers_generated::otp_ctrl::bits::Csr1::Register,
        >,
    ) {
    }
    fn read_csr2(
        &mut self,
        _size: emulator_types::RvSize,
    ) -> emulator_bus::ReadWriteRegister<u32, registers_generated::otp_ctrl::bits::Csr2::Register>
    {
        emulator_bus::ReadWriteRegister::new(0)
    }
    fn write_csr2(
        &mut self,
        _size: emulator_types::RvSize,
        _val: emulator_bus::ReadWriteRegister<
            u32,
            registers_generated::otp_ctrl::bits::Csr2::Register,
        >,
    ) {
    }
    fn read_csr3(
        &mut self,
        _size: emulator_types::RvSize,
    ) -> emulator_bus::ReadWriteRegister<u32, registers_generated::otp_ctrl::bits::Csr3::Register>
    {
        emulator_bus::ReadWriteRegister::new(0)
    }
    fn write_csr3(
        &mut self,
        _size: emulator_types::RvSize,
        _val: emulator_bus::ReadWriteRegister<
            u32,
            registers_generated::otp_ctrl::bits::Csr3::Register,
        >,
    ) {
    }
    fn read_csr4(
        &mut self,
        _size: emulator_types::RvSize,
    ) -> emulator_bus::ReadWriteRegister<u32, registers_generated::otp_ctrl::bits::Csr4::Register>
    {
        emulator_bus::ReadWriteRegister::new(0)
    }
    fn write_csr4(
        &mut self,
        _size: emulator_types::RvSize,
        _val: emulator_bus::ReadWriteRegister<
            u32,
            registers_generated::otp_ctrl::bits::Csr4::Register,
        >,
    ) {
    }
    fn read_csr5(
        &mut self,
        _size: emulator_types::RvSize,
    ) -> emulator_bus::ReadWriteRegister<u32, registers_generated::otp_ctrl::bits::Csr5::Register>
    {
        emulator_bus::ReadWriteRegister::new(0)
    }
    fn write_csr5(
        &mut self,
        _size: emulator_types::RvSize,
        _val: emulator_bus::ReadWriteRegister<
            u32,
            registers_generated::otp_ctrl::bits::Csr5::Register,
        >,
    ) {
    }
    fn read_csr6(
        &mut self,
        _size: emulator_types::RvSize,
    ) -> emulator_bus::ReadWriteRegister<u32, registers_generated::otp_ctrl::bits::Csr6::Register>
    {
        emulator_bus::ReadWriteRegister::new(0)
    }
    fn write_csr6(
        &mut self,
        _size: emulator_types::RvSize,
        _val: emulator_bus::ReadWriteRegister<
            u32,
            registers_generated::otp_ctrl::bits::Csr6::Register,
        >,
    ) {
    }
    fn read_csr7(
        &mut self,
        _size: emulator_types::RvSize,
    ) -> emulator_bus::ReadWriteRegister<u32, registers_generated::otp_ctrl::bits::Csr7::Register>
    {
        emulator_bus::ReadWriteRegister::new(0)
    }
    fn read_err_code_rf_err_code_0(
        &mut self,
        _size: emulator_types::RvSize,
    ) -> emulator_bus::ReadWriteRegister<
        u32,
        registers_generated::otp_ctrl::bits::ErrCodeRegT::Register,
    > {
        emulator_bus::ReadWriteRegister::new(0)
    }
    fn read_err_code_rf_err_code_1(
        &mut self,
        _size: emulator_types::RvSize,
    ) -> emulator_bus::ReadWriteRegister<
        u32,
        registers_generated::otp_ctrl::bits::ErrCodeRegT::Register,
    > {
        emulator_bus::ReadWriteRegister::new(0)
    }
    fn read_err_code_rf_err_code_2(
        &mut self,
        _size: emulator_types::RvSize,
    ) -> emulator_bus::ReadWriteRegister<
        u32,
        registers_generated::otp_ctrl::bits::ErrCodeRegT::Register,
    > {
        emulator_bus::ReadWriteRegister::new(0)
    }
    fn read_err_code_rf_err_code_3(
        &mut self,
        _size: emulator_types::RvSize,
    ) -> emulator_bus::ReadWriteRegister<
        u32,
        registers_generated::otp_ctrl::bits::ErrCodeRegT::Register,
    > {
        emulator_bus::ReadWriteRegister::new(0)
    }
    fn read_err_code_rf_err_code_4(
        &mut self,
        _size: emulator_types::RvSize,
    ) -> emulator_bus::ReadWriteRegister<
        u32,
        registers_generated::otp_ctrl::bits::ErrCodeRegT::Register,
    > {
        emulator_bus::ReadWriteRegister::new(0)
    }
    fn read_err_code_rf_err_code_5(
        &mut self,
        _size: emulator_types::RvSize,
    ) -> emulator_bus::ReadWriteRegister<
        u32,
        registers_generated::otp_ctrl::bits::ErrCodeRegT::Register,
    > {
        emulator_bus::ReadWriteRegister::new(0)
    }
    fn read_err_code_rf_err_code_6(
        &mut self,
        _size: emulator_types::RvSize,
    ) -> emulator_bus::ReadWriteRegister<
        u32,
        registers_generated::otp_ctrl::bits::ErrCodeRegT::Register,
    > {
        emulator_bus::ReadWriteRegister::new(0)
    }
    fn read_err_code_rf_err_code_7(
        &mut self,
        _size: emulator_types::RvSize,
    ) -> emulator_bus::ReadWriteRegister<
        u32,
        registers_generated::otp_ctrl::bits::ErrCodeRegT::Register,
    > {
        emulator_bus::ReadWriteRegister::new(0)
    }
    fn read_err_code_rf_err_code_8(
        &mut self,
        _size: emulator_types::RvSize,
    ) -> emulator_bus::ReadWriteRegister<
        u32,
        registers_generated::otp_ctrl::bits::ErrCodeRegT::Register,
    > {
        emulator_bus::ReadWriteRegister::new(0)
    }
    fn read_dai_wdata_rf_direct_access_wdata_0(
        &mut self,
        _size: emulator_types::RvSize,
    ) -> emulator_types::RvData {
        0
    }
    fn write_dai_wdata_rf_direct_access_wdata_0(
        &mut self,
        _size: emulator_types::RvSize,
        _val: emulator_types::RvData,
    ) {
    }
    fn read_dai_wdata_rf_direct_access_wdata_1(
        &mut self,
        _size: emulator_types::RvSize,
    ) -> emulator_types::RvData {
        0
    }
    fn write_dai_wdata_rf_direct_access_wdata_1(
        &mut self,
        _size: emulator_types::RvSize,
        _val: emulator_types::RvData,
    ) {
    }
    fn read_dai_rdata_rf_direct_access_rdata_0(
        &mut self,
        _size: emulator_types::RvSize,
    ) -> emulator_types::RvData {
        0
    }
    fn read_dai_rdata_rf_direct_access_rdata_1(
        &mut self,
        _size: emulator_types::RvSize,
    ) -> emulator_types::RvData {
        0
    }
    fn read_vendor_test_digest_digest_0(
        &mut self,
        _size: emulator_types::RvSize,
    ) -> emulator_types::RvData {
        0
    }
    fn read_vendor_test_digest_digest_1(
        &mut self,
        _size: emulator_types::RvSize,
    ) -> emulator_types::RvData {
        0
    }
    fn read_non_secret_fuses_digest_digest_0(
        &mut self,
        _size: emulator_types::RvSize,
    ) -> emulator_types::RvData {
        0
    }
    fn read_non_secret_fuses_digest_digest_1(
        &mut self,
        _size: emulator_types::RvSize,
    ) -> emulator_types::RvData {
        0
    }
    fn read_secret0_digest_digest_0(
        &mut self,
        _size: emulator_types::RvSize,
    ) -> emulator_types::RvData {
        0
    }
    fn read_secret0_digest_digest_1(
        &mut self,
        _size: emulator_types::RvSize,
    ) -> emulator_types::RvData {
        0
    }
    fn read_secret1_digest_digest_0(
        &mut self,
        _size: emulator_types::RvSize,
    ) -> emulator_types::RvData {
        0
    }
    fn read_secret1_digest_digest_1(
        &mut self,
        _size: emulator_types::RvSize,
    ) -> emulator_types::RvData {
        0
    }
    fn read_secret2_digest_digest_0(
        &mut self,
        _size: emulator_types::RvSize,
    ) -> emulator_types::RvData {
        0
    }
    fn read_secret2_digest_digest_1(
        &mut self,
        _size: emulator_types::RvSize,
    ) -> emulator_types::RvData {
        0
    }
    fn read_secret3_digest_digest_0(
        &mut self,
        _size: emulator_types::RvSize,
    ) -> emulator_types::RvData {
        0
    }
    fn read_secret3_digest_digest_1(
        &mut self,
        _size: emulator_types::RvSize,
    ) -> emulator_types::RvData {
        0
    }
}
pub struct OtpBus {
    pub periph: Box<dyn OtpPeripheral>,
}
impl emulator_bus::Bus for OtpBus {
    fn read(
        &mut self,
        size: emulator_types::RvSize,
        addr: emulator_types::RvAddr,
    ) -> Result<emulator_types::RvData, emulator_bus::BusError> {
        match (size, addr) {
            (emulator_types::RvSize::Word, 0) => Ok(emulator_types::RvData::from(
                self.periph
                    .read_interrupt_state(emulator_types::RvSize::Word)
                    .reg
                    .get(),
            )),
            (emulator_types::RvSize::Word, 1..=3) => {
                Err(emulator_bus::BusError::LoadAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 4) => Ok(emulator_types::RvData::from(
                self.periph
                    .read_interrupt_enable(emulator_types::RvSize::Word)
                    .reg
                    .get(),
            )),
            (emulator_types::RvSize::Word, 5..=7) => {
                Err(emulator_bus::BusError::LoadAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0x10) => Ok(emulator_types::RvData::from(
                self.periph
                    .read_status(emulator_types::RvSize::Word)
                    .reg
                    .get(),
            )),
            (emulator_types::RvSize::Word, 0x11..=0x13) => {
                Err(emulator_bus::BusError::LoadAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0x38) => Ok(emulator_types::RvData::from(
                self.periph
                    .read_direct_access_regwen(emulator_types::RvSize::Word)
                    .reg
                    .get(),
            )),
            (emulator_types::RvSize::Word, 0x39..=0x3b) => {
                Err(emulator_bus::BusError::LoadAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0x40) => Ok(emulator_types::RvData::from(
                self.periph
                    .read_direct_access_address(emulator_types::RvSize::Word)
                    .reg
                    .get(),
            )),
            (emulator_types::RvSize::Word, 0x41..=0x43) => {
                Err(emulator_bus::BusError::LoadAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0x54) => Ok(emulator_types::RvData::from(
                self.periph
                    .read_check_trigger_regwen(emulator_types::RvSize::Word)
                    .reg
                    .get(),
            )),
            (emulator_types::RvSize::Word, 0x55..=0x57) => {
                Err(emulator_bus::BusError::LoadAddrMisaligned)
            }
            (size, 0x60) => Ok(self.periph.read_check_timeout(size)),
            (_, 0x61..=0x63) => Err(emulator_bus::BusError::LoadAddrMisaligned),
            (size, 0x64) => Ok(self.periph.read_integrity_check_period(size)),
            (_, 0x65..=0x67) => Err(emulator_bus::BusError::LoadAddrMisaligned),
            (size, 0x68) => Ok(self.periph.read_consistency_check_period(size)),
            (_, 0x69..=0x6b) => Err(emulator_bus::BusError::LoadAddrMisaligned),
            (emulator_types::RvSize::Word, 0x6c) => Ok(emulator_types::RvData::from(
                self.periph
                    .read_vendor_test_read_lock(emulator_types::RvSize::Word)
                    .reg
                    .get(),
            )),
            (emulator_types::RvSize::Word, 0x6d..=0x6f) => {
                Err(emulator_bus::BusError::LoadAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0x70) => Ok(emulator_types::RvData::from(
                self.periph
                    .read_non_secret_fuses_read_lock(emulator_types::RvSize::Word)
                    .reg
                    .get(),
            )),
            (emulator_types::RvSize::Word, 0x71..=0x73) => {
                Err(emulator_bus::BusError::LoadAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0xa4) => Ok(emulator_types::RvData::from(
                self.periph
                    .read_csr0(emulator_types::RvSize::Word)
                    .reg
                    .get(),
            )),
            (emulator_types::RvSize::Word, 0xa5..=0xa7) => {
                Err(emulator_bus::BusError::LoadAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0xa8) => Ok(emulator_types::RvData::from(
                self.periph
                    .read_csr1(emulator_types::RvSize::Word)
                    .reg
                    .get(),
            )),
            (emulator_types::RvSize::Word, 0xa9..=0xab) => {
                Err(emulator_bus::BusError::LoadAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0xac) => Ok(emulator_types::RvData::from(
                self.periph
                    .read_csr2(emulator_types::RvSize::Word)
                    .reg
                    .get(),
            )),
            (emulator_types::RvSize::Word, 0xad..=0xaf) => {
                Err(emulator_bus::BusError::LoadAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0xb0) => Ok(emulator_types::RvData::from(
                self.periph
                    .read_csr3(emulator_types::RvSize::Word)
                    .reg
                    .get(),
            )),
            (emulator_types::RvSize::Word, 0xb1..=0xb3) => {
                Err(emulator_bus::BusError::LoadAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0xb4) => Ok(emulator_types::RvData::from(
                self.periph
                    .read_csr4(emulator_types::RvSize::Word)
                    .reg
                    .get(),
            )),
            (emulator_types::RvSize::Word, 0xb5..=0xb7) => {
                Err(emulator_bus::BusError::LoadAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0xb8) => Ok(emulator_types::RvData::from(
                self.periph
                    .read_csr5(emulator_types::RvSize::Word)
                    .reg
                    .get(),
            )),
            (emulator_types::RvSize::Word, 0xb9..=0xbb) => {
                Err(emulator_bus::BusError::LoadAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0xbc) => Ok(emulator_types::RvData::from(
                self.periph
                    .read_csr6(emulator_types::RvSize::Word)
                    .reg
                    .get(),
            )),
            (emulator_types::RvSize::Word, 0xbd..=0xbf) => {
                Err(emulator_bus::BusError::LoadAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0xc0) => Ok(emulator_types::RvData::from(
                self.periph
                    .read_csr7(emulator_types::RvSize::Word)
                    .reg
                    .get(),
            )),
            (emulator_types::RvSize::Word, 0xc1..=0xc3) => {
                Err(emulator_bus::BusError::LoadAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0x14) => Ok(emulator_types::RvData::from(
                self.periph
                    .read_err_code_rf_err_code_0(emulator_types::RvSize::Word)
                    .reg
                    .get(),
            )),
            (emulator_types::RvSize::Word, 0x15..=0x17) => {
                Err(emulator_bus::BusError::LoadAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0x18) => Ok(emulator_types::RvData::from(
                self.periph
                    .read_err_code_rf_err_code_1(emulator_types::RvSize::Word)
                    .reg
                    .get(),
            )),
            (emulator_types::RvSize::Word, 0x19..=0x1b) => {
                Err(emulator_bus::BusError::LoadAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0x1c) => Ok(emulator_types::RvData::from(
                self.periph
                    .read_err_code_rf_err_code_2(emulator_types::RvSize::Word)
                    .reg
                    .get(),
            )),
            (emulator_types::RvSize::Word, 0x1d..=0x1f) => {
                Err(emulator_bus::BusError::LoadAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0x20) => Ok(emulator_types::RvData::from(
                self.periph
                    .read_err_code_rf_err_code_3(emulator_types::RvSize::Word)
                    .reg
                    .get(),
            )),
            (emulator_types::RvSize::Word, 0x21..=0x23) => {
                Err(emulator_bus::BusError::LoadAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0x24) => Ok(emulator_types::RvData::from(
                self.periph
                    .read_err_code_rf_err_code_4(emulator_types::RvSize::Word)
                    .reg
                    .get(),
            )),
            (emulator_types::RvSize::Word, 0x25..=0x27) => {
                Err(emulator_bus::BusError::LoadAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0x28) => Ok(emulator_types::RvData::from(
                self.periph
                    .read_err_code_rf_err_code_5(emulator_types::RvSize::Word)
                    .reg
                    .get(),
            )),
            (emulator_types::RvSize::Word, 0x29..=0x2b) => {
                Err(emulator_bus::BusError::LoadAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0x2c) => Ok(emulator_types::RvData::from(
                self.periph
                    .read_err_code_rf_err_code_6(emulator_types::RvSize::Word)
                    .reg
                    .get(),
            )),
            (emulator_types::RvSize::Word, 0x2d..=0x2f) => {
                Err(emulator_bus::BusError::LoadAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0x30) => Ok(emulator_types::RvData::from(
                self.periph
                    .read_err_code_rf_err_code_7(emulator_types::RvSize::Word)
                    .reg
                    .get(),
            )),
            (emulator_types::RvSize::Word, 0x31..=0x33) => {
                Err(emulator_bus::BusError::LoadAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0x34) => Ok(emulator_types::RvData::from(
                self.periph
                    .read_err_code_rf_err_code_8(emulator_types::RvSize::Word)
                    .reg
                    .get(),
            )),
            (emulator_types::RvSize::Word, 0x35..=0x37) => {
                Err(emulator_bus::BusError::LoadAddrMisaligned)
            }
            (size, 0x44) => Ok(self.periph.read_dai_wdata_rf_direct_access_wdata_0(size)),
            (_, 0x45..=0x47) => Err(emulator_bus::BusError::LoadAddrMisaligned),
            (size, 0x48) => Ok(self.periph.read_dai_wdata_rf_direct_access_wdata_1(size)),
            (_, 0x49..=0x4b) => Err(emulator_bus::BusError::LoadAddrMisaligned),
            (size, 0x4c) => Ok(self.periph.read_dai_rdata_rf_direct_access_rdata_0(size)),
            (_, 0x4d..=0x4f) => Err(emulator_bus::BusError::LoadAddrMisaligned),
            (size, 0x50) => Ok(self.periph.read_dai_rdata_rf_direct_access_rdata_1(size)),
            (_, 0x51..=0x53) => Err(emulator_bus::BusError::LoadAddrMisaligned),
            (size, 0x74) => Ok(self.periph.read_vendor_test_digest_digest_0(size)),
            (_, 0x75..=0x77) => Err(emulator_bus::BusError::LoadAddrMisaligned),
            (size, 0x78) => Ok(self.periph.read_vendor_test_digest_digest_1(size)),
            (_, 0x79..=0x7b) => Err(emulator_bus::BusError::LoadAddrMisaligned),
            (size, 0x7c) => Ok(self.periph.read_non_secret_fuses_digest_digest_0(size)),
            (_, 0x7d..=0x7f) => Err(emulator_bus::BusError::LoadAddrMisaligned),
            (size, 0x80) => Ok(self.periph.read_non_secret_fuses_digest_digest_1(size)),
            (_, 0x81..=0x83) => Err(emulator_bus::BusError::LoadAddrMisaligned),
            (size, 0x84) => Ok(self.periph.read_secret0_digest_digest_0(size)),
            (_, 0x85..=0x87) => Err(emulator_bus::BusError::LoadAddrMisaligned),
            (size, 0x88) => Ok(self.periph.read_secret0_digest_digest_1(size)),
            (_, 0x89..=0x8b) => Err(emulator_bus::BusError::LoadAddrMisaligned),
            (size, 0x8c) => Ok(self.periph.read_secret1_digest_digest_0(size)),
            (_, 0x8d..=0x8f) => Err(emulator_bus::BusError::LoadAddrMisaligned),
            (size, 0x90) => Ok(self.periph.read_secret1_digest_digest_1(size)),
            (_, 0x91..=0x93) => Err(emulator_bus::BusError::LoadAddrMisaligned),
            (size, 0x94) => Ok(self.periph.read_secret2_digest_digest_0(size)),
            (_, 0x95..=0x97) => Err(emulator_bus::BusError::LoadAddrMisaligned),
            (size, 0x98) => Ok(self.periph.read_secret2_digest_digest_1(size)),
            (_, 0x99..=0x9b) => Err(emulator_bus::BusError::LoadAddrMisaligned),
            (size, 0x9c) => Ok(self.periph.read_secret3_digest_digest_0(size)),
            (_, 0x9d..=0x9f) => Err(emulator_bus::BusError::LoadAddrMisaligned),
            (size, 0xa0) => Ok(self.periph.read_secret3_digest_digest_1(size)),
            (_, 0xa1..=0xa3) => Err(emulator_bus::BusError::LoadAddrMisaligned),
            _ => Err(emulator_bus::BusError::LoadAccessFault),
        }
    }
    fn write(
        &mut self,
        size: emulator_types::RvSize,
        addr: emulator_types::RvAddr,
        val: emulator_types::RvData,
    ) -> Result<(), emulator_bus::BusError> {
        match (size, addr) {
            (emulator_types::RvSize::Word, 0) => {
                self.periph.write_interrupt_state(
                    emulator_types::RvSize::Word,
                    emulator_bus::ReadWriteRegister::new(val),
                );
                Ok(())
            }
            (emulator_types::RvSize::Word, 1..=3) => {
                Err(emulator_bus::BusError::StoreAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 4) => {
                self.periph.write_interrupt_enable(
                    emulator_types::RvSize::Word,
                    emulator_bus::ReadWriteRegister::new(val),
                );
                Ok(())
            }
            (emulator_types::RvSize::Word, 5..=7) => {
                Err(emulator_bus::BusError::StoreAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 8) => {
                self.periph.write_interrupt_test(
                    emulator_types::RvSize::Word,
                    emulator_bus::ReadWriteRegister::new(val),
                );
                Ok(())
            }
            (emulator_types::RvSize::Word, 9..=0xb) => {
                Err(emulator_bus::BusError::StoreAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0xc) => {
                self.periph.write_alert_test(
                    emulator_types::RvSize::Word,
                    emulator_bus::ReadWriteRegister::new(val),
                );
                Ok(())
            }
            (emulator_types::RvSize::Word, 0xd..=0xf) => {
                Err(emulator_bus::BusError::StoreAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0x38) => {
                self.periph.write_direct_access_regwen(
                    emulator_types::RvSize::Word,
                    emulator_bus::ReadWriteRegister::new(val),
                );
                Ok(())
            }
            (emulator_types::RvSize::Word, 0x39..=0x3b) => {
                Err(emulator_bus::BusError::StoreAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0x3c) => {
                self.periph.write_direct_access_cmd(
                    emulator_types::RvSize::Word,
                    emulator_bus::ReadWriteRegister::new(val),
                );
                Ok(())
            }
            (emulator_types::RvSize::Word, 0x3d..=0x3f) => {
                Err(emulator_bus::BusError::StoreAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0x40) => {
                self.periph.write_direct_access_address(
                    emulator_types::RvSize::Word,
                    emulator_bus::ReadWriteRegister::new(val),
                );
                Ok(())
            }
            (emulator_types::RvSize::Word, 0x41..=0x43) => {
                Err(emulator_bus::BusError::StoreAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0x54) => {
                self.periph.write_check_trigger_regwen(
                    emulator_types::RvSize::Word,
                    emulator_bus::ReadWriteRegister::new(val),
                );
                Ok(())
            }
            (emulator_types::RvSize::Word, 0x55..=0x57) => {
                Err(emulator_bus::BusError::StoreAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0x58) => {
                self.periph.write_check_trigger(
                    emulator_types::RvSize::Word,
                    emulator_bus::ReadWriteRegister::new(val),
                );
                Ok(())
            }
            (emulator_types::RvSize::Word, 0x59..=0x5b) => {
                Err(emulator_bus::BusError::StoreAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0x5c) => {
                self.periph.write_check_regwen(
                    emulator_types::RvSize::Word,
                    emulator_bus::ReadWriteRegister::new(val),
                );
                Ok(())
            }
            (emulator_types::RvSize::Word, 0x5d..=0x5f) => {
                Err(emulator_bus::BusError::StoreAddrMisaligned)
            }
            (size, 0x60) => {
                self.periph.write_check_timeout(size, val);
                Ok(())
            }
            (_, 0x61..=0x63) => Err(emulator_bus::BusError::StoreAddrMisaligned),
            (size, 0x64) => {
                self.periph.write_integrity_check_period(size, val);
                Ok(())
            }
            (_, 0x65..=0x67) => Err(emulator_bus::BusError::StoreAddrMisaligned),
            (size, 0x68) => {
                self.periph.write_consistency_check_period(size, val);
                Ok(())
            }
            (_, 0x69..=0x6b) => Err(emulator_bus::BusError::StoreAddrMisaligned),
            (emulator_types::RvSize::Word, 0x6c) => {
                self.periph.write_vendor_test_read_lock(
                    emulator_types::RvSize::Word,
                    emulator_bus::ReadWriteRegister::new(val),
                );
                Ok(())
            }
            (emulator_types::RvSize::Word, 0x6d..=0x6f) => {
                Err(emulator_bus::BusError::StoreAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0x70) => {
                self.periph.write_non_secret_fuses_read_lock(
                    emulator_types::RvSize::Word,
                    emulator_bus::ReadWriteRegister::new(val),
                );
                Ok(())
            }
            (emulator_types::RvSize::Word, 0x71..=0x73) => {
                Err(emulator_bus::BusError::StoreAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0xa4) => {
                self.periph.write_csr0(
                    emulator_types::RvSize::Word,
                    emulator_bus::ReadWriteRegister::new(val),
                );
                Ok(())
            }
            (emulator_types::RvSize::Word, 0xa5..=0xa7) => {
                Err(emulator_bus::BusError::StoreAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0xa8) => {
                self.periph.write_csr1(
                    emulator_types::RvSize::Word,
                    emulator_bus::ReadWriteRegister::new(val),
                );
                Ok(())
            }
            (emulator_types::RvSize::Word, 0xa9..=0xab) => {
                Err(emulator_bus::BusError::StoreAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0xac) => {
                self.periph.write_csr2(
                    emulator_types::RvSize::Word,
                    emulator_bus::ReadWriteRegister::new(val),
                );
                Ok(())
            }
            (emulator_types::RvSize::Word, 0xad..=0xaf) => {
                Err(emulator_bus::BusError::StoreAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0xb0) => {
                self.periph.write_csr3(
                    emulator_types::RvSize::Word,
                    emulator_bus::ReadWriteRegister::new(val),
                );
                Ok(())
            }
            (emulator_types::RvSize::Word, 0xb1..=0xb3) => {
                Err(emulator_bus::BusError::StoreAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0xb4) => {
                self.periph.write_csr4(
                    emulator_types::RvSize::Word,
                    emulator_bus::ReadWriteRegister::new(val),
                );
                Ok(())
            }
            (emulator_types::RvSize::Word, 0xb5..=0xb7) => {
                Err(emulator_bus::BusError::StoreAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0xb8) => {
                self.periph.write_csr5(
                    emulator_types::RvSize::Word,
                    emulator_bus::ReadWriteRegister::new(val),
                );
                Ok(())
            }
            (emulator_types::RvSize::Word, 0xb9..=0xbb) => {
                Err(emulator_bus::BusError::StoreAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0xbc) => {
                self.periph.write_csr6(
                    emulator_types::RvSize::Word,
                    emulator_bus::ReadWriteRegister::new(val),
                );
                Ok(())
            }
            (emulator_types::RvSize::Word, 0xbd..=0xbf) => {
                Err(emulator_bus::BusError::StoreAddrMisaligned)
            }
            (size, 0x44) => {
                self.periph
                    .write_dai_wdata_rf_direct_access_wdata_0(size, val);
                Ok(())
            }
            (_, 0x45..=0x47) => Err(emulator_bus::BusError::StoreAddrMisaligned),
            (size, 0x48) => {
                self.periph
                    .write_dai_wdata_rf_direct_access_wdata_1(size, val);
                Ok(())
            }
            (_, 0x49..=0x4b) => Err(emulator_bus::BusError::StoreAddrMisaligned),
            _ => Err(emulator_bus::BusError::StoreAccessFault),
        }
    }
    fn poll(&mut self) {
        self.periph.poll();
    }
    fn warm_reset(&mut self) {
        self.periph.warm_reset();
    }
    fn update_reset(&mut self) {
        self.periph.update_reset();
    }
}
