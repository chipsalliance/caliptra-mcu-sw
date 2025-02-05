// Licensed under the Apache-2.0 license.
//
// generated by registers_generator with caliptra-ss repo at 2ec4914686d656467fae8ff40ee7da03ee6f5ec3
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
    ) -> emulator_bus::ReadWriteRegister<
        u32,
        registers_generated::otp_ctrl::bits::InterruptState::Register,
    > {
        emulator_bus::ReadWriteRegister::new(0)
    }
    fn write_interrupt_state(
        &mut self,
        _val: emulator_bus::ReadWriteRegister<
            u32,
            registers_generated::otp_ctrl::bits::InterruptState::Register,
        >,
    ) {
    }
    fn read_interrupt_enable(
        &mut self,
    ) -> emulator_bus::ReadWriteRegister<
        u32,
        registers_generated::i3c::bits::InterruptEnable::Register,
    > {
        emulator_bus::ReadWriteRegister::new(0)
    }
    fn write_interrupt_enable(
        &mut self,
        _val: emulator_bus::ReadWriteRegister<
            u32,
            registers_generated::i3c::bits::InterruptEnable::Register,
        >,
    ) {
    }
    fn write_interrupt_test(
        &mut self,
        _val: emulator_bus::ReadWriteRegister<
            u32,
            registers_generated::otp_ctrl::bits::InterruptTest::Register,
        >,
    ) {
    }
    fn write_alert_test(
        &mut self,
        _val: emulator_bus::ReadWriteRegister<
            u32,
            registers_generated::otp_ctrl::bits::AlertTest::Register,
        >,
    ) {
    }
    fn read_status(
        &mut self,
    ) -> emulator_bus::ReadWriteRegister<u32, registers_generated::otp_ctrl::bits::Status::Register>
    {
        emulator_bus::ReadWriteRegister::new(0)
    }
    fn read_direct_access_regwen(
        &mut self,
    ) -> emulator_bus::ReadWriteRegister<
        u32,
        registers_generated::otp_ctrl::bits::DirectAccessRegwen::Register,
    > {
        emulator_bus::ReadWriteRegister::new(0)
    }
    fn write_direct_access_regwen(
        &mut self,
        _val: emulator_bus::ReadWriteRegister<
            u32,
            registers_generated::otp_ctrl::bits::DirectAccessRegwen::Register,
        >,
    ) {
    }
    fn write_direct_access_cmd(
        &mut self,
        _val: emulator_bus::ReadWriteRegister<
            u32,
            registers_generated::otp_ctrl::bits::DirectAccessCmd::Register,
        >,
    ) {
    }
    fn read_direct_access_address(
        &mut self,
    ) -> emulator_bus::ReadWriteRegister<
        u32,
        registers_generated::otp_ctrl::bits::DirectAccessAddress::Register,
    > {
        emulator_bus::ReadWriteRegister::new(0)
    }
    fn write_direct_access_address(
        &mut self,
        _val: emulator_bus::ReadWriteRegister<
            u32,
            registers_generated::otp_ctrl::bits::DirectAccessAddress::Register,
        >,
    ) {
    }
    fn read_check_trigger_regwen(
        &mut self,
    ) -> emulator_bus::ReadWriteRegister<
        u32,
        registers_generated::otp_ctrl::bits::CheckTriggerRegwen::Register,
    > {
        emulator_bus::ReadWriteRegister::new(0)
    }
    fn write_check_trigger_regwen(
        &mut self,
        _val: emulator_bus::ReadWriteRegister<
            u32,
            registers_generated::otp_ctrl::bits::CheckTriggerRegwen::Register,
        >,
    ) {
    }
    fn write_check_trigger(
        &mut self,
        _val: emulator_bus::ReadWriteRegister<
            u32,
            registers_generated::otp_ctrl::bits::CheckTrigger::Register,
        >,
    ) {
    }
    fn write_check_regwen(
        &mut self,
        _val: emulator_bus::ReadWriteRegister<
            u32,
            registers_generated::otp_ctrl::bits::CheckRegwen::Register,
        >,
    ) {
    }
    fn read_check_timeout(&mut self) -> emulator_types::RvData {
        0
    }
    fn write_check_timeout(&mut self, _val: emulator_types::RvData) {}
    fn read_integrity_check_period(&mut self) -> emulator_types::RvData {
        0
    }
    fn write_integrity_check_period(&mut self, _val: emulator_types::RvData) {}
    fn read_consistency_check_period(&mut self) -> emulator_types::RvData {
        0
    }
    fn write_consistency_check_period(&mut self, _val: emulator_types::RvData) {}
    fn read_vendor_test_read_lock(
        &mut self,
    ) -> emulator_bus::ReadWriteRegister<
        u32,
        registers_generated::otp_ctrl::bits::VendorTestReadLock::Register,
    > {
        emulator_bus::ReadWriteRegister::new(0)
    }
    fn write_vendor_test_read_lock(
        &mut self,
        _val: emulator_bus::ReadWriteRegister<
            u32,
            registers_generated::otp_ctrl::bits::VendorTestReadLock::Register,
        >,
    ) {
    }
    fn read_non_secret_fuses_read_lock(
        &mut self,
    ) -> emulator_bus::ReadWriteRegister<
        u32,
        registers_generated::otp_ctrl::bits::NonSecretFusesReadLock::Register,
    > {
        emulator_bus::ReadWriteRegister::new(0)
    }
    fn write_non_secret_fuses_read_lock(
        &mut self,
        _val: emulator_bus::ReadWriteRegister<
            u32,
            registers_generated::otp_ctrl::bits::NonSecretFusesReadLock::Register,
        >,
    ) {
    }
    fn read_csr0(
        &mut self,
    ) -> emulator_bus::ReadWriteRegister<u32, registers_generated::otp_ctrl::bits::Csr0::Register>
    {
        emulator_bus::ReadWriteRegister::new(0)
    }
    fn write_csr0(
        &mut self,
        _val: emulator_bus::ReadWriteRegister<
            u32,
            registers_generated::otp_ctrl::bits::Csr0::Register,
        >,
    ) {
    }
    fn read_csr1(
        &mut self,
    ) -> emulator_bus::ReadWriteRegister<u32, registers_generated::otp_ctrl::bits::Csr1::Register>
    {
        emulator_bus::ReadWriteRegister::new(0)
    }
    fn write_csr1(
        &mut self,
        _val: emulator_bus::ReadWriteRegister<
            u32,
            registers_generated::otp_ctrl::bits::Csr1::Register,
        >,
    ) {
    }
    fn read_csr2(
        &mut self,
    ) -> emulator_bus::ReadWriteRegister<u32, registers_generated::otp_ctrl::bits::Csr2::Register>
    {
        emulator_bus::ReadWriteRegister::new(0)
    }
    fn write_csr2(
        &mut self,
        _val: emulator_bus::ReadWriteRegister<
            u32,
            registers_generated::otp_ctrl::bits::Csr2::Register,
        >,
    ) {
    }
    fn read_csr3(
        &mut self,
    ) -> emulator_bus::ReadWriteRegister<u32, registers_generated::otp_ctrl::bits::Csr3::Register>
    {
        emulator_bus::ReadWriteRegister::new(0)
    }
    fn write_csr3(
        &mut self,
        _val: emulator_bus::ReadWriteRegister<
            u32,
            registers_generated::otp_ctrl::bits::Csr3::Register,
        >,
    ) {
    }
    fn read_csr4(
        &mut self,
    ) -> emulator_bus::ReadWriteRegister<u32, registers_generated::otp_ctrl::bits::Csr4::Register>
    {
        emulator_bus::ReadWriteRegister::new(0)
    }
    fn write_csr4(
        &mut self,
        _val: emulator_bus::ReadWriteRegister<
            u32,
            registers_generated::otp_ctrl::bits::Csr4::Register,
        >,
    ) {
    }
    fn read_csr5(
        &mut self,
    ) -> emulator_bus::ReadWriteRegister<u32, registers_generated::otp_ctrl::bits::Csr5::Register>
    {
        emulator_bus::ReadWriteRegister::new(0)
    }
    fn write_csr5(
        &mut self,
        _val: emulator_bus::ReadWriteRegister<
            u32,
            registers_generated::otp_ctrl::bits::Csr5::Register,
        >,
    ) {
    }
    fn read_csr6(
        &mut self,
    ) -> emulator_bus::ReadWriteRegister<u32, registers_generated::otp_ctrl::bits::Csr6::Register>
    {
        emulator_bus::ReadWriteRegister::new(0)
    }
    fn write_csr6(
        &mut self,
        _val: emulator_bus::ReadWriteRegister<
            u32,
            registers_generated::otp_ctrl::bits::Csr6::Register,
        >,
    ) {
    }
    fn read_csr7(
        &mut self,
    ) -> emulator_bus::ReadWriteRegister<u32, registers_generated::otp_ctrl::bits::Csr7::Register>
    {
        emulator_bus::ReadWriteRegister::new(0)
    }
    fn read_err_code_rf_err_code_0(
        &mut self,
    ) -> emulator_bus::ReadWriteRegister<
        u32,
        registers_generated::otp_ctrl::bits::ErrCodeRegT::Register,
    > {
        emulator_bus::ReadWriteRegister::new(0)
    }
    fn read_err_code_rf_err_code_1(
        &mut self,
    ) -> emulator_bus::ReadWriteRegister<
        u32,
        registers_generated::otp_ctrl::bits::ErrCodeRegT::Register,
    > {
        emulator_bus::ReadWriteRegister::new(0)
    }
    fn read_err_code_rf_err_code_2(
        &mut self,
    ) -> emulator_bus::ReadWriteRegister<
        u32,
        registers_generated::otp_ctrl::bits::ErrCodeRegT::Register,
    > {
        emulator_bus::ReadWriteRegister::new(0)
    }
    fn read_err_code_rf_err_code_3(
        &mut self,
    ) -> emulator_bus::ReadWriteRegister<
        u32,
        registers_generated::otp_ctrl::bits::ErrCodeRegT::Register,
    > {
        emulator_bus::ReadWriteRegister::new(0)
    }
    fn read_err_code_rf_err_code_4(
        &mut self,
    ) -> emulator_bus::ReadWriteRegister<
        u32,
        registers_generated::otp_ctrl::bits::ErrCodeRegT::Register,
    > {
        emulator_bus::ReadWriteRegister::new(0)
    }
    fn read_err_code_rf_err_code_5(
        &mut self,
    ) -> emulator_bus::ReadWriteRegister<
        u32,
        registers_generated::otp_ctrl::bits::ErrCodeRegT::Register,
    > {
        emulator_bus::ReadWriteRegister::new(0)
    }
    fn read_err_code_rf_err_code_6(
        &mut self,
    ) -> emulator_bus::ReadWriteRegister<
        u32,
        registers_generated::otp_ctrl::bits::ErrCodeRegT::Register,
    > {
        emulator_bus::ReadWriteRegister::new(0)
    }
    fn read_err_code_rf_err_code_7(
        &mut self,
    ) -> emulator_bus::ReadWriteRegister<
        u32,
        registers_generated::otp_ctrl::bits::ErrCodeRegT::Register,
    > {
        emulator_bus::ReadWriteRegister::new(0)
    }
    fn read_err_code_rf_err_code_8(
        &mut self,
    ) -> emulator_bus::ReadWriteRegister<
        u32,
        registers_generated::otp_ctrl::bits::ErrCodeRegT::Register,
    > {
        emulator_bus::ReadWriteRegister::new(0)
    }
    fn read_dai_wdata_rf_direct_access_wdata_0(&mut self) -> emulator_types::RvData {
        0
    }
    fn write_dai_wdata_rf_direct_access_wdata_0(&mut self, _val: emulator_types::RvData) {}
    fn read_dai_wdata_rf_direct_access_wdata_1(&mut self) -> emulator_types::RvData {
        0
    }
    fn write_dai_wdata_rf_direct_access_wdata_1(&mut self, _val: emulator_types::RvData) {}
    fn read_dai_rdata_rf_direct_access_rdata_0(&mut self) -> emulator_types::RvData {
        0
    }
    fn read_dai_rdata_rf_direct_access_rdata_1(&mut self) -> emulator_types::RvData {
        0
    }
    fn read_vendor_test_digest_digest_0(&mut self) -> emulator_types::RvData {
        0
    }
    fn read_vendor_test_digest_digest_1(&mut self) -> emulator_types::RvData {
        0
    }
    fn read_non_secret_fuses_digest_digest_0(&mut self) -> emulator_types::RvData {
        0
    }
    fn read_non_secret_fuses_digest_digest_1(&mut self) -> emulator_types::RvData {
        0
    }
    fn read_secret0_digest_digest_0(&mut self) -> emulator_types::RvData {
        0
    }
    fn read_secret0_digest_digest_1(&mut self) -> emulator_types::RvData {
        0
    }
    fn read_secret1_digest_digest_0(&mut self) -> emulator_types::RvData {
        0
    }
    fn read_secret1_digest_digest_1(&mut self) -> emulator_types::RvData {
        0
    }
    fn read_secret2_digest_digest_0(&mut self) -> emulator_types::RvData {
        0
    }
    fn read_secret2_digest_digest_1(&mut self) -> emulator_types::RvData {
        0
    }
    fn read_secret3_digest_digest_0(&mut self) -> emulator_types::RvData {
        0
    }
    fn read_secret3_digest_digest_1(&mut self) -> emulator_types::RvData {
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
        if addr & 0x3 != 0 || size != emulator_types::RvSize::Word {
            return Err(emulator_bus::BusError::LoadAddrMisaligned);
        }
        match addr {
            0..4 => Ok(emulator_types::RvData::from(
                self.periph.read_interrupt_state().reg.get(),
            )),
            4..8 => Ok(emulator_types::RvData::from(
                self.periph.read_interrupt_enable().reg.get(),
            )),
            0x10..0x14 => Ok(emulator_types::RvData::from(
                self.periph.read_status().reg.get(),
            )),
            0x38..0x3c => Ok(emulator_types::RvData::from(
                self.periph.read_direct_access_regwen().reg.get(),
            )),
            0x40..0x44 => Ok(emulator_types::RvData::from(
                self.periph.read_direct_access_address().reg.get(),
            )),
            0x54..0x58 => Ok(emulator_types::RvData::from(
                self.periph.read_check_trigger_regwen().reg.get(),
            )),
            0x60..0x64 => Ok(self.periph.read_check_timeout()),
            0x64..0x68 => Ok(self.periph.read_integrity_check_period()),
            0x68..0x6c => Ok(self.periph.read_consistency_check_period()),
            0x6c..0x70 => Ok(emulator_types::RvData::from(
                self.periph.read_vendor_test_read_lock().reg.get(),
            )),
            0x70..0x74 => Ok(emulator_types::RvData::from(
                self.periph.read_non_secret_fuses_read_lock().reg.get(),
            )),
            0xa4..0xa8 => Ok(emulator_types::RvData::from(
                self.periph.read_csr0().reg.get(),
            )),
            0xa8..0xac => Ok(emulator_types::RvData::from(
                self.periph.read_csr1().reg.get(),
            )),
            0xac..0xb0 => Ok(emulator_types::RvData::from(
                self.periph.read_csr2().reg.get(),
            )),
            0xb0..0xb4 => Ok(emulator_types::RvData::from(
                self.periph.read_csr3().reg.get(),
            )),
            0xb4..0xb8 => Ok(emulator_types::RvData::from(
                self.periph.read_csr4().reg.get(),
            )),
            0xb8..0xbc => Ok(emulator_types::RvData::from(
                self.periph.read_csr5().reg.get(),
            )),
            0xbc..0xc0 => Ok(emulator_types::RvData::from(
                self.periph.read_csr6().reg.get(),
            )),
            0xc0..0xc4 => Ok(emulator_types::RvData::from(
                self.periph.read_csr7().reg.get(),
            )),
            0x14..0x18 => Ok(emulator_types::RvData::from(
                self.periph.read_err_code_rf_err_code_0().reg.get(),
            )),
            0x18..0x1c => Ok(emulator_types::RvData::from(
                self.periph.read_err_code_rf_err_code_1().reg.get(),
            )),
            0x1c..0x20 => Ok(emulator_types::RvData::from(
                self.periph.read_err_code_rf_err_code_2().reg.get(),
            )),
            0x20..0x24 => Ok(emulator_types::RvData::from(
                self.periph.read_err_code_rf_err_code_3().reg.get(),
            )),
            0x24..0x28 => Ok(emulator_types::RvData::from(
                self.periph.read_err_code_rf_err_code_4().reg.get(),
            )),
            0x28..0x2c => Ok(emulator_types::RvData::from(
                self.periph.read_err_code_rf_err_code_5().reg.get(),
            )),
            0x2c..0x30 => Ok(emulator_types::RvData::from(
                self.periph.read_err_code_rf_err_code_6().reg.get(),
            )),
            0x30..0x34 => Ok(emulator_types::RvData::from(
                self.periph.read_err_code_rf_err_code_7().reg.get(),
            )),
            0x34..0x38 => Ok(emulator_types::RvData::from(
                self.periph.read_err_code_rf_err_code_8().reg.get(),
            )),
            0x44..0x48 => Ok(self.periph.read_dai_wdata_rf_direct_access_wdata_0()),
            0x48..0x4c => Ok(self.periph.read_dai_wdata_rf_direct_access_wdata_1()),
            0x4c..0x50 => Ok(self.periph.read_dai_rdata_rf_direct_access_rdata_0()),
            0x50..0x54 => Ok(self.periph.read_dai_rdata_rf_direct_access_rdata_1()),
            0x74..0x78 => Ok(self.periph.read_vendor_test_digest_digest_0()),
            0x78..0x7c => Ok(self.periph.read_vendor_test_digest_digest_1()),
            0x7c..0x80 => Ok(self.periph.read_non_secret_fuses_digest_digest_0()),
            0x80..0x84 => Ok(self.periph.read_non_secret_fuses_digest_digest_1()),
            0x84..0x88 => Ok(self.periph.read_secret0_digest_digest_0()),
            0x88..0x8c => Ok(self.periph.read_secret0_digest_digest_1()),
            0x8c..0x90 => Ok(self.periph.read_secret1_digest_digest_0()),
            0x90..0x94 => Ok(self.periph.read_secret1_digest_digest_1()),
            0x94..0x98 => Ok(self.periph.read_secret2_digest_digest_0()),
            0x98..0x9c => Ok(self.periph.read_secret2_digest_digest_1()),
            0x9c..0xa0 => Ok(self.periph.read_secret3_digest_digest_0()),
            0xa0..0xa4 => Ok(self.periph.read_secret3_digest_digest_1()),
            _ => Err(emulator_bus::BusError::LoadAccessFault),
        }
    }
    fn write(
        &mut self,
        size: emulator_types::RvSize,
        addr: emulator_types::RvAddr,
        val: emulator_types::RvData,
    ) -> Result<(), emulator_bus::BusError> {
        if addr & 0x3 != 0 || size != emulator_types::RvSize::Word {
            return Err(emulator_bus::BusError::StoreAddrMisaligned);
        }
        match addr {
            0..4 => {
                self.periph
                    .write_interrupt_state(emulator_bus::ReadWriteRegister::new(val));
                Ok(())
            }
            4..8 => {
                self.periph
                    .write_interrupt_enable(emulator_bus::ReadWriteRegister::new(val));
                Ok(())
            }
            8..0xc => {
                self.periph
                    .write_interrupt_test(emulator_bus::ReadWriteRegister::new(val));
                Ok(())
            }
            0xc..0x10 => {
                self.periph
                    .write_alert_test(emulator_bus::ReadWriteRegister::new(val));
                Ok(())
            }
            0x38..0x3c => {
                self.periph
                    .write_direct_access_regwen(emulator_bus::ReadWriteRegister::new(val));
                Ok(())
            }
            0x3c..0x40 => {
                self.periph
                    .write_direct_access_cmd(emulator_bus::ReadWriteRegister::new(val));
                Ok(())
            }
            0x40..0x44 => {
                self.periph
                    .write_direct_access_address(emulator_bus::ReadWriteRegister::new(val));
                Ok(())
            }
            0x54..0x58 => {
                self.periph
                    .write_check_trigger_regwen(emulator_bus::ReadWriteRegister::new(val));
                Ok(())
            }
            0x58..0x5c => {
                self.periph
                    .write_check_trigger(emulator_bus::ReadWriteRegister::new(val));
                Ok(())
            }
            0x5c..0x60 => {
                self.periph
                    .write_check_regwen(emulator_bus::ReadWriteRegister::new(val));
                Ok(())
            }
            0x60..0x64 => {
                self.periph.write_check_timeout(val);
                Ok(())
            }
            0x64..0x68 => {
                self.periph.write_integrity_check_period(val);
                Ok(())
            }
            0x68..0x6c => {
                self.periph.write_consistency_check_period(val);
                Ok(())
            }
            0x6c..0x70 => {
                self.periph
                    .write_vendor_test_read_lock(emulator_bus::ReadWriteRegister::new(val));
                Ok(())
            }
            0x70..0x74 => {
                self.periph
                    .write_non_secret_fuses_read_lock(emulator_bus::ReadWriteRegister::new(val));
                Ok(())
            }
            0xa4..0xa8 => {
                self.periph
                    .write_csr0(emulator_bus::ReadWriteRegister::new(val));
                Ok(())
            }
            0xa8..0xac => {
                self.periph
                    .write_csr1(emulator_bus::ReadWriteRegister::new(val));
                Ok(())
            }
            0xac..0xb0 => {
                self.periph
                    .write_csr2(emulator_bus::ReadWriteRegister::new(val));
                Ok(())
            }
            0xb0..0xb4 => {
                self.periph
                    .write_csr3(emulator_bus::ReadWriteRegister::new(val));
                Ok(())
            }
            0xb4..0xb8 => {
                self.periph
                    .write_csr4(emulator_bus::ReadWriteRegister::new(val));
                Ok(())
            }
            0xb8..0xbc => {
                self.periph
                    .write_csr5(emulator_bus::ReadWriteRegister::new(val));
                Ok(())
            }
            0xbc..0xc0 => {
                self.periph
                    .write_csr6(emulator_bus::ReadWriteRegister::new(val));
                Ok(())
            }
            0x44..0x48 => {
                self.periph.write_dai_wdata_rf_direct_access_wdata_0(val);
                Ok(())
            }
            0x48..0x4c => {
                self.periph.write_dai_wdata_rf_direct_access_wdata_1(val);
                Ok(())
            }
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
