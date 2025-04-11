// Licensed under the Apache-2.0 license.
//
// generated by registers_generator with caliptra-ss repo at 4f006115433f926f4e599bc8718a39168f70ce5f
//
//
// Warning: caliptra-ss was dirty:?? src/integration/rtl/html/
//
#[allow(unused_imports)]
use tock_registers::interfaces::{Readable, Writeable};
pub trait Sha512AccPeripheral {
    fn set_dma_ram(&mut self, _ram: std::rc::Rc<std::cell::RefCell<emulator_bus::Ram>>) {}
    fn poll(&mut self) {}
    fn warm_reset(&mut self) {}
    fn update_reset(&mut self) {}
    fn read_lock(
        &mut self,
    ) -> emulator_bus::ReadWriteRegister<u32, registers_generated::sha512_acc::bits::Lock::Register>
    {
        emulator_bus::ReadWriteRegister::new(0)
    }
    fn write_lock(
        &mut self,
        _val: emulator_bus::ReadWriteRegister<
            u32,
            registers_generated::sha512_acc::bits::Lock::Register,
        >,
    ) {
    }
    fn read_user(&mut self) -> caliptra_emu_types::RvData {
        0
    }
    fn read_mode(
        &mut self,
    ) -> emulator_bus::ReadWriteRegister<u32, registers_generated::sha512_acc::bits::Mode::Register>
    {
        emulator_bus::ReadWriteRegister::new(0)
    }
    fn write_mode(
        &mut self,
        _val: emulator_bus::ReadWriteRegister<
            u32,
            registers_generated::sha512_acc::bits::Mode::Register,
        >,
    ) {
    }
    fn read_start_address(&mut self) -> caliptra_emu_types::RvData {
        0
    }
    fn write_start_address(&mut self, _val: caliptra_emu_types::RvData) {}
    fn read_dlen(&mut self) -> caliptra_emu_types::RvData {
        0
    }
    fn write_dlen(&mut self, _val: caliptra_emu_types::RvData) {}
    fn read_datain(&mut self) -> caliptra_emu_types::RvData {
        0
    }
    fn write_datain(&mut self, _val: caliptra_emu_types::RvData) {}
    fn read_execute(
        &mut self,
    ) -> emulator_bus::ReadWriteRegister<
        u32,
        registers_generated::sha512_acc::bits::Execute::Register,
    > {
        emulator_bus::ReadWriteRegister::new(0)
    }
    fn write_execute(
        &mut self,
        _val: emulator_bus::ReadWriteRegister<
            u32,
            registers_generated::sha512_acc::bits::Execute::Register,
        >,
    ) {
    }
    fn read_status(
        &mut self,
    ) -> emulator_bus::ReadWriteRegister<u32, registers_generated::lc_ctrl::bits::Status::Register>
    {
        emulator_bus::ReadWriteRegister::new(0)
    }
    fn read_digest(&mut self) -> caliptra_emu_types::RvData {
        0
    }
    fn read_control(
        &mut self,
    ) -> emulator_bus::ReadWriteRegister<
        u32,
        registers_generated::sha512_acc::bits::Control::Register,
    > {
        emulator_bus::ReadWriteRegister::new(0)
    }
    fn write_control(
        &mut self,
        _val: emulator_bus::ReadWriteRegister<
            u32,
            registers_generated::sha512_acc::bits::Control::Register,
        >,
    ) {
    }
    fn read_intr_block_rf_global_intr_en_r(
        &mut self,
    ) -> emulator_bus::ReadWriteRegister<
        u32,
        registers_generated::sha512_acc::bits::GlobalIntrEnT::Register,
    > {
        emulator_bus::ReadWriteRegister::new(0)
    }
    fn write_intr_block_rf_global_intr_en_r(
        &mut self,
        _val: emulator_bus::ReadWriteRegister<
            u32,
            registers_generated::sha512_acc::bits::GlobalIntrEnT::Register,
        >,
    ) {
    }
    fn read_intr_block_rf_error_intr_en_r(
        &mut self,
    ) -> emulator_bus::ReadWriteRegister<
        u32,
        registers_generated::sha512_acc::bits::ErrorIntrEnT::Register,
    > {
        emulator_bus::ReadWriteRegister::new(0)
    }
    fn write_intr_block_rf_error_intr_en_r(
        &mut self,
        _val: emulator_bus::ReadWriteRegister<
            u32,
            registers_generated::sha512_acc::bits::ErrorIntrEnT::Register,
        >,
    ) {
    }
    fn read_intr_block_rf_notif_intr_en_r(
        &mut self,
    ) -> emulator_bus::ReadWriteRegister<
        u32,
        registers_generated::sha512_acc::bits::NotifIntrEnT::Register,
    > {
        emulator_bus::ReadWriteRegister::new(0)
    }
    fn write_intr_block_rf_notif_intr_en_r(
        &mut self,
        _val: emulator_bus::ReadWriteRegister<
            u32,
            registers_generated::sha512_acc::bits::NotifIntrEnT::Register,
        >,
    ) {
    }
    fn read_intr_block_rf_error_global_intr_r(
        &mut self,
    ) -> emulator_bus::ReadWriteRegister<
        u32,
        registers_generated::sha512_acc::bits::GlobalIntrT::Register,
    > {
        emulator_bus::ReadWriteRegister::new(0)
    }
    fn read_intr_block_rf_notif_global_intr_r(
        &mut self,
    ) -> emulator_bus::ReadWriteRegister<
        u32,
        registers_generated::sha512_acc::bits::GlobalIntrT::Register,
    > {
        emulator_bus::ReadWriteRegister::new(0)
    }
    fn read_intr_block_rf_error_internal_intr_r(
        &mut self,
    ) -> emulator_bus::ReadWriteRegister<
        u32,
        registers_generated::sha512_acc::bits::ErrorIntrT::Register,
    > {
        emulator_bus::ReadWriteRegister::new(0)
    }
    fn write_intr_block_rf_error_internal_intr_r(
        &mut self,
        _val: emulator_bus::ReadWriteRegister<
            u32,
            registers_generated::sha512_acc::bits::ErrorIntrT::Register,
        >,
    ) {
    }
    fn read_intr_block_rf_notif_internal_intr_r(
        &mut self,
    ) -> emulator_bus::ReadWriteRegister<
        u32,
        registers_generated::sha512_acc::bits::NotifIntrT::Register,
    > {
        emulator_bus::ReadWriteRegister::new(0)
    }
    fn write_intr_block_rf_notif_internal_intr_r(
        &mut self,
        _val: emulator_bus::ReadWriteRegister<
            u32,
            registers_generated::sha512_acc::bits::NotifIntrT::Register,
        >,
    ) {
    }
    fn read_intr_block_rf_error_intr_trig_r(
        &mut self,
    ) -> emulator_bus::ReadWriteRegister<
        u32,
        registers_generated::sha512_acc::bits::ErrorIntrTrigT::Register,
    > {
        emulator_bus::ReadWriteRegister::new(0)
    }
    fn write_intr_block_rf_error_intr_trig_r(
        &mut self,
        _val: emulator_bus::ReadWriteRegister<
            u32,
            registers_generated::sha512_acc::bits::ErrorIntrTrigT::Register,
        >,
    ) {
    }
    fn read_intr_block_rf_notif_intr_trig_r(
        &mut self,
    ) -> emulator_bus::ReadWriteRegister<
        u32,
        registers_generated::sha512_acc::bits::NotifIntrTrigT::Register,
    > {
        emulator_bus::ReadWriteRegister::new(0)
    }
    fn write_intr_block_rf_notif_intr_trig_r(
        &mut self,
        _val: emulator_bus::ReadWriteRegister<
            u32,
            registers_generated::sha512_acc::bits::NotifIntrTrigT::Register,
        >,
    ) {
    }
    fn read_intr_block_rf_error0_intr_count_r(&mut self) -> caliptra_emu_types::RvData {
        0
    }
    fn write_intr_block_rf_error0_intr_count_r(&mut self, _val: caliptra_emu_types::RvData) {}
    fn read_intr_block_rf_error1_intr_count_r(&mut self) -> caliptra_emu_types::RvData {
        0
    }
    fn write_intr_block_rf_error1_intr_count_r(&mut self, _val: caliptra_emu_types::RvData) {}
    fn read_intr_block_rf_error2_intr_count_r(&mut self) -> caliptra_emu_types::RvData {
        0
    }
    fn write_intr_block_rf_error2_intr_count_r(&mut self, _val: caliptra_emu_types::RvData) {}
    fn read_intr_block_rf_error3_intr_count_r(&mut self) -> caliptra_emu_types::RvData {
        0
    }
    fn write_intr_block_rf_error3_intr_count_r(&mut self, _val: caliptra_emu_types::RvData) {}
    fn read_intr_block_rf_notif_cmd_done_intr_count_r(&mut self) -> caliptra_emu_types::RvData {
        0
    }
    fn write_intr_block_rf_notif_cmd_done_intr_count_r(
        &mut self,
        _val: caliptra_emu_types::RvData,
    ) {
    }
    fn read_intr_block_rf_error0_intr_count_incr_r(
        &mut self,
    ) -> emulator_bus::ReadWriteRegister<
        u32,
        registers_generated::sha512_acc::bits::IntrCountIncrT::Register,
    > {
        emulator_bus::ReadWriteRegister::new(0)
    }
    fn read_intr_block_rf_error1_intr_count_incr_r(
        &mut self,
    ) -> emulator_bus::ReadWriteRegister<
        u32,
        registers_generated::sha512_acc::bits::IntrCountIncrT::Register,
    > {
        emulator_bus::ReadWriteRegister::new(0)
    }
    fn read_intr_block_rf_error2_intr_count_incr_r(
        &mut self,
    ) -> emulator_bus::ReadWriteRegister<
        u32,
        registers_generated::sha512_acc::bits::IntrCountIncrT::Register,
    > {
        emulator_bus::ReadWriteRegister::new(0)
    }
    fn read_intr_block_rf_error3_intr_count_incr_r(
        &mut self,
    ) -> emulator_bus::ReadWriteRegister<
        u32,
        registers_generated::sha512_acc::bits::IntrCountIncrT::Register,
    > {
        emulator_bus::ReadWriteRegister::new(0)
    }
    fn read_intr_block_rf_notif_cmd_done_intr_count_incr_r(
        &mut self,
    ) -> emulator_bus::ReadWriteRegister<
        u32,
        registers_generated::sha512_acc::bits::IntrCountIncrT::Register,
    > {
        emulator_bus::ReadWriteRegister::new(0)
    }
}
pub struct Sha512AccBus {
    pub periph: Box<dyn Sha512AccPeripheral>,
}
impl emulator_bus::Bus for Sha512AccBus {
    fn read(
        &mut self,
        size: caliptra_emu_types::RvSize,
        addr: caliptra_emu_types::RvAddr,
    ) -> Result<caliptra_emu_types::RvData, emulator_bus::BusError> {
        if addr & 0x3 != 0 || size != caliptra_emu_types::RvSize::Word {
            return Err(emulator_bus::BusError::LoadAddrMisaligned);
        }
        match addr {
            0..4 => Ok(caliptra_emu_types::RvData::from(
                self.periph.read_lock().reg.get(),
            )),
            4..8 => Ok(self.periph.read_user()),
            8..0xc => Ok(caliptra_emu_types::RvData::from(
                self.periph.read_mode().reg.get(),
            )),
            0xc..0x10 => Ok(self.periph.read_start_address()),
            0x10..0x14 => Ok(self.periph.read_dlen()),
            0x14..0x18 => Ok(self.periph.read_datain()),
            0x18..0x1c => Ok(caliptra_emu_types::RvData::from(
                self.periph.read_execute().reg.get(),
            )),
            0x1c..0x20 => Ok(caliptra_emu_types::RvData::from(
                self.periph.read_status().reg.get(),
            )),
            0x20..0x60 => Ok(self.periph.read_digest()),
            0x60..0x64 => Ok(caliptra_emu_types::RvData::from(
                self.periph.read_control().reg.get(),
            )),
            0x800..0x804 => Ok(caliptra_emu_types::RvData::from(
                self.periph.read_intr_block_rf_global_intr_en_r().reg.get(),
            )),
            0x804..0x808 => Ok(caliptra_emu_types::RvData::from(
                self.periph.read_intr_block_rf_error_intr_en_r().reg.get(),
            )),
            0x808..0x80c => Ok(caliptra_emu_types::RvData::from(
                self.periph.read_intr_block_rf_notif_intr_en_r().reg.get(),
            )),
            0x80c..0x810 => Ok(caliptra_emu_types::RvData::from(
                self.periph
                    .read_intr_block_rf_error_global_intr_r()
                    .reg
                    .get(),
            )),
            0x810..0x814 => Ok(caliptra_emu_types::RvData::from(
                self.periph
                    .read_intr_block_rf_notif_global_intr_r()
                    .reg
                    .get(),
            )),
            0x814..0x818 => Ok(caliptra_emu_types::RvData::from(
                self.periph
                    .read_intr_block_rf_error_internal_intr_r()
                    .reg
                    .get(),
            )),
            0x818..0x81c => Ok(caliptra_emu_types::RvData::from(
                self.periph
                    .read_intr_block_rf_notif_internal_intr_r()
                    .reg
                    .get(),
            )),
            0x81c..0x820 => Ok(caliptra_emu_types::RvData::from(
                self.periph.read_intr_block_rf_error_intr_trig_r().reg.get(),
            )),
            0x820..0x824 => Ok(caliptra_emu_types::RvData::from(
                self.periph.read_intr_block_rf_notif_intr_trig_r().reg.get(),
            )),
            0x900..0x904 => Ok(self.periph.read_intr_block_rf_error0_intr_count_r()),
            0x904..0x908 => Ok(self.periph.read_intr_block_rf_error1_intr_count_r()),
            0x908..0x90c => Ok(self.periph.read_intr_block_rf_error2_intr_count_r()),
            0x90c..0x910 => Ok(self.periph.read_intr_block_rf_error3_intr_count_r()),
            0x980..0x984 => Ok(self.periph.read_intr_block_rf_notif_cmd_done_intr_count_r()),
            0xa00..0xa04 => Ok(caliptra_emu_types::RvData::from(
                self.periph
                    .read_intr_block_rf_error0_intr_count_incr_r()
                    .reg
                    .get(),
            )),
            0xa04..0xa08 => Ok(caliptra_emu_types::RvData::from(
                self.periph
                    .read_intr_block_rf_error1_intr_count_incr_r()
                    .reg
                    .get(),
            )),
            0xa08..0xa0c => Ok(caliptra_emu_types::RvData::from(
                self.periph
                    .read_intr_block_rf_error2_intr_count_incr_r()
                    .reg
                    .get(),
            )),
            0xa0c..0xa10 => Ok(caliptra_emu_types::RvData::from(
                self.periph
                    .read_intr_block_rf_error3_intr_count_incr_r()
                    .reg
                    .get(),
            )),
            0xa10..0xa14 => Ok(caliptra_emu_types::RvData::from(
                self.periph
                    .read_intr_block_rf_notif_cmd_done_intr_count_incr_r()
                    .reg
                    .get(),
            )),
            _ => Err(emulator_bus::BusError::LoadAccessFault),
        }
    }
    fn write(
        &mut self,
        size: caliptra_emu_types::RvSize,
        addr: caliptra_emu_types::RvAddr,
        val: caliptra_emu_types::RvData,
    ) -> Result<(), emulator_bus::BusError> {
        if addr & 0x3 != 0 || size != caliptra_emu_types::RvSize::Word {
            return Err(emulator_bus::BusError::StoreAddrMisaligned);
        }
        match addr {
            0..4 => {
                self.periph
                    .write_lock(emulator_bus::ReadWriteRegister::new(val));
                Ok(())
            }
            8..0xc => {
                self.periph
                    .write_mode(emulator_bus::ReadWriteRegister::new(val));
                Ok(())
            }
            0xc..0x10 => {
                self.periph.write_start_address(val);
                Ok(())
            }
            0x10..0x14 => {
                self.periph.write_dlen(val);
                Ok(())
            }
            0x14..0x18 => {
                self.periph.write_datain(val);
                Ok(())
            }
            0x18..0x1c => {
                self.periph
                    .write_execute(emulator_bus::ReadWriteRegister::new(val));
                Ok(())
            }
            0x60..0x64 => {
                self.periph
                    .write_control(emulator_bus::ReadWriteRegister::new(val));
                Ok(())
            }
            0x800..0x804 => {
                self.periph.write_intr_block_rf_global_intr_en_r(
                    emulator_bus::ReadWriteRegister::new(val),
                );
                Ok(())
            }
            0x804..0x808 => {
                self.periph
                    .write_intr_block_rf_error_intr_en_r(emulator_bus::ReadWriteRegister::new(val));
                Ok(())
            }
            0x808..0x80c => {
                self.periph
                    .write_intr_block_rf_notif_intr_en_r(emulator_bus::ReadWriteRegister::new(val));
                Ok(())
            }
            0x814..0x818 => {
                self.periph.write_intr_block_rf_error_internal_intr_r(
                    emulator_bus::ReadWriteRegister::new(val),
                );
                Ok(())
            }
            0x818..0x81c => {
                self.periph.write_intr_block_rf_notif_internal_intr_r(
                    emulator_bus::ReadWriteRegister::new(val),
                );
                Ok(())
            }
            0x81c..0x820 => {
                self.periph.write_intr_block_rf_error_intr_trig_r(
                    emulator_bus::ReadWriteRegister::new(val),
                );
                Ok(())
            }
            0x820..0x824 => {
                self.periph.write_intr_block_rf_notif_intr_trig_r(
                    emulator_bus::ReadWriteRegister::new(val),
                );
                Ok(())
            }
            0x900..0x904 => {
                self.periph.write_intr_block_rf_error0_intr_count_r(val);
                Ok(())
            }
            0x904..0x908 => {
                self.periph.write_intr_block_rf_error1_intr_count_r(val);
                Ok(())
            }
            0x908..0x90c => {
                self.periph.write_intr_block_rf_error2_intr_count_r(val);
                Ok(())
            }
            0x90c..0x910 => {
                self.periph.write_intr_block_rf_error3_intr_count_r(val);
                Ok(())
            }
            0x980..0x984 => {
                self.periph
                    .write_intr_block_rf_notif_cmd_done_intr_count_r(val);
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
