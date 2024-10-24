// Licensed under the Apache-2.0 license.
//
// generated by registers_generator with caliptra-rtl repo at 0e43b8e7011c1c8761e114bc949fcad6cf30538e
// , caliptra-ss repo at 9911c2b0e4bac9e4b48f6c2155c86cb116159734
// , and i3c-core repo at d5c715103f529ade0e5d375a53c5692daaa9c54b
//
#[allow(unused_imports)]
use tock_registers::interfaces::{Readable, Writeable};
pub trait El2PicPeripheral {
    fn poll(&mut self) {}
    fn warm_reset(&mut self) {}
    fn update_reset(&mut self) {}
    fn read_meipl(
        &mut self,
    ) -> emulator_bus::ReadWriteRegister<
        u32,
        registers_generated::el2_pic_ctrl::bits::Meipl::Register,
    > {
        emulator_bus::ReadWriteRegister::new(0)
    }
    fn write_meipl(
        &mut self,
        _val: emulator_bus::ReadWriteRegister<
            u32,
            registers_generated::el2_pic_ctrl::bits::Meipl::Register,
        >,
    ) {
    }
    fn read_meip(
        &mut self,
    ) -> emulator_bus::ReadWriteRegister<u32, registers_generated::el2_pic_ctrl::bits::Meip::Register>
    {
        emulator_bus::ReadWriteRegister::new(0)
    }
    fn write_meip(
        &mut self,
        _val: emulator_bus::ReadWriteRegister<
            u32,
            registers_generated::el2_pic_ctrl::bits::Meip::Register,
        >,
    ) {
    }
    fn read_meie(
        &mut self,
    ) -> emulator_bus::ReadWriteRegister<u32, registers_generated::el2_pic_ctrl::bits::Meie::Register>
    {
        emulator_bus::ReadWriteRegister::new(0)
    }
    fn write_meie(
        &mut self,
        _val: emulator_bus::ReadWriteRegister<
            u32,
            registers_generated::el2_pic_ctrl::bits::Meie::Register,
        >,
    ) {
    }
    fn read_mpiccfg(
        &mut self,
    ) -> emulator_bus::ReadWriteRegister<
        u32,
        registers_generated::el2_pic_ctrl::bits::Mpiccfg::Register,
    > {
        emulator_bus::ReadWriteRegister::new(0)
    }
    fn write_mpiccfg(
        &mut self,
        _val: emulator_bus::ReadWriteRegister<
            u32,
            registers_generated::el2_pic_ctrl::bits::Mpiccfg::Register,
        >,
    ) {
    }
    fn read_meigwctrl(
        &mut self,
    ) -> emulator_bus::ReadWriteRegister<
        u32,
        registers_generated::el2_pic_ctrl::bits::Meigwctrl::Register,
    > {
        emulator_bus::ReadWriteRegister::new(0)
    }
    fn write_meigwctrl(
        &mut self,
        _val: emulator_bus::ReadWriteRegister<
            u32,
            registers_generated::el2_pic_ctrl::bits::Meigwctrl::Register,
        >,
    ) {
    }
    fn read_meigwclr(&mut self) -> u32 {
        0
    }
    fn write_meigwclr(&mut self, _val: u32) {}
}
pub struct El2PicBus {
    pub periph: Box<dyn El2PicPeripheral>,
}
impl emulator_bus::Bus for El2PicBus {
    fn read(
        &mut self,
        size: emulator_types::RvSize,
        addr: emulator_types::RvAddr,
    ) -> Result<emulator_types::RvData, emulator_bus::BusError> {
        match (size, addr) {
            (emulator_types::RvSize::Word, 0) => Ok(emulator_types::RvData::from(
                self.periph.read_meipl().reg.get(),
            )),
            (emulator_types::RvSize::Word, 1..=3) => {
                Err(emulator_bus::BusError::LoadAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0x1000) => Ok(emulator_types::RvData::from(
                self.periph.read_meip().reg.get(),
            )),
            (emulator_types::RvSize::Word, 0x1001..=0x1003) => {
                Err(emulator_bus::BusError::LoadAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0x2000) => Ok(emulator_types::RvData::from(
                self.periph.read_meie().reg.get(),
            )),
            (emulator_types::RvSize::Word, 0x2001..=0x2003) => {
                Err(emulator_bus::BusError::LoadAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0x3000) => Ok(emulator_types::RvData::from(
                self.periph.read_mpiccfg().reg.get(),
            )),
            (emulator_types::RvSize::Word, 0x3001..=0x3003) => {
                Err(emulator_bus::BusError::LoadAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0x4000) => Ok(emulator_types::RvData::from(
                self.periph.read_meigwctrl().reg.get(),
            )),
            (emulator_types::RvSize::Word, 0x4001..=0x4003) => {
                Err(emulator_bus::BusError::LoadAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0x5000) => {
                Ok(emulator_types::RvData::from(self.periph.read_meigwclr()))
            }
            (emulator_types::RvSize::Word, 0x5001..=0x5003) => {
                Err(emulator_bus::BusError::LoadAddrMisaligned)
            }
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
                self.periph
                    .write_meipl(emulator_bus::ReadWriteRegister::new(val));
                Ok(())
            }
            (emulator_types::RvSize::Word, 1..=3) => {
                Err(emulator_bus::BusError::StoreAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0x1000) => {
                self.periph
                    .write_meip(emulator_bus::ReadWriteRegister::new(val));
                Ok(())
            }
            (emulator_types::RvSize::Word, 0x1001..=0x1003) => {
                Err(emulator_bus::BusError::StoreAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0x2000) => {
                self.periph
                    .write_meie(emulator_bus::ReadWriteRegister::new(val));
                Ok(())
            }
            (emulator_types::RvSize::Word, 0x2001..=0x2003) => {
                Err(emulator_bus::BusError::StoreAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0x3000) => {
                self.periph
                    .write_mpiccfg(emulator_bus::ReadWriteRegister::new(val));
                Ok(())
            }
            (emulator_types::RvSize::Word, 0x3001..=0x3003) => {
                Err(emulator_bus::BusError::StoreAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0x4000) => {
                self.periph
                    .write_meigwctrl(emulator_bus::ReadWriteRegister::new(val));
                Ok(())
            }
            (emulator_types::RvSize::Word, 0x4001..=0x4003) => {
                Err(emulator_bus::BusError::StoreAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0x5000) => {
                self.periph.write_meigwclr(val);
                Ok(())
            }
            (emulator_types::RvSize::Word, 0x5001..=0x5003) => {
                Err(emulator_bus::BusError::StoreAddrMisaligned)
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
