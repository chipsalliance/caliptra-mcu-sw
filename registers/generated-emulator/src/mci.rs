// Licensed under the Apache-2.0 license.
//
// generated by registers_generator with caliptra-rtl repo at 0e43b8e7011c1c8761e114bc949fcad6cf30538e
// , caliptra-ss repo at 9911c2b0e4bac9e4b48f6c2155c86cb116159734
// , and i3c-core repo at d5c715103f529ade0e5d375a53c5692daaa9c54b
//
pub trait MciPeripheral {
    fn poll(&mut self) {}
    fn warm_reset(&mut self) {}
    fn update_reset(&mut self) {}
    fn read_capabilities(&mut self) -> CAPABILITIES {
        CAPABILITIES::default()
    }
    fn write_capabilities(&mut self, _val: CAPABILITIES) {}
    fn read_hw_rev_id(&mut self) -> HW_REV_ID {
        HW_REV_ID::default()
    }
    fn write_hw_rev_id(&mut self, _val: HW_REV_ID) {}
    fn read_rom_rev_id(&mut self) -> u32 {
        0
    }
    fn write_rom_rev_id(&mut self, _val: u32) {}
    fn read_fw_rev_id(&mut self) -> u32 {
        0
    }
    fn write_fw_rev_id(&mut self, _val: u32) {}
    fn read_boot_status(&mut self) -> u32 {
        0
    }
    fn write_boot_status(&mut self, _val: u32) {}
    fn read_flow_status(&mut self) -> FLOW_STATUS {
        FLOW_STATUS::default()
    }
    fn write_flow_status(&mut self, _val: FLOW_STATUS) {}
    fn read_reset_reason(&mut self) -> RESET_REASON {
        RESET_REASON::default()
    }
    fn write_reset_reason(&mut self, _val: RESET_REASON) {}
    fn read_hw_error_fatal(&mut self) -> HW_ERROR_ {
        HW_ERROR_::default()
    }
    fn write_hw_error_fatal(&mut self, _val: HW_ERROR_) {}
    fn read_hw_error_non_fatal(&mut self) -> HW_ERROR_ {
        HW_ERROR_::default()
    }
    fn write_hw_error_non_fatal(&mut self, _val: HW_ERROR_) {}
    fn read_fw_error_fatal(&mut self) -> u32 {
        0
    }
    fn write_fw_error_fatal(&mut self, _val: u32) {}
    fn read_fw_error_non_fatal(&mut self) -> u32 {
        0
    }
    fn write_fw_error_non_fatal(&mut self, _val: u32) {}
    fn read_wdt_timer1_en(&mut self) -> WDT_TIMER1_EN {
        WDT_TIMER1_EN::default()
    }
    fn write_wdt_timer1_en(&mut self, _val: WDT_TIMER1_EN) {}
    fn read_wdt_timer1_ctrl(&mut self) -> WDT_TIMER1_CTRL {
        WDT_TIMER1_CTRL::default()
    }
    fn write_wdt_timer1_ctrl(&mut self, _val: WDT_TIMER1_CTRL) {}
    fn read_wdt_timer1_timeout_period(&mut self) -> u32 {
        0
    }
    fn write_wdt_timer1_timeout_period(&mut self, _val: u32) {}
    fn read_wdt_timer2_en(&mut self) -> WDT_TIMER2_EN {
        WDT_TIMER2_EN::default()
    }
    fn write_wdt_timer2_en(&mut self, _val: WDT_TIMER2_EN) {}
    fn read_wdt_timer2_ctrl(&mut self) -> WDT_TIMER2_CTRL {
        WDT_TIMER2_CTRL::default()
    }
    fn write_wdt_timer2_ctrl(&mut self, _val: WDT_TIMER2_CTRL) {}
    fn read_wdt_timer2_timeout_period(&mut self) -> u32 {
        0
    }
    fn write_wdt_timer2_timeout_period(&mut self, _val: u32) {}
    fn read_cptra_wdt_status(&mut self) -> CPTRA_WDT_STATUS {
        CPTRA_WDT_STATUS::default()
    }
    fn write_cptra_wdt_status(&mut self, _val: CPTRA_WDT_STATUS) {}
    fn read_wdt_cfg(&mut self) -> u32 {
        0
    }
    fn write_wdt_cfg(&mut self, _val: u32) {}
    fn read_mcu_timer_config(&mut self) -> u32 {
        0
    }
    fn write_mcu_timer_config(&mut self, _val: u32) {}
    fn read_reset_request(&mut self) -> RESET_REQUEST {
        RESET_REQUEST::default()
    }
    fn write_reset_request(&mut self, _val: RESET_REQUEST) {}
    fn read_reset_ack(&mut self) -> RESET_ACK {
        RESET_ACK::default()
    }
    fn write_reset_ack(&mut self, _val: RESET_ACK) {}
    fn read_caliptra_boot_go(&mut self) -> CALIPTRA_BOOT_GO {
        CALIPTRA_BOOT_GO::default()
    }
    fn write_caliptra_boot_go(&mut self, _val: CALIPTRA_BOOT_GO) {}
    fn read_caliptra_axi_id(&mut self) -> CALIPTRA_AXI_ID {
        CALIPTRA_AXI_ID::default()
    }
    fn write_caliptra_axi_id(&mut self, _val: CALIPTRA_AXI_ID) {}
    fn read_fw_sram_exec_region_size(&mut self) -> FW_SRAM_EXEC_REGION_SIZE {
        FW_SRAM_EXEC_REGION_SIZE::default()
    }
    fn write_fw_sram_exec_region_size(&mut self, _val: FW_SRAM_EXEC_REGION_SIZE) {}
    fn read_runtime_lock(&mut self) -> _LOCK {
        _LOCK::default()
    }
    fn write_runtime_lock(&mut self, _val: _LOCK) {}
    fn read_mbox0_valid_axi_id(&mut self) -> u32 {
        0
    }
    fn write_mbox0_valid_axi_id(&mut self, _val: u32) {}
    fn read_mbox0_valid_axi_id_lock(&mut self) -> _LOCK {
        _LOCK::default()
    }
    fn write_mbox0_valid_axi_id_lock(&mut self, _val: _LOCK) {}
    fn read_mbox1_valid_axi_id(&mut self) -> u32 {
        0
    }
    fn write_mbox1_valid_axi_id(&mut self, _val: u32) {}
    fn read_mbox1_valid_axi_id_lock(&mut self) -> _LOCK {
        _LOCK::default()
    }
    fn write_mbox1_valid_axi_id_lock(&mut self, _val: _LOCK) {}
    fn read_generic_input_wires(&mut self) -> u32 {
        0
    }
    fn write_generic_input_wires(&mut self, _val: u32) {}
    fn read_generic_output_wires(&mut self) -> u32 {
        0
    }
    fn write_generic_output_wires(&mut self, _val: u32) {}
    fn read_rsvd_rw_reg(&mut self) -> u32 {
        0
    }
    fn write_rsvd_rw_reg(&mut self, _val: u32) {}
    fn read_rsvd_rw_s_reg(&mut self) -> u32 {
        0
    }
    fn write_rsvd_rw_s_reg(&mut self, _val: u32) {}
    fn read_rsvd_cptra_rw_reg(&mut self) -> u32 {
        0
    }
    fn write_rsvd_cptra_rw_reg(&mut self, _val: u32) {}
    fn read_rsvd_cptra_rw_s_reg(&mut self) -> u32 {
        0
    }
    fn write_rsvd_cptra_rw_s_reg(&mut self, _val: u32) {}
    fn read_rsvd_mcu_rw_reg(&mut self) -> u32 {
        0
    }
    fn write_rsvd_mcu_rw_reg(&mut self, _val: u32) {}
    fn read_rsvd_mcu_rw_s_reg(&mut self) -> u32 {
        0
    }
    fn write_rsvd_mcu_rw_s_reg(&mut self, _val: u32) {}
    fn read_rsvd_rw_l_reg(&mut self) -> u32 {
        0
    }
    fn write_rsvd_rw_l_reg(&mut self, _val: u32) {}
    fn read_rsvd_rw_l_reg_lock(&mut self) -> u32 {
        0
    }
    fn write_rsvd_rw_l_reg_lock(&mut self, _val: u32) {}
    fn read_rsvd_rw_l_s_reg(&mut self) -> u32 {
        0
    }
    fn write_rsvd_rw_l_s_reg(&mut self, _val: u32) {}
    fn read_rsvd_rw_l_s_reg_lock(&mut self) -> u32 {
        0
    }
    fn write_rsvd_rw_l_s_reg_lock(&mut self, _val: u32) {}
}
pub struct MciBus {
    pub periph: Box<dyn MciPeripheral>,
}
impl emulator_bus::Bus for MciBus {
    fn read(
        &mut self,
        size: emulator_types::RvSize,
        addr: emulator_types::RvAddr,
    ) -> Result<emulator_types::RvData, emulator_bus::BusError> {
        match (size, addr) {
            (emulator_types::RvSize::Word, 0) => Ok(emulator_types::RvData::from(
                self.periph.read_capabilities(),
            )),
            (emulator_types::RvSize::Word, 1..=3) => {
                Err(emulator_bus::BusError::LoadAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 4) => {
                Ok(emulator_types::RvData::from(self.periph.read_hw_rev_id()))
            }
            (emulator_types::RvSize::Word, 5..=7) => {
                Err(emulator_bus::BusError::LoadAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 8) => {
                Ok(emulator_types::RvData::from(self.periph.read_rom_rev_id()))
            }
            (emulator_types::RvSize::Word, 9..=0xb) => {
                Err(emulator_bus::BusError::LoadAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0xc) => {
                Ok(emulator_types::RvData::from(self.periph.read_fw_rev_id()))
            }
            (emulator_types::RvSize::Word, 0xd..=0xf) => {
                Err(emulator_bus::BusError::LoadAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0x20) => {
                Ok(emulator_types::RvData::from(self.periph.read_boot_status()))
            }
            (emulator_types::RvSize::Word, 0x21..=0x23) => {
                Err(emulator_bus::BusError::LoadAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0x24) => {
                Ok(emulator_types::RvData::from(self.periph.read_flow_status()))
            }
            (emulator_types::RvSize::Word, 0x25..=0x27) => {
                Err(emulator_bus::BusError::LoadAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0x28) => Ok(emulator_types::RvData::from(
                self.periph.read_reset_reason(),
            )),
            (emulator_types::RvSize::Word, 0x29..=0x2b) => {
                Err(emulator_bus::BusError::LoadAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0x40) => Ok(emulator_types::RvData::from(
                self.periph.read_hw_error_fatal(),
            )),
            (emulator_types::RvSize::Word, 0x41..=0x43) => {
                Err(emulator_bus::BusError::LoadAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0x44) => Ok(emulator_types::RvData::from(
                self.periph.read_hw_error_non_fatal(),
            )),
            (emulator_types::RvSize::Word, 0x45..=0x47) => {
                Err(emulator_bus::BusError::LoadAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0x48) => Ok(emulator_types::RvData::from(
                self.periph.read_fw_error_fatal(),
            )),
            (emulator_types::RvSize::Word, 0x49..=0x4b) => {
                Err(emulator_bus::BusError::LoadAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0x4c) => Ok(emulator_types::RvData::from(
                self.periph.read_fw_error_non_fatal(),
            )),
            (emulator_types::RvSize::Word, 0x4d..=0x4f) => {
                Err(emulator_bus::BusError::LoadAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0x80) => Ok(emulator_types::RvData::from(
                self.periph.read_wdt_timer1_en(),
            )),
            (emulator_types::RvSize::Word, 0x81..=0x83) => {
                Err(emulator_bus::BusError::LoadAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0x84) => Ok(emulator_types::RvData::from(
                self.periph.read_wdt_timer1_ctrl(),
            )),
            (emulator_types::RvSize::Word, 0x85..=0x87) => {
                Err(emulator_bus::BusError::LoadAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0x88) => Ok(emulator_types::RvData::from(
                self.periph.read_wdt_timer1_timeout_period(),
            )),
            (emulator_types::RvSize::Word, 0x89..=0x8b) => {
                Err(emulator_bus::BusError::LoadAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0x90) => Ok(emulator_types::RvData::from(
                self.periph.read_wdt_timer2_en(),
            )),
            (emulator_types::RvSize::Word, 0x91..=0x93) => {
                Err(emulator_bus::BusError::LoadAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0x94) => Ok(emulator_types::RvData::from(
                self.periph.read_wdt_timer2_ctrl(),
            )),
            (emulator_types::RvSize::Word, 0x95..=0x97) => {
                Err(emulator_bus::BusError::LoadAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0x98) => Ok(emulator_types::RvData::from(
                self.periph.read_wdt_timer2_timeout_period(),
            )),
            (emulator_types::RvSize::Word, 0x99..=0x9b) => {
                Err(emulator_bus::BusError::LoadAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0xa0) => Ok(emulator_types::RvData::from(
                self.periph.read_cptra_wdt_status(),
            )),
            (emulator_types::RvSize::Word, 0xa1..=0xa3) => {
                Err(emulator_bus::BusError::LoadAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0xb0) => {
                Ok(emulator_types::RvData::from(self.periph.read_wdt_cfg()))
            }
            (emulator_types::RvSize::Word, 0xb1..=0xb3) => {
                Err(emulator_bus::BusError::LoadAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0xc0) => Ok(emulator_types::RvData::from(
                self.periph.read_mcu_timer_config(),
            )),
            (emulator_types::RvSize::Word, 0xc1..=0xc3) => {
                Err(emulator_bus::BusError::LoadAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0x100) => Ok(emulator_types::RvData::from(
                self.periph.read_reset_request(),
            )),
            (emulator_types::RvSize::Word, 0x101..=0x103) => {
                Err(emulator_bus::BusError::LoadAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0x104) => {
                Ok(emulator_types::RvData::from(self.periph.read_reset_ack()))
            }
            (emulator_types::RvSize::Word, 0x105..=0x107) => {
                Err(emulator_bus::BusError::LoadAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0x108) => Ok(emulator_types::RvData::from(
                self.periph.read_caliptra_boot_go(),
            )),
            (emulator_types::RvSize::Word, 0x109..=0x10b) => {
                Err(emulator_bus::BusError::LoadAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0x10c) => Ok(emulator_types::RvData::from(
                self.periph.read_caliptra_axi_id(),
            )),
            (emulator_types::RvSize::Word, 0x10d..=0x10f) => {
                Err(emulator_bus::BusError::LoadAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0x110) => Ok(emulator_types::RvData::from(
                self.periph.read_fw_sram_exec_region_size(),
            )),
            (emulator_types::RvSize::Word, 0x111..=0x113) => {
                Err(emulator_bus::BusError::LoadAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0x114) => Ok(emulator_types::RvData::from(
                self.periph.read_runtime_lock(),
            )),
            (emulator_types::RvSize::Word, 0x115..=0x117) => {
                Err(emulator_bus::BusError::LoadAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0x180) => Ok(emulator_types::RvData::from(
                self.periph.read_mbox0_valid_axi_id(),
            )),
            (emulator_types::RvSize::Word, 0x181..=0x183) => {
                Err(emulator_bus::BusError::LoadAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0x1a0) => Ok(emulator_types::RvData::from(
                self.periph.read_mbox0_valid_axi_id_lock(),
            )),
            (emulator_types::RvSize::Word, 0x1a1..=0x1a3) => {
                Err(emulator_bus::BusError::LoadAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0x1c0) => Ok(emulator_types::RvData::from(
                self.periph.read_mbox1_valid_axi_id(),
            )),
            (emulator_types::RvSize::Word, 0x1c1..=0x1c3) => {
                Err(emulator_bus::BusError::LoadAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0x1e0) => Ok(emulator_types::RvData::from(
                self.periph.read_mbox1_valid_axi_id_lock(),
            )),
            (emulator_types::RvSize::Word, 0x1e1..=0x1e3) => {
                Err(emulator_bus::BusError::LoadAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0x408) => Ok(emulator_types::RvData::from(
                self.periph.read_generic_output_wires(),
            )),
            (emulator_types::RvSize::Word, 0x409..=0x40b) => {
                Err(emulator_bus::BusError::LoadAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0x410) => {
                Ok(emulator_types::RvData::from(self.periph.read_rsvd_rw_reg()))
            }
            (emulator_types::RvSize::Word, 0x411..=0x413) => {
                Err(emulator_bus::BusError::LoadAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0x418) => Ok(emulator_types::RvData::from(
                self.periph.read_rsvd_rw_s_reg(),
            )),
            (emulator_types::RvSize::Word, 0x419..=0x41b) => {
                Err(emulator_bus::BusError::LoadAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0x420) => Ok(emulator_types::RvData::from(
                self.periph.read_rsvd_cptra_rw_reg(),
            )),
            (emulator_types::RvSize::Word, 0x421..=0x423) => {
                Err(emulator_bus::BusError::LoadAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0x428) => Ok(emulator_types::RvData::from(
                self.periph.read_rsvd_cptra_rw_s_reg(),
            )),
            (emulator_types::RvSize::Word, 0x429..=0x42b) => {
                Err(emulator_bus::BusError::LoadAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0x430) => Ok(emulator_types::RvData::from(
                self.periph.read_rsvd_mcu_rw_reg(),
            )),
            (emulator_types::RvSize::Word, 0x431..=0x433) => {
                Err(emulator_bus::BusError::LoadAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0x438) => Ok(emulator_types::RvData::from(
                self.periph.read_rsvd_mcu_rw_s_reg(),
            )),
            (emulator_types::RvSize::Word, 0x439..=0x43b) => {
                Err(emulator_bus::BusError::LoadAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0x440) => Ok(emulator_types::RvData::from(
                self.periph.read_rsvd_rw_l_reg(),
            )),
            (emulator_types::RvSize::Word, 0x441..=0x443) => {
                Err(emulator_bus::BusError::LoadAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0x448) => Ok(emulator_types::RvData::from(
                self.periph.read_rsvd_rw_l_reg_lock(),
            )),
            (emulator_types::RvSize::Word, 0x449..=0x44b) => {
                Err(emulator_bus::BusError::LoadAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0x450) => Ok(emulator_types::RvData::from(
                self.periph.read_rsvd_rw_l_s_reg(),
            )),
            (emulator_types::RvSize::Word, 0x451..=0x453) => {
                Err(emulator_bus::BusError::LoadAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0x458) => Ok(emulator_types::RvData::from(
                self.periph.read_rsvd_rw_l_s_reg_lock(),
            )),
            (emulator_types::RvSize::Word, 0x459..=0x45b) => {
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
                self.periph.write_capabilities(CAPABILITIES::from(val));
                Ok(())
            }
            (emulator_types::RvSize::Word, 1..=3) => {
                Err(emulator_bus::BusError::StoreAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 4) => {
                self.periph.write_hw_rev_id(HW_REV_ID::from(val));
                Ok(())
            }
            (emulator_types::RvSize::Word, 5..=7) => {
                Err(emulator_bus::BusError::StoreAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 8) => {
                self.periph.write_rom_rev_id(val);
                Ok(())
            }
            (emulator_types::RvSize::Word, 9..=0xb) => {
                Err(emulator_bus::BusError::StoreAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0xc) => {
                self.periph.write_fw_rev_id(val);
                Ok(())
            }
            (emulator_types::RvSize::Word, 0xd..=0xf) => {
                Err(emulator_bus::BusError::StoreAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0x20) => {
                self.periph.write_boot_status(val);
                Ok(())
            }
            (emulator_types::RvSize::Word, 0x21..=0x23) => {
                Err(emulator_bus::BusError::StoreAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0x24) => {
                self.periph.write_flow_status(FLOW_STATUS::from(val));
                Ok(())
            }
            (emulator_types::RvSize::Word, 0x25..=0x27) => {
                Err(emulator_bus::BusError::StoreAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0x28) => {
                self.periph.write_reset_reason(RESET_REASON::from(val));
                Ok(())
            }
            (emulator_types::RvSize::Word, 0x29..=0x2b) => {
                Err(emulator_bus::BusError::StoreAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0x40) => {
                self.periph.write_hw_error_fatal(HW_ERROR_::from(val));
                Ok(())
            }
            (emulator_types::RvSize::Word, 0x41..=0x43) => {
                Err(emulator_bus::BusError::StoreAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0x44) => {
                self.periph.write_hw_error_non_fatal(HW_ERROR_::from(val));
                Ok(())
            }
            (emulator_types::RvSize::Word, 0x45..=0x47) => {
                Err(emulator_bus::BusError::StoreAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0x48) => {
                self.periph.write_fw_error_fatal(val);
                Ok(())
            }
            (emulator_types::RvSize::Word, 0x49..=0x4b) => {
                Err(emulator_bus::BusError::StoreAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0x4c) => {
                self.periph.write_fw_error_non_fatal(val);
                Ok(())
            }
            (emulator_types::RvSize::Word, 0x4d..=0x4f) => {
                Err(emulator_bus::BusError::StoreAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0x80) => {
                self.periph.write_wdt_timer1_en(WDT_TIMER1_EN::from(val));
                Ok(())
            }
            (emulator_types::RvSize::Word, 0x81..=0x83) => {
                Err(emulator_bus::BusError::StoreAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0x84) => {
                self.periph
                    .write_wdt_timer1_ctrl(WDT_TIMER1_CTRL::from(val));
                Ok(())
            }
            (emulator_types::RvSize::Word, 0x85..=0x87) => {
                Err(emulator_bus::BusError::StoreAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0x88) => {
                self.periph.write_wdt_timer1_timeout_period(val);
                Ok(())
            }
            (emulator_types::RvSize::Word, 0x89..=0x8b) => {
                Err(emulator_bus::BusError::StoreAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0x90) => {
                self.periph.write_wdt_timer2_en(WDT_TIMER2_EN::from(val));
                Ok(())
            }
            (emulator_types::RvSize::Word, 0x91..=0x93) => {
                Err(emulator_bus::BusError::StoreAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0x94) => {
                self.periph
                    .write_wdt_timer2_ctrl(WDT_TIMER2_CTRL::from(val));
                Ok(())
            }
            (emulator_types::RvSize::Word, 0x95..=0x97) => {
                Err(emulator_bus::BusError::StoreAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0x98) => {
                self.periph.write_wdt_timer2_timeout_period(val);
                Ok(())
            }
            (emulator_types::RvSize::Word, 0x99..=0x9b) => {
                Err(emulator_bus::BusError::StoreAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0xa0) => {
                self.periph
                    .write_cptra_wdt_status(CPTRA_WDT_STATUS::from(val));
                Ok(())
            }
            (emulator_types::RvSize::Word, 0xa1..=0xa3) => {
                Err(emulator_bus::BusError::StoreAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0xb0) => {
                self.periph.write_wdt_cfg(val);
                Ok(())
            }
            (emulator_types::RvSize::Word, 0xb1..=0xb3) => {
                Err(emulator_bus::BusError::StoreAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0xc0) => {
                self.periph.write_mcu_timer_config(val);
                Ok(())
            }
            (emulator_types::RvSize::Word, 0xc1..=0xc3) => {
                Err(emulator_bus::BusError::StoreAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0x100) => {
                self.periph.write_reset_request(RESET_REQUEST::from(val));
                Ok(())
            }
            (emulator_types::RvSize::Word, 0x101..=0x103) => {
                Err(emulator_bus::BusError::StoreAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0x104) => {
                self.periph.write_reset_ack(RESET_ACK::from(val));
                Ok(())
            }
            (emulator_types::RvSize::Word, 0x105..=0x107) => {
                Err(emulator_bus::BusError::StoreAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0x108) => {
                self.periph
                    .write_caliptra_boot_go(CALIPTRA_BOOT_GO::from(val));
                Ok(())
            }
            (emulator_types::RvSize::Word, 0x109..=0x10b) => {
                Err(emulator_bus::BusError::StoreAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0x10c) => {
                self.periph
                    .write_caliptra_axi_id(CALIPTRA_AXI_ID::from(val));
                Ok(())
            }
            (emulator_types::RvSize::Word, 0x10d..=0x10f) => {
                Err(emulator_bus::BusError::StoreAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0x110) => {
                self.periph
                    .write_fw_sram_exec_region_size(FW_SRAM_EXEC_REGION_SIZE::from(val));
                Ok(())
            }
            (emulator_types::RvSize::Word, 0x111..=0x113) => {
                Err(emulator_bus::BusError::StoreAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0x114) => {
                self.periph.write_runtime_lock(_LOCK::from(val));
                Ok(())
            }
            (emulator_types::RvSize::Word, 0x115..=0x117) => {
                Err(emulator_bus::BusError::StoreAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0x180) => {
                self.periph.write_mbox0_valid_axi_id(val);
                Ok(())
            }
            (emulator_types::RvSize::Word, 0x181..=0x183) => {
                Err(emulator_bus::BusError::StoreAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0x1a0) => {
                self.periph.write_mbox0_valid_axi_id_lock(_LOCK::from(val));
                Ok(())
            }
            (emulator_types::RvSize::Word, 0x1a1..=0x1a3) => {
                Err(emulator_bus::BusError::StoreAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0x1c0) => {
                self.periph.write_mbox1_valid_axi_id(val);
                Ok(())
            }
            (emulator_types::RvSize::Word, 0x1c1..=0x1c3) => {
                Err(emulator_bus::BusError::StoreAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0x1e0) => {
                self.periph.write_mbox1_valid_axi_id_lock(_LOCK::from(val));
                Ok(())
            }
            (emulator_types::RvSize::Word, 0x1e1..=0x1e3) => {
                Err(emulator_bus::BusError::StoreAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0x400) => {
                self.periph.write_generic_input_wires(val);
                Ok(())
            }
            (emulator_types::RvSize::Word, 0x401..=0x403) => {
                Err(emulator_bus::BusError::StoreAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0x408) => {
                self.periph.write_generic_output_wires(val);
                Ok(())
            }
            (emulator_types::RvSize::Word, 0x409..=0x40b) => {
                Err(emulator_bus::BusError::StoreAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0x410) => {
                self.periph.write_rsvd_rw_reg(val);
                Ok(())
            }
            (emulator_types::RvSize::Word, 0x411..=0x413) => {
                Err(emulator_bus::BusError::StoreAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0x418) => {
                self.periph.write_rsvd_rw_s_reg(val);
                Ok(())
            }
            (emulator_types::RvSize::Word, 0x419..=0x41b) => {
                Err(emulator_bus::BusError::StoreAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0x420) => {
                self.periph.write_rsvd_cptra_rw_reg(val);
                Ok(())
            }
            (emulator_types::RvSize::Word, 0x421..=0x423) => {
                Err(emulator_bus::BusError::StoreAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0x428) => {
                self.periph.write_rsvd_cptra_rw_s_reg(val);
                Ok(())
            }
            (emulator_types::RvSize::Word, 0x429..=0x42b) => {
                Err(emulator_bus::BusError::StoreAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0x430) => {
                self.periph.write_rsvd_mcu_rw_reg(val);
                Ok(())
            }
            (emulator_types::RvSize::Word, 0x431..=0x433) => {
                Err(emulator_bus::BusError::StoreAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0x438) => {
                self.periph.write_rsvd_mcu_rw_s_reg(val);
                Ok(())
            }
            (emulator_types::RvSize::Word, 0x439..=0x43b) => {
                Err(emulator_bus::BusError::StoreAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0x440) => {
                self.periph.write_rsvd_rw_l_reg(val);
                Ok(())
            }
            (emulator_types::RvSize::Word, 0x441..=0x443) => {
                Err(emulator_bus::BusError::StoreAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0x448) => {
                self.periph.write_rsvd_rw_l_reg_lock(val);
                Ok(())
            }
            (emulator_types::RvSize::Word, 0x449..=0x44b) => {
                Err(emulator_bus::BusError::StoreAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0x450) => {
                self.periph.write_rsvd_rw_l_s_reg(val);
                Ok(())
            }
            (emulator_types::RvSize::Word, 0x451..=0x453) => {
                Err(emulator_bus::BusError::StoreAddrMisaligned)
            }
            (emulator_types::RvSize::Word, 0x458) => {
                self.periph.write_rsvd_rw_l_s_reg_lock(val);
                Ok(())
            }
            (emulator_types::RvSize::Word, 0x459..=0x45b) => {
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
