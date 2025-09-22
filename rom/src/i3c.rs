// Licensed under the Apache-2.0 license

use registers_generated::i3c;
use registers_generated::i3c::bits::{
    DeviceStatus0, HcControl, IndirectFifoCtrl0, QueueThldCtrl, RingHeadersSectionOffset,
    StbyCrCapabilities, StbyCrControl, StbyCrDeviceAddr, StbyCrVirtDeviceAddr, TtiQueueThldCtrl,
};
use romtime::{HexWord, StaticRef};
use tock_registers::interfaces::{ReadWriteable, Readable, Writeable};

use crate::fatal_error;

pub struct I3c {
    registers: StaticRef<i3c::regs::I3c>,
}

impl I3c {
    pub const fn new(registers: StaticRef<i3c::regs::I3c>) -> Self {
        I3c { registers }
    }

    /// Run the initialization steps for the primary and secondary controller.
    pub fn configure(&mut self, addr: u8, recovery_enabled: bool) {
        let regs = self.registers;
        romtime::println!(
            "[mcu-rom-i3c] HCI version: {:x}",
            regs.i3c_base_hci_version.get()
        );

        const TTI_RESET_CONTROL: u32 = 0x3f;
        romtime::println!(
            "[mcu-rom-i3c] Set TTI RESET_CONTROL: {}",
            HexWord(TTI_RESET_CONTROL)
        );
        regs.tti_tti_reset_control.set(TTI_RESET_CONTROL);

        // Evaluate RING_HEADERS_SECTION_OFFSET, the SECTION_OFFSET should read 0x0 as this controller doesn’t support the DMA mode
        let rhso = regs
            .i3c_base_ring_headers_section_offset
            .read(RingHeadersSectionOffset::SectionOffset);
        if rhso != 0 {
            romtime::println!("[mcu-rom-i3c] RING_HEADERS_SECTION_OFFSET is not 0");
            fatal_error(0x101);
        }

        // initialize timing registers
        romtime::println!("[mcu-rom-i3c] Initialize timing registers");

        // AXI clock is ~200 MHz, I3C clock is 12.5 MHz
        // values of all of these set to 0-5 seem to work for receiving data correctly
        // 6-7 gets corrupted data but will ACK
        // 8+ will fail to ACK
        //
        // TODO: pass this timing information in
        let clocks = 0;
        regs.soc_mgmt_if_t_r_reg.set(clocks); // rise time of both SDA and SCL in clock units
        regs.soc_mgmt_if_t_f_reg.set(clocks); // rise time of both SDA and SCL in clock units

        // if this is set to 6+ then ACKs start failing
        regs.soc_mgmt_if_t_hd_dat_reg.set(clocks); // data hold time in clock units
        regs.soc_mgmt_if_t_su_dat_reg.set(clocks); // data setup time in clock units

        regs.soc_mgmt_if_t_high_reg.set(clocks); // High period of the SCL in clock units
        regs.soc_mgmt_if_t_low_reg.set(clocks); // Low period of the SCL in clock units
        regs.soc_mgmt_if_t_hd_sta_reg.set(clocks); // Hold time for (repeated) START in clock units
        regs.soc_mgmt_if_t_su_sta_reg.set(clocks); // Setup time for repeated START in clock units
        regs.soc_mgmt_if_t_su_sto_reg.set(clocks); // Setup time for STOP in clock units

        // set this to 1 microsecond
        regs.soc_mgmt_if_t_free_reg.set(200); // Bus free time in clock units before doing IBI

        romtime::println!(
            "[mcu-rom-i3c] Timing registers t_r: {}, t_f: {}, t_hd_dat: {}, t_su_dat: {}, t_high: {}, t_low: {}, t_hd_sta: {}, t_su_sta: {}, t_su_sto: {}, t_free: {}",
            regs.soc_mgmt_if_t_r_reg.get(),
            regs.soc_mgmt_if_t_f_reg.get(),
            regs.soc_mgmt_if_t_hd_dat_reg.get(),
            regs.soc_mgmt_if_t_su_dat_reg.get(),
            regs.soc_mgmt_if_t_high_reg.get(),
            regs.soc_mgmt_if_t_low_reg.get(),
            regs.soc_mgmt_if_t_hd_sta_reg.get(),
            regs.soc_mgmt_if_t_su_sta_reg.get(),
            regs.soc_mgmt_if_t_su_sto_reg.get(),
            regs.soc_mgmt_if_t_free_reg.get(),
        );

        // Setup the threshold for the HCI queues (in the internal/private software data structures):
        romtime::println!("[mcu-rom-i3c] Setup HCI queue thresholds");
        regs.piocontrol_queue_thld_ctrl.modify(
            QueueThldCtrl::CmdEmptyBufThld.val(0)
                + QueueThldCtrl::RespBufThld.val(1)
                + QueueThldCtrl::IbiStatusThld.val(1),
        );

        romtime::println!("[mcu-rom-i3c] Enable the target transaction interface");
        regs.stdby_ctrl_mode_stby_cr_control.modify(
            StbyCrControl::StbyCrEnableInit.val(2) // enable the standby controller
                + StbyCrControl::TargetXactEnable::SET // enable Target Transaction Interface
                + StbyCrControl::DaaEntdaaEnable::SET // enable ENTDAA dynamic address assignment
                + StbyCrControl::DaaSetdasaEnable::SET // enable SETDASA dynamic address assignment
                + StbyCrControl::BastCccIbiRing.val(0) // Set the IBI to use ring buffer 0
                + StbyCrControl::PrimeAcceptGetacccr::CLEAR // // don't auto-accept primary controller role
                + StbyCrControl::AcrFsmOpSelect::CLEAR, // don't become the active controller and set us as not the bus owner
        );

        romtime::println!(
            "[mcu-rom-i3c] STBY_CR_CONTROL: {:x}",
            regs.stdby_ctrl_mode_stby_cr_control.get()
        );

        romtime::println!(
            "[mcu-rom-i3c] STBY_CR_CAPABILITIES: {:x}",
            regs.stdby_ctrl_mode_stby_cr_capabilities.get()
        );
        if !regs
            .stdby_ctrl_mode_stby_cr_capabilities
            .is_set(StbyCrCapabilities::TargetXactSupport)
        {
            romtime::println!("[mcu-rom-i3c] I3C target transaction support is not enabled");
            fatal_error(0x102)
        }

        // program a static address
        romtime::println!("[mcu-rom-i3c] Setting static address to {:x}", addr);
        regs.stdby_ctrl_mode_stby_cr_device_addr.write(
            StbyCrDeviceAddr::StaticAddrValid::SET + StbyCrDeviceAddr::StaticAddr.val(addr as u32),
        );
        if recovery_enabled {
            romtime::println!(
                "[mcu-rom-i3c] Setting virtual device static address to {:x}",
                addr + 1
            );
            regs.stdby_ctrl_mode_stby_cr_virt_device_addr.write(
                StbyCrVirtDeviceAddr::VirtStaticAddrValid::SET
                    + StbyCrVirtDeviceAddr::VirtStaticAddr.val((addr + 1) as u32),
            );
        }

        romtime::println!("[mcu-rom-i3c] Set TTI queue thresholds");
        // set TTI queue thresholds
        regs.tti_tti_queue_thld_ctrl.modify(
            TtiQueueThldCtrl::IbiThld.val(1)
                + TtiQueueThldCtrl::RxDescThld.val(1)
                + TtiQueueThldCtrl::TxDescThld.val(1),
        );
        romtime::println!(
            "[mcu-rom-i3c] TTI queue thresholds: {}",
            HexWord(regs.tti_tti_queue_thld_ctrl.get())
        );

        romtime::println!(
            "[mcu-rom-i3c] TTI data buffer thresholds ctrl: {}",
            HexWord(regs.tti_tti_data_buffer_thld_ctrl.get())
        );

        // reset the FIFO as there might be junk in it
        romtime::println!("[mcu-rom-i3c] Reset indirect fifo ctrl",);
        regs.sec_fw_recovery_if_indirect_fifo_ctrl_0
            .write(IndirectFifoCtrl0::Reset.val(1));
        regs.sec_fw_recovery_if_indirect_fifo_ctrl_1.set(0);

        romtime::println!("[mcu-rom-i3c] Enable PHY to the bus");
        // enable the PHY connection to the bus
        regs.i3c_base_hc_control.modify(
            HcControl::ModeSelector::SET +
                // clear is bus enabled, set is suspended
                HcControl::BusEnable::CLEAR,
        );
    }

    pub fn disable_recovery(&mut self) {
        self.registers
            .sec_fw_recovery_if_device_status_0
            .write(DeviceStatus0::DevStatus.val(0));
    }
}
