// Licensed under the Apache-2.0 license

use caliptra_mcu_error::McuError;
use caliptra_mcu_registers_generated::i3c;
use caliptra_mcu_registers_generated::i3c::bits::{
    DeviceStatus0, HcControl, IndirectFifoCtrl0, QueueThldCtrl, RecoveryStatus,
    RingHeadersSectionOffset, StbyCrCapabilities, StbyCrControl, StbyCrDeviceAddr,
    StbyCrDeviceChar, StbyCrVirtDeviceAddr, TtiQueueThldCtrl,
};
use caliptra_mcu_romtime::{HexWord, StaticRef};
use tock_registers::interfaces::{ReadWriteable, Readable, Writeable};

use crate::fatal_error;

/// MIPI-assigned Device Characteristic Register value for an MCTP device.
pub const MCTP_DCR: u8 = 0xCC;

/// I3C bus timing parameters, in clock units.
///
/// Each value is written to the corresponding `soc_mgmt_if_t_*_reg` timing
/// register during [`I3c::configure`]. The fields are sized as `u32` because
/// every timing register field is 20 bits wide (the smallest Rust integer that
/// holds 20 bits is `u32`); `t_free` is a plain 32-bit register.
///
/// The [`Default`] implementation provides the recommended settings for
/// high-speed parts: all values are 0 except `t_free`, which is 200 (~1
/// microsecond bus free time before issuing an IBI).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct I3cTimings {
    /// Rise time of both SDA and SCL in clock units.
    pub t_r: u32,
    /// Fall time of both SDA and SCL in clock units.
    pub t_f: u32,
    /// Data hold time in clock units.
    pub t_hd_dat: u32,
    /// Data setup time in clock units.
    pub t_su_dat: u32,
    /// High period of the SCL in clock units.
    pub t_high: u32,
    /// Low period of the SCL in clock units.
    pub t_low: u32,
    /// Hold time for (repeated) START in clock units.
    pub t_hd_sta: u32,
    /// Setup time for repeated START in clock units.
    pub t_su_sta: u32,
    /// Setup time for STOP in clock units.
    pub t_su_sto: u32,
    /// Bus free time in clock units before doing IBI.
    pub t_free: u32,
}

impl Default for I3cTimings {
    /// Recommended timing settings for high-speed parts.
    fn default() -> Self {
        Self {
            t_r: 0,
            t_f: 0,
            t_hd_dat: 0,
            t_su_dat: 0,
            t_high: 0,
            t_low: 0,
            t_hd_sta: 0,
            t_su_sta: 0,
            t_su_sto: 0,
            t_free: 200,
        }
    }
}

/// Configuration for a single I3C controller, passed to [`I3c::configure`].
///
/// Each controller (primary and secondary) has its own static address and
/// timing parameters, so these are bundled together and specified individually.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct I3cConfig {
    /// Static (initial) I3C target address for this controller.
    pub static_addr: u8,
    /// Whether recovery is enabled (also programs the virtual device address).
    pub recovery_enabled: bool,
    /// Device Characteristic Register (DCR) — distinguishes device type during DAA.
    /// The virtual target remains at its reset value of 0xBD (OCP Recovery).
    pub dcr: u8,
    /// Bus timing parameters for this controller.
    pub timings: I3cTimings,
}

pub struct I3c {
    registers: StaticRef<i3c::regs::I3c>,
}

impl I3c {
    pub const fn new(registers: StaticRef<i3c::regs::I3c>) -> Self {
        I3c { registers }
    }

    /// Run the initialization steps for the primary and secondary controller.
    pub fn configure(&mut self, config: I3cConfig) {
        let I3cConfig {
            static_addr: addr,
            recovery_enabled,
            dcr,
            timings,
        } = config;
        let regs = self.registers;
        caliptra_mcu_romtime::println!(
            "[mcu-rom-i3c] HCI version: {:x}",
            regs.i3c_base_hci_version.get()
        );

        const TTI_RESET_CONTROL: u32 = 0x3f;
        caliptra_mcu_romtime::println!(
            "[mcu-rom-i3c] Set TTI RESET_CONTROL: {}",
            HexWord(TTI_RESET_CONTROL)
        );
        regs.tti_tti_reset_control.set(TTI_RESET_CONTROL);
        // Clear reset to take TTI out of reset. In I3C v1.5 these bits are persistent
        // "hold in reset" rather than self-clearing pulses, so the TTI stays in reset
        // (and threshold register writes are discarded) unless explicitly cleared.
        regs.tti_tti_reset_control.set(0);

        // Evaluate RING_HEADERS_SECTION_OFFSET, the SECTION_OFFSET should read 0x0 as this controller doesn’t support the DMA mode
        let rhso = regs
            .i3c_base_ring_headers_section_offset
            .read(RingHeadersSectionOffset::SectionOffset);
        if rhso != 0 {
            caliptra_mcu_romtime::println!("[mcu-rom-i3c] RING_HEADERS_SECTION_OFFSET is not 0");
            fatal_error(McuError::ROM_I3C_CONFIG_RING_HEADER_ERROR);
        }

        // initialize timing registers
        caliptra_mcu_romtime::println!("[mcu-rom-i3c] Initialize timing registers");

        // AXI clock is ~200 MHz, I3C clock is 12.5 MHz
        // values of all of these set to 0-5 seem to work for receiving data correctly
        // 6-7 gets corrupted data but will ACK
        // 8+ will fail to ACK
        regs.soc_mgmt_if_t_r_reg.set(timings.t_r); // rise time of both SDA and SCL in clock units
        regs.soc_mgmt_if_t_f_reg.set(timings.t_f); // fall time of both SDA and SCL in clock units

        // if this is set to 6+ then ACKs start failing
        regs.soc_mgmt_if_t_hd_dat_reg.set(timings.t_hd_dat); // data hold time in clock units
        regs.soc_mgmt_if_t_su_dat_reg.set(timings.t_su_dat); // data setup time in clock units

        regs.soc_mgmt_if_t_high_reg.set(timings.t_high); // High period of the SCL in clock units
        regs.soc_mgmt_if_t_low_reg.set(timings.t_low); // Low period of the SCL in clock units
        regs.soc_mgmt_if_t_hd_sta_reg.set(timings.t_hd_sta); // Hold time for (repeated) START in clock units
        regs.soc_mgmt_if_t_su_sta_reg.set(timings.t_su_sta); // Setup time for repeated START in clock units
        regs.soc_mgmt_if_t_su_sto_reg.set(timings.t_su_sto); // Setup time for STOP in clock units

        regs.soc_mgmt_if_t_free_reg.set(timings.t_free); // Bus free time in clock units before doing IBI

        caliptra_mcu_romtime::println!(
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
        caliptra_mcu_romtime::println!("[mcu-rom-i3c] Setup HCI queue thresholds");
        regs.piocontrol_queue_thld_ctrl.modify(
            QueueThldCtrl::CmdEmptyBufThld.val(1)
                + QueueThldCtrl::RespBufThld.val(1)
                + QueueThldCtrl::IbiStatusThld.val(1),
        );

        // Set the main target's DCR before enabling the standby controller.
        // Once STBY_CR_ENABLE_INIT is non-zero, the RTL locks DCR read-only.
        caliptra_mcu_romtime::println!("[mcu-rom-i3c] Setting main target DCR to {:02x}", dcr);
        regs.stdby_ctrl_mode_stby_cr_device_char
            .modify(StbyCrDeviceChar::Dcr.val(dcr as u32));

        caliptra_mcu_romtime::println!("[mcu-rom-i3c] Enable the target transaction interface");
        regs.stdby_ctrl_mode_stby_cr_control.modify(
            StbyCrControl::StbyCrEnableInit.val(2) // enable the standby controller
                + StbyCrControl::TargetXactEnable::SET // enable Target Transaction Interface
                + StbyCrControl::DaaEntdaaEnable::SET // enable ENTDAA dynamic address assignment
                + StbyCrControl::DaaSetdasaEnable::SET // enable SETDASA dynamic address assignment
                + StbyCrControl::BastCccIbiRing.val(0) // Set the IBI to use ring buffer 0
                + StbyCrControl::PrimeAcceptGetacccr::CLEAR // // don't auto-accept primary controller role
                + StbyCrControl::AcrFsmOpSelect::CLEAR, // don't become the active controller and set us as not the bus owner
        );

        caliptra_mcu_romtime::println!(
            "[mcu-rom-i3c] STBY_CR_CONTROL: {:x}",
            regs.stdby_ctrl_mode_stby_cr_control.get()
        );

        caliptra_mcu_romtime::println!(
            "[mcu-rom-i3c] STBY_CR_CAPABILITIES: {:x}",
            regs.stdby_ctrl_mode_stby_cr_capabilities.get()
        );
        if !regs
            .stdby_ctrl_mode_stby_cr_capabilities
            .is_set(StbyCrCapabilities::TargetXactSupport)
        {
            caliptra_mcu_romtime::println!(
                "[mcu-rom-i3c] I3C target transaction support is not enabled"
            );
            fatal_error(McuError::ROM_I3C_CONFIG_STDBY_CTRL_MODE_ERROR)
        }

        // program a static address
        caliptra_mcu_romtime::println!("[mcu-rom-i3c] Setting static address to {:x}", addr);
        regs.stdby_ctrl_mode_stby_cr_device_addr.write(
            StbyCrDeviceAddr::StaticAddrValid::SET + StbyCrDeviceAddr::StaticAddr.val(addr as u32),
        );
        if recovery_enabled {
            caliptra_mcu_romtime::println!(
                "[mcu-rom-i3c] Setting virtual device static address to {:x}",
                addr + 1
            );
            regs.stdby_ctrl_mode_stby_cr_virt_device_addr.write(
                StbyCrVirtDeviceAddr::VirtStaticAddrValid::SET
                    + StbyCrVirtDeviceAddr::VirtStaticAddr.val((addr + 1) as u32),
            );
        }

        caliptra_mcu_romtime::println!("[mcu-rom-i3c] Set TTI queue thresholds");
        // set TTI queue thresholds
        regs.tti_tti_queue_thld_ctrl.modify(
            TtiQueueThldCtrl::IbiThld.val(1)
                + TtiQueueThldCtrl::RxDescThld.val(1)
                + TtiQueueThldCtrl::TxDescThld.val(1),
        );
        caliptra_mcu_romtime::println!(
            "[mcu-rom-i3c] TTI queue thresholds: {}",
            HexWord(regs.tti_tti_queue_thld_ctrl.get())
        );

        caliptra_mcu_romtime::println!(
            "[mcu-rom-i3c] TTI data buffer thresholds ctrl: {}",
            HexWord(regs.tti_tti_data_buffer_thld_ctrl.get())
        );

        // reset the FIFO as there might be junk in it
        caliptra_mcu_romtime::println!("[mcu-rom-i3c] Reset indirect fifo ctrl",);
        regs.sec_fw_recovery_if_indirect_fifo_ctrl_0
            .write(IndirectFifoCtrl0::Reset.val(1));
        regs.sec_fw_recovery_if_indirect_fifo_ctrl_1.set(0);

        caliptra_mcu_romtime::println!("[mcu-rom-i3c] Enable PHY to the bus");
        // enable the PHY connection to the bus
        regs.i3c_base_hc_control
            .modify(HcControl::ModeSelector::SET + HcControl::BusEnable::SET);
    }

    pub fn disable_recovery(&mut self) {
        self.registers
            .sec_fw_recovery_if_recovery_status
            .write(RecoveryStatus::DevRecStatus.val(3)); // recovery successful
        self.registers
            .sec_fw_recovery_if_device_status_0
            .write(DeviceStatus0::DevStatus.val(0));
    }

    pub fn set_recovery_status_open(&self) {
        self.registers
            .sec_fw_recovery_if_recovery_status
            .write(RecoveryStatus::DevRecStatus.val(2)); // booting recovery image, so that the BMC knows that we might still want more images
    }
}
