// Licensed under the Apache-2.0 license

//! Hardware owns OCP command dispatch and the FIFO. Caliptra authenticates and
//! consumes images 0 (FMC/runtime), 1 (SoC manifest), then 2 (MCU runtime).
//! MCU ROM services standard USB requests without copying images through I3C.

use crate::{fatal_error, rom::Soc, RecoveryInterface, RomParameters};
use caliptra_mcu_error::{McuError, McuResult};
use caliptra_mcu_ocp::protocol::device_status::DeviceStatusValue;
use caliptra_mcu_ocp::protocol::recovery_status::DeviceRecoveryStatus;
use caliptra_mcu_registers_generated::usb_combo::{bits, regs::UsbCombo};
use caliptra_mcu_romtime::{Mci, StaticRef};
use caliptra_mcu_usb_common::{LpcipUsbDriver, UsbParams, UsbPoll};
use tock_registers::interfaces::{ReadWriteable, Readable, Writeable};

pub(crate) fn validate(params: &RomParameters, mci: &Mci) -> McuResult<()> {
    let usb = params.recovery_interface == RecoveryInterface::Usb;
    let provider_boot = params.request_recovery_boot
        || mci.registers.mci_reg_generic_input_wires[1].get() & (1 << 29) != 0;
    if usb != params.usb.is_some()
        || (usb
            && (provider_boot
                || params.image_provider_manager.is_some()
                || params.request_network_boot
                || params.force_i3c_services))
    {
        return Err(McuError::ROM_COLD_BOOT_RECOVERY_NOT_CONFIGURED_ERROR);
    }
    if usb
        && params
            .cptra_dma_axi_user
            .is_some_and(|user| user != mci.sram_config_axi_user())
    {
        return Err(McuError::ROM_USB_RECOVERY_DMA_USER_ERROR);
    }
    Ok(())
}

pub(crate) struct UsbRecovery {
    driver: LpcipUsbDriver,
    registers: StaticRef<UsbCombo>,
    enable_logs: bool,
    failure_logged: bool,
}

impl UsbRecovery {
    pub(crate) fn initialize(params: UsbParams) -> McuResult<Self> {
        let enable_logs = params.enable_logs;
        let enable_hub = params.enable_hub;
        let registers = params.registers;
        registers
            .recovery_caliptra_ctrl
            .modify(bits::CaliptraCtrl::OcpPathDisable::CLEAR);
        if registers
            .recovery_caliptra_ctrl
            .is_set(bits::CaliptraCtrl::OcpPathDisable)
        {
            caliptra_mcu_romtime::println!("[mcu-rom-usb] OCP hardware path remains disabled");
            return Err(McuError::ROM_USB_RECOVERY_ERROR);
        }
        let mut driver = LpcipUsbDriver::new(params);
        if let Err(error) = driver.initialize() {
            caliptra_mcu_romtime::println!("[mcu-rom-usb] initialization failed: {:?}", error);
            return Err(McuError::ROM_USB_RECOVERY_ERROR);
        }
        if enable_logs {
            caliptra_mcu_romtime::println!("[mcu-rom-usb] Device 0 ready for hardware recovery");
            if enable_hub {
                caliptra_mcu_romtime::println!("[mcu-rom-usb] Hub connected; Device 0 on port 1");
            }
        }
        Ok(Self {
            driver,
            registers,
            enable_logs,
            failure_logged: false,
        })
    }

    fn log_failure(&mut self, soc: &Soc) -> bool {
        if self.failure_logged {
            return false;
        }
        let device = self.registers.recovery_device_status_0.get();
        let status = self.registers.recovery_recovery_status.get();
        if matches!(device & 0xf, 2 | 14 | 15)
            || status & 0xf >= DeviceRecoveryStatus::Failed as u32
            || soc.cptra_fw_fatal_error()
            || soc.cptra_hw_fatal_error()
        {
            self.failure_logged = true;
            caliptra_mcu_romtime::println!(
                "[mcu-rom-usb] Recovery failure: DEVICE_STATUS_0={} DEVICE_STATUS_1={} RECOVERY_STATUS={}",
                caliptra_mcu_romtime::HexWord(device),
                caliptra_mcu_romtime::HexWord(self.registers.recovery_device_status_1.get()),
                caliptra_mcu_romtime::HexWord(status)
            );
            soc.log_usb_recovery_errors();
            return true;
        }
        false
    }

    pub(crate) fn poll(&mut self, mci: &Mci, soc: &Soc) {
        self.log_failure(soc);
        if self
            .registers
            .recovery_caliptra_status
            .is_set(bits::CaliptraStatus::BatchAborted)
        {
            self.registers
                .recovery_caliptra_ctrl
                .modify(bits::CaliptraCtrl::OcpProtocolErrorGeneral::SET);
        }
        match self.driver.poll() {
            Ok(UsbPoll::ConfigurationChanged(configuration)) => {
                if self.enable_logs {
                    caliptra_mcu_romtime::println!("[mcu-rom-usb] configuration {}", configuration);
                }
            }
            Ok(UsbPoll::Disconnected) => {
                caliptra_mcu_romtime::println!("[mcu-rom-usb] disconnected during recovery");
                self.serve_failed_recovery(mci, soc);
            }
            Err(error) => {
                caliptra_mcu_romtime::println!("[mcu-rom-usb] service failed: {:?}", error);
                fatal_error(McuError::ROM_USB_RECOVERY_ERROR);
            }
            _ => {}
        }
        if soc.cptra_fw_fatal_error() {
            caliptra_mcu_romtime::println!("[mcu-rom-usb] Core recovery failed");
            self.serve_failed_recovery(mci, soc);
        }
    }

    pub(crate) fn serve_failed_recovery(&mut self, mci: &Mci, soc: &Soc) -> ! {
        caliptra_mcu_romtime::println!(
            "[mcu-rom-usb] Recovery interrupted; servicing USB status until cold reset"
        );
        mci.disable_wdt();
        self.driver.enter_status_only();
        self.registers
            .recovery_caliptra_ctrl
            .modify(bits::CaliptraCtrl::OcpProtocolErrorGeneral::SET);
        loop {
            Self::publish_failure(self.registers);
            self.log_failure(soc);
            match self.driver.poll() {
                Ok(UsbPoll::ConfigurationChanged(configuration)) => {
                    if self.enable_logs {
                        caliptra_mcu_romtime::println!(
                            "[mcu-rom-usb] status-only configuration {}",
                            configuration
                        );
                    }
                }
                Err(error) => {
                    caliptra_mcu_romtime::println!(
                        "[mcu-rom-usb] status service failed: {:?}",
                        error
                    );
                    fatal_error(McuError::ROM_USB_RECOVERY_ERROR);
                }
                _ => {}
            }
        }
    }

    fn publish_failure(registers: StaticRef<UsbCombo>) {
        if registers
            .recovery_recovery_status
            .read(bits::RecoveryStatus::DevRecStatus)
            < DeviceRecoveryStatus::Failed as u32
        {
            registers.recovery_recovery_status.modify(
                bits::RecoveryStatus::DevRecStatus.val(DeviceRecoveryStatus::Failed as u32),
            );
        }
        if registers
            .recovery_device_status_0
            .read(bits::DeviceStatus0::DevStatus)
            != DeviceStatusValue::FatalError as u32
        {
            registers
                .recovery_device_status_0
                .modify(bits::DeviceStatus0::DevStatus.val(DeviceStatusValue::DeviceError as u32));
        }
    }

    pub(crate) fn finish(&self, open: bool) {
        finish(self.registers, open);
    }
}

pub(crate) fn finish(registers: StaticRef<UsbCombo>, open: bool) {
    let status = if open {
        DeviceRecoveryStatus::BootingImage
    } else {
        DeviceRecoveryStatus::Success
    };
    registers
        .recovery_recovery_status
        .write(bits::RecoveryStatus::DevRecStatus.val(status as u32));
    if !open {
        registers
            .recovery_device_status_0
            .write(bits::DeviceStatus0::DevStatus.val(DeviceStatusValue::DeviceHealthy as u32));
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use caliptra_mcu_registers_generated::{mci, usb_dev0_mem};
    use std::boxed::Box;

    fn mci() -> Mci {
        mci_with_wire(0)
    }

    fn mci_with_wire(wire: u32) -> Mci {
        let layout = std::alloc::Layout::new::<mci::regs::Mci>();
        // The MCI register block includes megabytes of SRAM: allocate on heap.
        let memory = unsafe { std::alloc::alloc_zeroed(layout) };
        if memory.is_null() {
            std::alloc::handle_alloc_error(layout);
        }
        unsafe {
            memory
                .add(core::mem::offset_of!(
                    mci::regs::Mci,
                    mci_reg_mcu_sram_config_axi_user
                ))
                .cast::<u32>()
                .write(0x300);
            memory
                .add(core::mem::offset_of!(mci::regs::Mci, mci_reg_generic_input_wires) + 4)
                .cast::<u32>()
                .write(wire);
            Mci::new(StaticRef::new(memory.cast()))
        }
    }

    fn params() -> RomParameters<'static> {
        let registers = Box::leak(Box::new(unsafe { core::mem::zeroed::<UsbCombo>() }));
        let memory = Box::leak(Box::new(unsafe {
            core::mem::zeroed::<usb_dev0_mem::regs::UsbDev0Mem>()
        }));
        RomParameters {
            recovery_interface: RecoveryInterface::Usb,
            usb: Some(UsbParams {
                shared_phy_owner: true,
                enable_hub: false,
                enable_logs: false,
                registers: unsafe { StaticRef::new(registers) },
                packet_memory: unsafe { StaticRef::new(memory) },
                vendor_id: 0xffff,
                product_id: 0xffff,
                device_revision: 0x100,
                self_powered: true,
                max_power_2ma: 0,
                remote_wakeup: false,
                force_full_speed: false,
                poll_limit: 10,
            }),
            ..Default::default()
        }
    }

    #[test]
    fn requires_matching_selection_and_platform_parameters() {
        let mci = mci();
        assert_eq!(validate(&RomParameters::default(), &mci), Ok(()));
        let mut params = params();
        assert_eq!(validate(&params, &mci), Ok(()));
        params.recovery_interface = RecoveryInterface::I3c;
        assert_eq!(
            validate(&params, &mci),
            Err(McuError::ROM_COLD_BOOT_RECOVERY_NOT_CONFIGURED_ERROR)
        );
        params.recovery_interface = RecoveryInterface::Usb;
        params.usb = None;
        assert_eq!(
            validate(&params, &mci),
            Err(McuError::ROM_COLD_BOOT_RECOVERY_NOT_CONFIGURED_ERROR)
        );
    }

    #[test]
    fn dma_requires_the_sram_configuration_user_including_zero() {
        let mci = mci();
        let mut params = params();
        for user in [None, Some(0x300)] {
            params.cptra_dma_axi_user = user;
            assert_eq!(validate(&params, &mci), Ok(()));
        }
        for user in [0, 0xcccc_cccc, 0xdead_beef] {
            params.cptra_dma_axi_user = Some(user);
            assert_eq!(
                validate(&params, &mci),
                Err(McuError::ROM_USB_RECOVERY_DMA_USER_ERROR)
            );
        }
    }

    #[test]
    fn rejects_provider_bypass_network_and_forced_services() {
        let mci = mci();
        let mut params = params();
        params.request_recovery_boot = true;
        assert!(validate(&params, &mci).is_err());
        params.request_recovery_boot = false;
        params.request_network_boot = true;
        assert!(validate(&params, &mci).is_err());
        params.request_network_boot = false;
        params.force_i3c_services = true;
        assert!(validate(&params, &mci).is_err());
        params.force_i3c_services = false;
        assert!(validate(&params, &mci_with_wire(1 << 29)).is_err());
    }

    #[test]
    fn hardware_only_core_failure_is_logged_once_without_mutating_status() {
        use caliptra_mcu_registers_generated::soc;
        let words = Box::leak(Box::new([0u32; core::mem::size_of::<soc::regs::Soc>() / 4]));
        let offset = core::mem::offset_of!(soc::regs::Soc, cptra_hw_error_fatal) / 4;
        words[offset] = 0x10;
        let core_registers = unsafe { StaticRef::new(words.as_ptr().cast::<soc::regs::Soc>()) };
        let soc = Soc::new(core_registers);
        let params = params().usb.unwrap();
        let registers = params.registers;
        registers.recovery_device_status_0.set(1);
        registers.recovery_recovery_status.set(0x21);
        let mut recovery = UsbRecovery {
            driver: LpcipUsbDriver::new(params),
            registers,
            enable_logs: false,
            failure_logged: false,
        };
        assert!(!soc.cptra_fw_fatal_error());
        assert!(recovery.log_failure(&soc));
        assert!(!recovery.log_failure(&soc));
        assert_eq!(core_registers.cptra_hw_error_fatal.get(), 0x10);
        assert_eq!(registers.recovery_device_status_0.get(), 1);
        assert_eq!(registers.recovery_recovery_status.get(), 0x21);
    }

    #[test]
    fn failure_status_preserves_core_error_and_image_index() {
        let registers = params().usb.unwrap().registers;
        registers.recovery_recovery_status.set(0x21);
        registers.recovery_device_status_0.set(3);
        UsbRecovery::publish_failure(registers);
        assert_eq!(registers.recovery_recovery_status.get(), 0x2c);
        assert_eq!(registers.recovery_device_status_0.get(), 2);
        registers.recovery_recovery_status.set(0x2d);
        registers.recovery_device_status_0.set(0xf);
        UsbRecovery::publish_failure(registers);
        assert_eq!(registers.recovery_recovery_status.get(), 0x2d);
        assert_eq!(registers.recovery_device_status_0.get(), 0xf);
    }

    #[test]
    fn finish_preserves_open_state_or_publishes_success() {
        let params = params();
        let registers = params.usb.unwrap().registers;
        registers.recovery_device_status_0.set(4);
        finish(registers, true);
        assert_eq!(registers.recovery_recovery_status.get(), 2);
        assert_eq!(registers.recovery_device_status_0.get(), 4);
        finish(registers, false);
        assert_eq!(registers.recovery_recovery_status.get(), 3);
        assert_eq!(registers.recovery_device_status_0.get(), 1);
    }
}
