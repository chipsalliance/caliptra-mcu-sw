// Licensed under the Apache-2.0 license

//! Persistent, polled EP0 service for FPGA device-framework testing.
//! No transfer waits here: either controller may be reset or receive a new SETUP
//! while its peer's host transfer is incomplete.

use super::*;
use core::convert::Infallible;

const CONNECTED: u32 = KEEP_PHY_CLOCK
    | usb_combo::bits::DevcmdstatT::DevEn::SET.value
    | usb_combo::bits::DevcmdstatT::Dcon::SET.value;
const SETUP: u32 = usb_combo::bits::DevcmdstatT::Setup::SET.value;
const RESET: u32 = usb_combo::bits::DevcmdstatT::DresC::SET.value;
const VBUS: u32 = usb_combo::bits::DevcmdstatT::VbusDebounced::SET.value;
const TRANSFER_POLL_LIMIT: u32 = 10_000_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Completion {
    None,
    Address(u8),
    Configuration(u8),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Idle,
    Aborting,
    DataIn { terminating_zlp: bool },
    StatusOut,
    StatusIn(Completion),
}

struct Ep0 {
    driver: LpcipUsbDriver,
    phase: Phase,
    address: u8,
    configuration: u8,
    setup: Option<SetupPacket>,
    polls: u32,
}

impl LpcipUsbDriver {
    /// Remain in ROM servicing both internal devices, without recovery boot.
    ///
    /// Hub class requests remain hardware-managed. Test identities and the
    /// existing Device 0 OCP descriptors are retained, but OCP claims are
    /// disabled and class/vendor requests are stalled by software.
    pub fn run_compliance(
        &mut self,
        regs: StaticRef<usb_dev1::regs::UsbDev1>,
        memory: StaticRef<usb_dev1_mem::regs::UsbDev1Mem>,
    ) -> Result<Infallible, LpcipUsbError> {
        let device1 = Self {
            regs: self.regs,
            controller: DeviceController::Device1 { regs, memory },
            poll_limit: self.poll_limit,
        };
        self.disconnect_and_initialize();
        device1.initialize_endpoints();
        self.regs.recovery_caliptra_ctrl.set(
            usb_combo::bits::CaliptraCtrl::OcpPathDisable::SET.value
                | usb_combo::bits::CaliptraCtrl::OcpClaimAbort::SET.value,
        );
        self.initialize_phy()?;
        self.wait_for_vbus()?;
        // Polling owns the controllers; do not deliver unhandled CPU IRQs.
        self.connect();
        device1.connect();
        let mut devices = [
            Ep0::new(Self {
                regs: self.regs,
                controller: self.controller,
                poll_limit: self.poll_limit,
            }),
            Ep0::new(device1),
        ];
        caliptra_mcu_romtime::println!(
            "[usb-compliance] Serving Device 0 and Device 1 continuously; no recovery boot"
        );
        let mut had_vbus = true;
        loop {
            let vbus = self.controller.command_status() & VBUS != 0;
            if !vbus {
                if had_vbus {
                    caliptra_mcu_romtime::println!("[usb-compliance] VBUS lost");
                    for device in &mut devices {
                        device.reset(false);
                    }
                }
            } else {
                for device in &mut devices {
                    device.poll();
                }
            }
            had_vbus = vbus;
            core::hint::spin_loop();
        }
    }
}

impl Ep0 {
    fn new(driver: LpcipUsbDriver) -> Self {
        Self {
            driver,
            phase: Phase::Idle,
            address: 0,
            configuration: 0,
            setup: None,
            polls: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lpcip::tests::{test_device1, test_driver};
    use caliptra_mcu_ocp::usb::setup::BmRequestType;

    fn setup(kind: u8, request: u8, value: u16, index: u16, length: u16) -> SetupPacket {
        SetupPacket {
            bm_request_type: BmRequestType(kind),
            b_request: request,
            w_value: value.to_le_bytes(),
            w_index: index.to_le_bytes(),
            w_length: length.to_le(),
        }
    }

    fn device() -> Ep0 {
        let driver = test_driver();
        driver.initialize_endpoints();
        driver.connect();
        Ep0::new(driver)
    }

    fn finish_status(device: &mut Ep0) {
        device.driver.write_memory_word(EP0_IN_DESCRIPTOR, 0);
        device.poll();
        assert_eq!(device.phase, Phase::Idle);
    }

    fn read_buffer(device: &Ep0, length: usize) -> Vec<u8> {
        (0..length)
            .map(|index| {
                device
                    .driver
                    .read_memory_word(IN_BUFFER_OFFSET / 4 + index / 4)
                    .to_le_bytes()[index % 4]
            })
            .collect()
    }

    #[test]
    fn configuration_commits_after_status_and_can_be_cleared() {
        let mut device = device();
        device.dispatch(&setup(0, 5, 9, 0, 0));
        assert_eq!(device.address, 0);
        assert_eq!(device.driver.controller.command_status() & 127, 9);
        finish_status(&mut device);
        assert_eq!(device.address, 9);
        device.dispatch(&setup(0, 9, 1, 0, 0));
        assert_eq!(device.configuration, 0);
        finish_status(&mut device);
        assert_eq!(device.configuration, 1);
        device.dispatch(&setup(0x80, 8, 0, 0, 1));
        assert_eq!(read_buffer(&device, 1), [1]);
        device.dispatch(&setup(0, 9, 0, 0, 0));
        finish_status(&mut device);
        assert_eq!(device.configuration, 0);
        device.dispatch(&setup(0x80, 8, 0, 0, 1));
        assert_eq!(read_buffer(&device, 1), [0]);
    }

    #[test]
    fn peers_progress_while_one_device_has_an_incomplete_transfer() {
        let mut device0 = device();
        let driver1 = LpcipUsbDriver {
            regs: device0.driver.regs,
            controller: test_device1(),
            poll_limit: None,
        };
        driver1.initialize_endpoints();
        driver1.connect();
        let mut device1 = Ep0::new(driver1);
        device0.dispatch(&setup(0x80, 6, 0x100, 0, 18));
        device1.address = 5;
        device1.dispatch(&setup(0, 9, 1, 0, 0));
        for _ in 0..10 {
            device0.poll();
            device1.poll();
        }
        assert!(matches!(device0.phase, Phase::DataIn { .. }));
        finish_status(&mut device1);
        assert_eq!(device1.configuration, 1);
        assert!(matches!(device0.phase, Phase::DataIn { .. }));
        device1.dispatch(&setup(0x80, 6, 0x200, 0, 255));
        assert_eq!(read_buffer(&device1, 18), DEVICE1_CONFIGURATION);
    }

    #[test]
    fn reset_clears_pending_configuration_address_and_stalls() {
        let mut device = device();
        device.address = 23;
        device.configuration = 1;
        device.dispatch(&setup(0, 9, 0, 0, 0));
        device
            .driver
            .controller
            .set_command_status(CONNECTED | RESET);
        device.poll();
        assert_eq!(device.address, 0);
        assert_eq!(device.configuration, 0);
        assert_eq!(device.phase, Phase::Idle);
        assert_eq!(device.driver.read_memory_word(EP0_IN_DESCRIPTOR), 0);
        assert_eq!(device.driver.read_memory_word(EP0_OUT_DESCRIPTOR), 0);
        assert_eq!(device.driver.controller.command_status() & 127, 0);
        // Model the W1C register and start another enumeration.
        device.driver.controller.set_command_status(CONNECTED);
        device.dispatch(&setup(0x80, 6, 0x100, 0, 18));
        assert!(matches!(device.phase, Phase::DataIn { .. }));
    }

    #[test]
    fn setup_aborts_old_transfer_without_committing_its_configuration() {
        let mut device = device();
        device.address = 4;
        device.dispatch(&setup(0, 9, 1, 0, 0));
        let request = setup(0x80, 8, 0, 0, 1);
        device
            .driver
            .write_buffer(SETUP_BUFFER_OFFSET, request.as_bytes());
        device
            .driver
            .controller
            .set_command_status(CONNECTED | 4 | SETUP);
        device.poll();
        assert_eq!(device.phase, Phase::Aborting);
        assert_eq!(device.configuration, 0);
        // Hardware completes EPSKIP before software touches the old buffers.
        device.skip(0);
        device.poll();
        assert_eq!(device.configuration, 0);
        assert_eq!(read_buffer(&device, 1), [0]);
        assert!(matches!(device.phase, Phase::DataIn { .. }));
    }

    #[test]
    fn new_setup_recovers_from_stall_and_replaces_setup_during_skip() {
        let mut device = device();
        device.dispatch(&setup(0x80, 6, 0x3ee, 0, 18));
        assert_ne!(device.driver.read_memory_word(EP0_IN_DESCRIPTOR) & STALL, 0);
        let first = setup(0x80, 6, 0x100, 0, 18);
        device
            .driver
            .write_buffer(SETUP_BUFFER_OFFSET, first.as_bytes());
        device
            .driver
            .controller
            .set_command_status(CONNECTED | SETUP);
        device.poll();
        let latest = setup(0x80, 6, 0x600, 0, 10);
        device
            .driver
            .write_buffer(SETUP_BUFFER_OFFSET, latest.as_bytes());
        device.skip(0);
        device.poll();
        assert_eq!(read_buffer(&device, 10), DEVICE1_QUALIFIER);
        assert_eq!(device.driver.read_memory_word(EP0_IN_DESCRIPTOR) & STALL, 0);
    }

    #[test]
    fn descriptors_remain_available_after_configuration() {
        let mut device = device();
        device.address = 7;
        device.configuration = 1;
        for kind in [1, 2, 6, 7] {
            device.dispatch(&setup(0x80, 6, kind << 8, 0, 255));
            let expected = match kind {
                1 => 18,
                2 | 7 => core::mem::size_of::<ConfigurationTree>(),
                6 => 10,
                _ => unreachable!(),
            };
            assert_eq!(read_buffer(&device, 2)[1], kind as u8);
            assert_eq!(
                device.driver.read_memory_word(EP0_IN_DESCRIPTOR),
                LpcipUsbDriver::buffer_descriptor(IN_BUFFER_OFFSET, expected) | ACTIVE,
            );
        }
        device.dispatch(&setup(0x80, 6, 0x301, LANG_ID_ENGLISH_US, 255));
        assert_eq!(
            read_buffer(&device, OCP_INTERFACE_STRING_DESCRIPTOR_LEN),
            OcpInterfaceStringDescriptor::ocp().as_bytes(),
        );
    }

    #[test]
    fn status_and_interface_requests_validate_recipient_and_state() {
        let mut device = device();
        device.address = 7;
        device.configuration = 1;
        for (recipient, expected) in [(0x80, [1, 0]), (0x81, [0, 0]), (0x82, [0, 0])] {
            device.dispatch(&setup(recipient, 0, 0, 0, 2));
            assert_eq!(read_buffer(&device, 2), expected);
        }
        device.dispatch(&setup(0x81, 10, 0, 0, 1));
        assert_eq!(read_buffer(&device, 1), [0]);
        device.dispatch(&setup(1, 11, 0, 0, 0));
        assert_eq!(device.phase, Phase::StatusIn(Completion::None));
        for invalid in [
            setup(1, 11, 1, 0, 0),
            setup(0x82, 0, 0, 1, 2),
            setup(0x80, 0, 1, 0, 2),
            setup(0x81, 10, 0, 1, 1),
            setup(0, 9, 2, 0, 0),
            setup(0, 5, 128, 0, 0),
            setup(0xa1, 0, 0, 0, 2),
            setup(0x80, 6, 0x101, 0, 18),
        ] {
            device.clear_ep0();
            device.dispatch(&invalid);
            assert_eq!(device.phase, Phase::Idle);
            assert_ne!(device.driver.read_memory_word(EP0_IN_DESCRIPTOR) & STALL, 0);
        }
    }

    #[test]
    fn data_and_status_phases_complete_without_blocking() {
        let mut device = device();
        device.read(&[0x55; 64], 65);
        assert_eq!(
            device.phase,
            Phase::DataIn {
                terminating_zlp: true
            }
        );
        device.driver.write_memory_word(EP0_IN_DESCRIPTOR, 0);
        device.poll();
        assert_eq!(
            device.phase,
            Phase::DataIn {
                terminating_zlp: false
            }
        );
        assert_eq!(
            device.driver.read_memory_word(EP0_IN_DESCRIPTOR),
            LpcipUsbDriver::buffer_descriptor(IN_BUFFER_OFFSET, 0) | ACTIVE,
        );
        device.driver.write_memory_word(EP0_IN_DESCRIPTOR, 0);
        device.poll();
        assert_eq!(device.phase, Phase::StatusOut);
        device.driver.write_memory_word(EP0_OUT_DESCRIPTOR, 0);
        device.poll();
        assert_eq!(device.phase, Phase::Idle);
        device.read(&[0; 18], 8);
        assert_eq!(
            device.driver.read_memory_word(EP0_IN_DESCRIPTOR),
            LpcipUsbDriver::buffer_descriptor(IN_BUFFER_OFFSET, 8) | ACTIVE,
        );
    }

    #[test]
    fn unrouted_device_phy_test_mode_is_not_acknowledged() {
        let mut device = device();
        device
            .driver
            .controller
            .set_command_status(CONNECTED | usb_combo::bits::DevcmdstatT::Speed.val(2).value);
        device.dispatch(&setup(0, 3, 2, 0x400, 0));
        assert_eq!(device.phase, Phase::Idle);
        assert_ne!(device.driver.read_memory_word(EP0_IN_DESCRIPTOR) & STALL, 0);
    }

    #[test]
    fn stalled_host_times_out_without_blocking_peer_or_using_dma_buffers() {
        let mut device = device();
        device.read(&[1], 1);
        device.polls = TRANSFER_POLL_LIMIT - 1;
        device.poll();
        assert_eq!(device.phase, Phase::Aborting);
        assert!(device.skipping());
        assert_ne!(
            device.driver.read_memory_word(EP0_IN_DESCRIPTOR) & ACTIVE,
            0
        );
        device.skip(0);
        device.poll();
        assert_eq!(device.phase, Phase::Idle);
    }

    #[test]
    fn cable_loss_discards_state_and_waits_for_dma_before_reusing_memory() {
        let mut device = device();
        device.address = 12;
        device.configuration = 1;
        device.read(&[1, 2], 2);
        device.reset(false);
        assert_eq!(device.address, 0);
        assert_eq!(device.configuration, 0);
        assert_eq!(device.phase, Phase::Aborting);
        assert_ne!(
            device.driver.read_memory_word(EP0_IN_DESCRIPTOR) & ACTIVE,
            0
        );
        device.skip(0);
        device.poll();
        assert_eq!(device.phase, Phase::Idle);
        assert_eq!(device.driver.read_memory_word(EP0_IN_DESCRIPTOR), 0);
    }

    #[test]
    fn startup_disables_recovery_claims_before_enabling_devices() {
        let mut driver = test_driver();
        let DeviceController::Device1 { regs, memory } = test_device1() else {
            unreachable!()
        };
        assert_eq!(
            driver.run_compliance(regs, memory),
            Err(LpcipUsbError::UnsupportedPhy),
        );
        assert_ne!(
            driver.regs.recovery_caliptra_ctrl.get()
                & usb_combo::bits::CaliptraCtrl::OcpPathDisable::SET.value,
            0,
        );
        assert_eq!(regs.devcmdstat.get(), KEEP_PHY_CLOCK);
        assert_eq!(regs.inten.get(), 0);
    }

    #[test]
    fn inactive_descriptor_without_in_completion_does_not_commit_status() {
        let mut device = device();
        device.address = 3;
        device.dispatch(&setup(0, 9, 1, 0, 0));
        device.driver.write_memory_word(EP0_IN_DESCRIPTOR, 0);
        // Plain test memory does not implement W1C: emulate a cleared INTSTAT.
        device.driver.controller.clear_interrupts(0);
        device.poll();
        assert_eq!(device.configuration, 0);
        assert_eq!(device.phase, Phase::StatusIn(Completion::Configuration(1)));
        device.driver.controller.clear_interrupts(2);
        device.poll();
        assert_eq!(device.configuration, 1);
        assert_eq!(device.phase, Phase::Idle);
    }
}

impl Ep0 {
    fn command(&self, acknowledge: u32) {
        let address = match self.phase {
            Phase::StatusIn(Completion::Address(address)) => address,
            _ => self.address,
        };
        // Never echo read-only or W1C status bits back into DEVCMDSTAT.
        self.driver
            .controller
            .set_command_status(CONNECTED | u32::from(address) | acknowledge);
    }

    fn reset(&mut self, acknowledge: bool) {
        self.address = 0;
        self.configuration = 0;
        self.phase = if acknowledge {
            Phase::Idle
        } else {
            Phase::Aborting
        };
        self.setup = None;
        self.polls = 0;
        if acknowledge {
            self.clear_ep0();
        } else {
            // Cable removal does not synchronously stop descriptor DMA.
            self.skip(3);
        }
        self.command(if acknowledge { RESET } else { 0 });
        self.driver
            .controller
            .clear_interrupts(IMPLEMENTED_INTERRUPTS);
    }

    fn clear_ep0(&self) {
        self.driver.write_memory_word(EP0_OUT_DESCRIPTOR, 0);
        self.driver.write_memory_word(EP0_IN_DESCRIPTOR, 0);
        self.driver.write_memory_word(
            SETUP_DESCRIPTOR,
            LpcipUsbDriver::buffer_offset(SETUP_BUFFER_OFFSET),
        );
    }

    fn skip(&self, value: u32) {
        match self.driver.controller {
            DeviceController::Device0 { regs, .. } => regs.dev0_csr_epskip.set(value),
            DeviceController::Device1 { regs, .. } => regs.epskip.set(value),
        }
    }

    fn skipping(&self) -> bool {
        let value = match self.driver.controller {
            DeviceController::Device0 { regs, .. } => regs.dev0_csr_epskip.get(),
            DeviceController::Device1 { regs, .. } => regs.epskip.get(),
        };
        value & 3 != 0
    }

    fn in_completed(&self) -> bool {
        let interrupts = match self.driver.controller {
            DeviceController::Device0 { regs, .. } => regs.dev0_csr_intstat.get(),
            DeviceController::Device1 { regs, .. } => regs.intstat.get(),
        };
        self.driver.read_memory_word(EP0_IN_DESCRIPTOR) & ACTIVE == 0
            && interrupts & usb_combo::bits::IntstatT::Ep0in::SET.value != 0
    }

    fn poll(&mut self) {
        let status = self.driver.controller.command_status();
        if status & RESET != 0 {
            self.reset(true);
            caliptra_mcu_romtime::println!(
                "[usb-compliance] Device {} reset",
                self.driver.controller.number()
            );
            return;
        }

        // Commit completed status stages even if the next SETUP has arrived.
        if let Phase::StatusIn(completion) = self.phase {
            if self.in_completed() {
                self.complete(completion);
            }
        }
        if status & SETUP != 0 && self.phase != Phase::Aborting {
            self.setup = Some(self.driver.read_setup());
            self.phase = Phase::Aborting;
            self.polls = 0;
            self.skip(3);
        }
        if self.phase == Phase::Aborting {
            if self.skipping() {
                self.check_timeout();
                return;
            }
            // A newer SETUP can supersede the one that initiated the skip.
            if status & SETUP != 0 {
                self.setup = Some(self.driver.read_setup());
            }
            self.clear_ep0();
            self.phase = Phase::Idle;
            self.command(SETUP);
            self.driver.controller.clear_interrupts(3);
            if let Some(setup) = self.setup.take() {
                self.dispatch(&setup);
            }
            return;
        }
        match self.phase {
            Phase::DataIn { terminating_zlp } if self.in_completed() => {
                self.driver.clear_endpoint_interrupt(EP0_IN_DESCRIPTOR);
                if terminating_zlp {
                    self.driver.arm_in(0);
                    self.phase = Phase::DataIn {
                        terminating_zlp: false,
                    };
                } else {
                    self.driver.clear_endpoint_interrupt(EP0_OUT_DESCRIPTOR);
                    self.driver.arm_out(0);
                    self.phase = Phase::StatusOut;
                }
                self.polls = 0;
            }
            Phase::StatusOut if self.driver.read_memory_word(EP0_OUT_DESCRIPTOR) & ACTIVE == 0 => {
                self.phase = Phase::Idle;
                self.polls = 0;
            }
            _ => {}
        }
        self.check_timeout();
    }

    fn check_timeout(&mut self) {
        if self.phase == Phase::Idle {
            return;
        }
        self.polls += 1;
        if self.polls == TRANSFER_POLL_LIMIT {
            caliptra_mcu_romtime::println!(
                "[usb-compliance] Device {} transfer timeout in {:?}",
                self.driver.controller.number(),
                self.phase
            );
            // A failed skip must not lead to writes to DMA-owned buffers.
            if self.phase != Phase::Aborting {
                self.skip(3);
                self.setup = None;
                self.phase = Phase::Aborting;
            }
            self.polls = 0;
        }
    }

    fn complete(&mut self, completion: Completion) {
        match completion {
            Completion::Address(address) => self.address = address,
            Completion::Configuration(configuration) => {
                self.configuration = configuration;
                caliptra_mcu_romtime::println!(
                    "[usb-compliance] Device {} configuration {}",
                    self.driver.controller.number(),
                    configuration
                );
            }
            Completion::None => {}
        }
        self.phase = Phase::Idle;
        self.polls = 0;
    }

    fn read(&mut self, bytes: &[u8], requested: usize) {
        let length = bytes.len().min(requested);
        if requested == 0 {
            self.status(Completion::None);
            return;
        }
        self.driver.write_buffer(IN_BUFFER_OFFSET, &bytes[..length]);
        self.driver.clear_endpoint_interrupt(EP0_IN_DESCRIPTOR);
        self.driver.arm_in(length);
        self.phase = Phase::DataIn {
            terminating_zlp: length < requested
                && length.is_multiple_of(MAX_TRANSFER_SIZE as usize),
        };
        self.polls = 0;
    }

    fn status(&mut self, completion: Completion) {
        self.phase = Phase::StatusIn(completion);
        self.command(0);
        self.driver.clear_endpoint_interrupt(EP0_IN_DESCRIPTOR);
        self.driver.arm_in(0);
        self.polls = 0;
    }

    fn stall(&mut self, setup: &SetupPacket) {
        caliptra_mcu_romtime::println!(
            "[usb-compliance] Device {} STALL {:02x} {:02x} value={:04x} index={:04x} length={}",
            self.driver.controller.number(),
            setup.bm_request_type.0,
            setup.b_request,
            u16::from_le_bytes(setup.w_value),
            u16::from_le_bytes(setup.w_index),
            setup.data_length()
        );
        self.driver.stall_ep0();
        self.phase = Phase::Idle;
    }

    fn dispatch(&mut self, setup: &SetupPacket) {
        let request_type = setup.bm_request_type.0;
        let value = u16::from_le_bytes(setup.w_value);
        let index = u16::from_le_bytes(setup.w_index);
        let length = setup.data_length();
        match (request_type, setup.standard_request()) {
            (0x80, Some(StandardRequest::GetDescriptor)) => {
                if self.descriptor(setup) {
                    return;
                }
            }
            (0, Some(StandardRequest::SetAddress))
                if index == 0 && length == 0 && value <= 127 && self.configuration == 0 =>
            {
                self.status(Completion::Address(value as u8));
                return;
            }
            (0, Some(StandardRequest::SetConfiguration))
                if index == 0 && length == 0 && value <= 1 && self.address != 0 =>
            {
                self.status(Completion::Configuration(value as u8));
                return;
            }
            (0x80, Some(StandardRequest::GetConfiguration))
                if value == 0 && index == 0 && length == 1 && self.address != 0 =>
            {
                self.read(&[self.configuration], 1);
                return;
            }
            (0x80, Some(StandardRequest::GetStatus))
                if value == 0 && index == 0 && length == 2 && self.address != 0 =>
            {
                self.read(&[1, 0], 2);
                return;
            }
            (0x81, Some(StandardRequest::GetStatus))
                if value == 0 && index == 0 && length == 2 && self.configuration != 0 =>
            {
                self.read(&[0, 0], 2);
                return;
            }
            (0x82, Some(StandardRequest::GetStatus))
                if value == 0 && matches!(index, 0 | 0x80) && length == 2 && self.address != 0 =>
            {
                self.read(&[0, 0], 2);
                return;
            }
            (0x81, Some(StandardRequest::GetInterface))
                if value == 0 && index == 0 && length == 1 && self.configuration != 0 =>
            {
                self.read(&[0], 1);
                return;
            }
            (1, Some(StandardRequest::SetInterface))
                if value == 0 && index == 0 && length == 0 && self.configuration != 0 =>
            {
                self.status(Completion::None);
                return;
            }
            _ => {}
        }
        self.stall(setup);
    }

    fn descriptor(&mut self, setup: &SetupPacket) -> bool {
        let length = setup.data_length() as usize;
        let index = setup.descriptor_index();
        let language = u16::from_le_bytes(setup.w_index);
        let device0 = self.driver.controller.number() == 0;
        match setup.w_value[1] {
            1 if index == 0 && language == 0 => {
                let descriptor = if device0 {
                    DeviceDescriptor::ocp(0x0200, 0x0424, 0x0007, 0x0100, 0, 0, 0)
                } else {
                    DEVICE1_DESCRIPTOR
                };
                self.read(descriptor.as_bytes(), length);
            }
            kind @ (2 | 7) if index == 0 && language == 0 => {
                if device0 {
                    let descriptor = ConfigurationTree::ocp(
                        BmAttributes::new(true, false),
                        MaxPower2mA(50),
                        None,
                        MAX_TRANSFER_SIZE,
                        MAX_TRANSFER_SIZE,
                    );
                    let mut bytes = [0; MAX_TRANSFER_SIZE as usize];
                    let data = descriptor.as_bytes();
                    bytes[..data.len()].copy_from_slice(data);
                    bytes[1] = kind;
                    self.read(&bytes[..data.len()], length);
                } else {
                    let mut bytes = DEVICE1_CONFIGURATION;
                    bytes[1] = kind;
                    self.read(&bytes, length);
                }
            }
            6 if index == 0 && language == 0 => self.read(&DEVICE1_QUALIFIER, length),
            3 if index == 0 && language == 0 => {
                self.read(StringDescriptorZero::ocp().as_bytes(), length);
            }
            3 if device0
                && index == OCP_INTERFACE_STRING_INDEX
                && language == LANG_ID_ENGLISH_US =>
            {
                self.read(OcpInterfaceStringDescriptor::ocp().as_bytes(), length);
            }
            _ => return false,
        }
        true
    }
}
