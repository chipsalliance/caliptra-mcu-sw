// Licensed under the Apache-2.0 license

pub mod flash;
pub mod ocp;

use core::num::NonZeroU8;

use bitfield::bitfield;
use registers_generated::i3c;
use registers_generated::i3c::bits::{IndirectFifoStatus0, RecIntfCfg, RecIntfRegW1cAccess};
use romtime::StaticRef;
use smlang::statemachine;
use tock_registers::interfaces::{ReadWriteable, Readable, Writeable};
use zerocopy::IntoBytes;

const ACTIVATE_RECOVERY_IMAGE_CMD: u32 = 0xF;

/// A trait defining how an image can be provided to the i3c recovery interface.  This allows
/// multiple providers (e.g. flash, usb, etc.) to independently provide images while utilizing the
/// same i3c bypass recovery load logic.
pub trait ImageProvider {
    /// A blocking call which waits until the image is ready to be loaded into the recovery
    /// interface.  It will return the size of the image being loaded in bytes.  This must be called
    /// prior to `next_bytes`.
    ///
    /// This could return an error if the underlying provider encounters an error waiting for the
    /// image or processing any header related data.
    #[allow(clippy::result_unit_err)]
    fn image_ready(&mut self, image_index: u32) -> Result<usize, ()>;

    /// Retrieve up to the next len(data) number of bytes in the image.  The slice will be updated
    /// to include the new set of data, including having the length adjusted to indicate the number
    /// of bytes actually loaded.
    ///
    /// This call will block if the next bytes are not yet available.  The data will only be
    /// partially populated in the case the image ends prior to the entire buffer.  
    ///
    /// This could return an error if the underlying provider encounters an error reading the
    /// image.
    #[allow(clippy::result_unit_err)]
    fn next_bytes(&mut self, data: &mut [u8]) -> Result<(), ()>;

    /// Return the number of image bytes which have been loaded by the given provider.
    fn bytes_loaded(&self) -> usize;
}

/// Policy for handling errors from an [`ImageProvider`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorPolicy {
    /// On error, skip this provider and try the next one.
    Continue,
    /// Retry up to N times, then fall through to the next provider.
    Retry(NonZeroU8),
    /// Retry indefinitely.
    RetryForever,
}

/// An [`ImageProvider`] paired with its error-handling policy.
pub struct ImageProviderEntry<'a> {
    pub provider: &'a mut dyn ImageProvider,
    pub policy: ErrorPolicy,
}

/// Manages a sequence of [`ImageProviderEntry`]s, tracking the active provider
/// and retry count.
pub struct ImageProviderManager<'a> {
    entries: &'a mut [ImageProviderEntry<'a>],
    current: usize,
    retries: u8,
}

impl<'a> ImageProviderManager<'a> {
    pub fn new(entries: &'a mut [ImageProviderEntry<'a>]) -> Self {
        Self {
            entries,
            current: 0,
            retries: 0,
        }
    }

    /// Returns the current provider, incrementing the retry counter.
    /// Uses the retry policy to determine whether to stay on the current
    /// provider or advance.
    ///
    /// - First call for a provider: returns it (retries = 0).
    /// - `Continue`: immediately advances to the next provider on next call.
    /// - `Retry(n)`: stays on current while retries < n, then advances.
    /// - `RetryForever`: stays on current indefinitely.
    ///
    /// Returns `None` if all providers are exhausted.
    fn provider(&mut self) -> Option<&mut (dyn ImageProvider + 'a)> {
        if self.retries == 0 {
            self.retries += 1;
        } else if let Some(policy) = self.entries.get(self.current).map(|c| c.policy) {
            match policy {
                ErrorPolicy::Continue => {
                    self.current += 1;
                    self.retries = 0;
                }
                ErrorPolicy::Retry(n) => {
                    if self.retries < n.get() {
                        self.retries += 1;
                    } else {
                        self.current += 1;
                        self.retries = 0;
                    }
                }
                ErrorPolicy::RetryForever => {
                    self.retries = self.retries.saturating_add(1);
                }
            }
        }

        // Explicit reborrow (`&mut *`) is required because the closure
        // boundary prevents the implicit reborrow the compiler would
        // insert at a normal coercion site (e.g. `return Some(c.provider)`).
        // The `+ 'a` on the return type is also necessary: without it the
        // default trait-object bound ties to the `&mut self` borrow, which
        // is shorter than `'a` and causes a lifetime mismatch.
        self.entries.get_mut(self.current).map(|c| &mut *c.provider)
    }
}

statemachine! {
    derive_states: [Clone, Copy, Debug],
    transitions: {
        // syntax: CurrentState Event [guard] / action = NextState

        // start by reading ProtCap to see if the device supports recovery
        *ReadProtCap + ProtCap(ProtCap2) [check_device_status_support] = ReadDeviceStatus,

        // read the device status to see if it needs recovery
        ReadDeviceStatus + DeviceStatus(DeviceStatus0) [check_device_status_healthy] = Done,

        // if the device needs recovery, send the recovery control message
        ReadDeviceStatus + DeviceStatus(DeviceStatus0) [check_device_status_recovery]
             = WaitForRecoveryStatus,

        // send the requested recovery image
        WaitForRecoveryStatus + RecoveryStatus(RecoveryStatus) [check_recovery_status_awaiting]
             = TransferringImage,

        TransferringImage + TransferComplete  = WaitForRecoveryPending,

        // activate the recovery image after it has been processed
        WaitForRecoveryPending + DeviceStatus(DeviceStatus0) [check_device_status_recovery_pending]
             = Activate,

        // check if we need to send another recovery image (if awaiting image is set and running recovery)
        Activate + CheckFwActivation = CheckFwActivation,

        // Use device_status to detect when Caliptra has processed the activation
        // and is ready for the next image. This avoids acting on a stale
        // recovery_status that still shows AWAITING_IMAGE from the previous
        // request_image call.
        CheckFwActivation + DeviceStatus(DeviceStatus0) [check_device_status_recovery]
             = WaitForRecoveryStatus,

        CheckFwActivation + RecoveryStatus(RecoveryStatus) [check_recovery_status_booting_mcu_img]
             = Done,

    }
}

bitfield! {
    pub struct ProtCap2(u32);
    impl Debug;
    pub identification, set_identification: 16;
    pub forced_recovery, set_forced_recovery: 17;
    pub mgmt_reset, set_mgmt_reset: 18;
    pub device_reset, set_device_reset: 19;
    pub device_status, set_device_status: 20;
    pub recovery_memory_access, set_recovery_memory_access: 21;
    pub local_c_image_support, set_local_c_image_support: 22;
    pub push_c_image_support, set_push_c_image_support: 23;
    pub interface_isolation, set_interface_isolation: 24;
    pub hardware_status, set_hardware_status: 25;
    pub vendors_command, set_vendors_command: 26;
}

bitfield! {
    pub struct DeviceStatus0(u32);
    impl Debug;
    pub device_status, set_device_status: 7,0;
    pub protocol_error, set_protocol_error: 15,8;
    pub recovery_reason, set_recovery_reason: 31,16;

}

bitfield! {
    pub struct RecoveryCtrl0(u32);
    impl Debug;
    pub cms, set_cms: 7,0;
    pub rec_img_sel, set_rec_img_sel: 15,8;
    pub activate_rec_image, set_activate_rec_image: 23,16;

}

// Device status codes (Byte 0)
pub mod device_status_code {
    pub const DEVICE_HEALTHY: u8 = 0x1;
    pub const RECOVERY_MODE: u8 = 0x3;
    pub const RECOVERY_PENDING: u8 = 0x4;
}

// RECOVERY_STATUS register (32 bits)
bitfield! {
    #[derive(Clone, Copy)]
    pub struct RecoveryStatus(u32);
    impl Debug;

    // Bits 3:0 - Device recovery status
    pub dev_rec_status, set_dev_rec_status: 3, 0;
    // Bits 7:4 - Recovery image index
    pub rec_img_index, set_rec_img_index: 7, 4;
    // Bits 15:8 - Vendor specific status
    pub vendor_specific_status, set_vendor_specific_status: 15, 8;
    // Bits 31:16 - Reserved (not used, can be added if needed)
}

/// Device Recovery Status codes (Bits 3:0)
pub mod dev_rec_status_code {
    pub const AWAITING_IMAGE: u8 = 0x1;
    pub const BOOTING_IMAGE: u8 = 0x2;
    #[allow(dead_code)]
    pub const RECOVERY_SUCCESS: u8 = 0x3;
    // 0x4-0xB: Reserved
}

pub mod rec_img_index {
    pub const MCU_IMG_INDEX: u8 = 0x2;
}

/// State machine extended variables.
pub(crate) struct Context {
    image_size: usize,
}

impl Context {
    pub(crate) fn new() -> Context {
        Context { image_size: 0 }
    }
}

impl StateMachineContext for Context {
    /// Check that the the protcap supports device status
    fn check_device_status_support(&self, prot_cap: &ProtCap2) -> Result<bool, ()> {
        if prot_cap.device_status() {
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Chjeck that the device status is healthy
    fn check_device_status_healthy(&self, status: &DeviceStatus0) -> Result<bool, ()> {
        if status.device_status() == device_status_code::DEVICE_HEALTHY as u32 {
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Check that the device status is recovery mode
    fn check_device_status_recovery(&self, status: &DeviceStatus0) -> Result<bool, ()> {
        if status.device_status() == device_status_code::RECOVERY_MODE as u32 {
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Check that the recovery status is awaiting a recovery image
    fn check_recovery_status_awaiting(&self, status: &RecoveryStatus) -> Result<bool, ()> {
        if status.dev_rec_status() == dev_rec_status_code::AWAITING_IMAGE as u32 {
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Check that the device status is recovery pending
    fn check_device_status_recovery_pending(&self, status: &DeviceStatus0) -> Result<bool, ()> {
        if status.device_status() == device_status_code::RECOVERY_PENDING as u32 {
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn check_recovery_status_booting_mcu_img(&self, status: &RecoveryStatus) -> Result<bool, ()> {
        if status.dev_rec_status() == dev_rec_status_code::BOOTING_IMAGE as u32
            && status.rec_img_index() == rec_img_index::MCU_IMG_INDEX as u32
        {
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

/// Attempt to load an image using the [`ImageProviderManager`], retrying with
/// subsequent providers according to each entry's [`ErrorPolicy`].
///
/// Returns `Ok(())` once a provider succeeds, or `Err(())` if all providers
/// are exhausted.
pub(crate) fn load_image_with_retry(
    i3c_periph: StaticRef<i3c::regs::I3c>,
    manager: &mut ImageProviderManager<'_>,
) -> Result<(), ()> {
    while let Some(provider) = manager.provider() {
        match load_image_to_recovery(i3c_periph, provider) {
            Ok(()) => return Ok(()),
            Err(()) => {
                romtime::println!("[mcu-rom] Image provider failed, trying next");
                continue;
            }
        }
    }
    romtime::println!("[mcu-rom] All image providers exhausted");
    Err(())
}

fn load_image_to_recovery(
    i3c_periph: StaticRef<i3c::regs::I3c>,
    image_provider: &mut dyn ImageProvider,
) -> Result<(), ()> {
    let context = Context::new();
    let mut state_machine = StateMachine::new(context);

    let mut prev_state = States::ReadProtCap;
    let mut next_print_checkpoint = 0;
    let mut start_cycle = None;

    while *state_machine.state() != States::Done {
        if prev_state != *state_machine.state() {
            romtime::println!(
                "[mcu-rom] Transitioning from {:?} to {:?}",
                prev_state,
                state_machine.state()
            );
            prev_state = *state_machine.state();
        };

        match *state_machine.state() {
            States::ReadProtCap => {
                // Read the ProtCap2 register
                let prot_cap = i3c_periph.sec_fw_recovery_if_prot_cap_2.get();
                let _ = state_machine.process_event(Events::ProtCap(ProtCap2(prot_cap)));
            }

            States::ReadDeviceStatus => {
                // Read the Device Status register
                let device_status = i3c_periph.sec_fw_recovery_if_device_status_0.get();
                let _ =
                    state_machine.process_event(Events::DeviceStatus(DeviceStatus0(device_status)));
            }

            States::WaitForRecoveryStatus => {
                // Read the Recovery Status register
                let recovery_status =
                    RecoveryStatus(i3c_periph.sec_fw_recovery_if_recovery_status.get());
                let res = state_machine.process_event(Events::RecoveryStatus(recovery_status));
                if res.is_ok() {
                    let recovery_image_index = recovery_status.rec_img_index();
                    romtime::println!(
                        "[mcu-rom] Starting recovery with image index {}",
                        recovery_image_index
                    );
                    // Clear REC_INTF_CFG.REC_PAYLOAD_DONE bit to indicate image is not available
                    i3c_periph
                        .soc_mgmt_if_rec_intf_cfg
                        .modify(RecIntfCfg::RecPayloadDone.val(0));
                    let image_size = image_provider.image_ready(recovery_image_index)?;
                    state_machine.context_mut().image_size = image_size;
                    i3c_periph
                        .sec_fw_recovery_if_indirect_fifo_ctrl_1
                        .set((state_machine.context().image_size / 4) as u32);
                }
            }

            States::TransferringImage => {
                if start_cycle.is_none() {
                    start_cycle = Some(romtime::mcycle());
                }

                let bytes_loaded = image_provider.bytes_loaded();
                if bytes_loaded >= next_print_checkpoint {
                    romtime::println!(
                        "[mcu-rom] Transferring image data at offset {} out of {}",
                        bytes_loaded,
                        state_machine.context().image_size
                    );
                    next_print_checkpoint = bytes_loaded + state_machine.context().image_size / 10;
                }

                if bytes_loaded >= state_machine.context().image_size {
                    // Set REC_INTF_CFG.REC_PAYLOAD_DONE bit to indicate transfer complete
                    i3c_periph
                        .soc_mgmt_if_rec_intf_cfg
                        .modify(RecIntfCfg::RecPayloadDone.val(1));

                    // If the transfer is complete, we can move to the next state
                    let _ = state_machine.process_event(Events::TransferComplete);
                    let end_cycle = romtime::mcycle();
                    let cycles = (end_cycle - start_cycle.unwrap_or_default()).max(1);
                    romtime::println!(
                        "[mcu-rom] Image transfer complete after {} cycles (≈{} bytes per 1,000 cycles)",
                        cycles,
                        (state_machine.context().image_size as u64 * 1000) / cycles,
                    );
                } else {
                    // wait for fifo empty before transferring full 256 bytes
                    // this is necessary to work around some hardware quirks where
                    // being not full does not mean it is safe to write
                    if i3c_periph
                        .sec_fw_recovery_if_indirect_fifo_status_0
                        .is_set(IndirectFifoStatus0::Empty)
                    {
                        let mut buf = [0u32; 64];
                        let data = buf.as_mut_bytes();
                        image_provider.next_bytes(data)?;

                        // load a dword at a time to recovery interface
                        let dwords_loaded = data.len().div_ceil(4);
                        for dword in buf.iter().take(dwords_loaded) {
                            i3c_periph.tti_tx_data_port.set(*dword);
                        }
                    }
                }
            }

            States::WaitForRecoveryPending => {
                let device_status = i3c_periph.sec_fw_recovery_if_device_status_0.get();
                let _ =
                    state_machine.process_event(Events::DeviceStatus(DeviceStatus0(device_status)));
            }

            States::Activate => {
                // Activate the recovery image
                i3c_periph.soc_mgmt_if_rec_intf_reg_w1_c_access.modify(
                    RecIntfRegW1cAccess::RecoveryCtrlActivateRecImg
                        .val(ACTIVATE_RECOVERY_IMAGE_CMD),
                );
                let _ = state_machine.process_event(Events::CheckFwActivation);
            }

            States::CheckFwActivation => {
                let device_status = i3c_periph.sec_fw_recovery_if_device_status_0.get();
                let result =
                    state_machine.process_event(Events::DeviceStatus(DeviceStatus0(device_status)));
                if result.is_err() {
                    let recovery_status =
                        RecoveryStatus(i3c_periph.sec_fw_recovery_if_recovery_status.get());
                    let _ = state_machine.process_event(Events::RecoveryStatus(recovery_status));
                }
            }
            _ => {}
        }
    }

    Ok(())
}
