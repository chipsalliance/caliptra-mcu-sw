// Licensed under the Apache-2.0 license

use crate::flash::flash_partition::FlashPartition;
use bitfield::bitfield;
use caliptra_mcu_flash_image::{
    FlashHeaderV3, ImageHeaderV3, CALIPTRA_FMC_RT_IDENTIFIER, MCU_RT_IDENTIFIER,
    SOC_MANIFEST_IDENTIFIER,
};
use caliptra_mcu_registers_generated::i3c;
use caliptra_mcu_registers_generated::i3c::bits::{
    DeviceReset, IndirectFifoStatus0, RecIntfCfg, RecIntfRegW1cAccess,
};
use caliptra_mcu_romtime::StaticRef;
use smlang::statemachine;
use tock_registers::interfaces::{ReadWriteable, Readable, Writeable};
use zerocopy::{FromBytes, IntoBytes};

const ACTIVATE_RECOVERY_IMAGE_CMD: u32 = 0xF;

/// DEVICE_STATUS_0 value used when MCU ROM reports DOT blob recovery failure.
pub const DOT_RECOVERY_DEVICE_STATUS: u32 = 0x0094_000E;
/// DEVICE_RESET.RESET_CTRL value requesting fused-owner recovery on next boot.
pub const DEVICE_RESET_CTRL_PREVIOUS_DOT_FAILED: u32 = 0x10;
/// DEVICE_RESET.RESET_CTRL value requesting regular DOT verification on next boot.
pub const DEVICE_RESET_CTRL_PREVIOUS_DOT_SUCCEEDED: u32 = 0x11;

/// Reads I3C OCP recovery DEVICE_RESET.RESET_CTRL.
pub fn device_reset_ctrl(i3c_periph: StaticRef<i3c::regs::I3c>) -> u32 {
    i3c_periph
        .sec_fw_recovery_if_device_reset
        .read(DeviceReset::ResetCtrl)
}

/// Waits until BMC writes a DOT recovery result to DEVICE_RESET.RESET_CTRL.
pub fn wait_for_dot_recovery_reset_result(i3c_periph: StaticRef<i3c::regs::I3c>) -> u32 {
    loop {
        let reset_ctrl = device_reset_ctrl(i3c_periph);
        if reset_ctrl == DEVICE_RESET_CTRL_PREVIOUS_DOT_FAILED
            || reset_ctrl == DEVICE_RESET_CTRL_PREVIOUS_DOT_SUCCEEDED
        {
            return reset_ctrl;
        }
    }
}

/// Publishes the MCU ROM DOT recovery failure status through DEVICE_STATUS_0.
pub fn set_dot_recovery_device_status(i3c_periph: StaticRef<i3c::regs::I3c>) {
    i3c_periph
        .sec_fw_recovery_if_device_status_0
        .set(DOT_RECOVERY_DEVICE_STATUS);
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


        CheckFwActivation + RecoveryStatus(RecoveryStatus) [check_fw_booting_image]
            = ActivateCheckRecoveryStatus,

        ActivateCheckRecoveryStatus + RecoveryStatus(RecoveryStatus) [check_recovery_status_awaiting]
             = ReadDeviceStatus,

        ActivateCheckRecoveryStatus + RecoveryStatus(RecoveryStatus) [check_recovery_status_booting_mcu_img]
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
    recovery_image_index: u8,
    image_size: u32,
    flash_offset: u32,
    pub transfer_offset: u32,
}

impl Context {
    pub(crate) fn new() -> Context {
        Context {
            recovery_image_index: 0,
            image_size: 0,
            flash_offset: 0,
            transfer_offset: 0,
        }
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

    fn check_fw_booting_image(&self, status: &RecoveryStatus) -> Result<bool, ()> {
        if status.dev_rec_status() == dev_rec_status_code::BOOTING_IMAGE as u32 {
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn check_recovery_status_booting_mcu_img(&self, status: &RecoveryStatus) -> Result<bool, ()> {
        Ok(self.check_fw_booting_image(status)?
            && status.rec_img_index() == rec_img_index::MCU_IMG_INDEX as u32)
    }
}

pub fn get_flash_image_info(id: u32, flash_driver: &mut FlashPartition) -> Result<(u32, u32), ()> {
    const HEADER_SIZE: usize = core::mem::size_of::<FlashHeaderV3>();
    const IMAGE_HEADER_SIZE: usize = core::mem::size_of::<ImageHeaderV3>();
    let mut buf = [0u8; IMAGE_HEADER_SIZE];

    flash_driver
        .read(0, &mut buf[..HEADER_SIZE])
        .map_err(|_| ())?;

    let flash_header = FlashHeaderV3::read_from_bytes(&buf[..HEADER_SIZE]).map_err(|_| {
        caliptra_mcu_romtime::println!("[mcu-rom] Invalid flash header");
    })?;
    if !flash_header.verify() {
        caliptra_mcu_romtime::println!(
            "[mcu-rom] Invalid or unsupported flash header version {}",
            flash_header.version
        );
        return Err(());
    }

    let image_count = flash_header.image_count as usize;
    let table_offset = flash_header.image_headers_offset as usize;
    let table_end = image_count
        .checked_mul(IMAGE_HEADER_SIZE)
        .and_then(|size| table_offset.checked_add(size))
        .filter(|end| *end <= flash_driver.len())
        .ok_or_else(|| {
            caliptra_mcu_romtime::println!("[mcu-rom] Flash image table exceeds partition");
        })?;

    for i in 0..image_count {
        let offset = table_offset + i * IMAGE_HEADER_SIZE;
        flash_driver.read(offset, &mut buf).map_err(|_| ())?;
        let image_header = ImageHeaderV3::read_from_bytes(&buf).map_err(|_| {
            caliptra_mcu_romtime::println!("[mcu-rom] Invalid flash image entry");
        })?;
        if !image_header.verify() {
            caliptra_mcu_romtime::println!("[mcu-rom] Invalid flash image entry checksum");
            return Err(());
        }

        if image_header.identifier == id {
            let image_offset = image_header.offset as usize;
            image_offset
                .checked_add(image_header.size as usize)
                .filter(|end| image_offset >= table_end && *end <= flash_driver.len())
                .ok_or_else(|| {
                    caliptra_mcu_romtime::println!(
                        "[mcu-rom] Flash image payload outside partition"
                    );
                })?;
            return Ok((image_header.offset, image_header.size));
        }
    }

    Err(())
}

pub fn recovery_img_index_to_image_id(recovery_image_index: u32) -> Result<u32, ()> {
    // Convert the recovery image index to the image ID
    match recovery_image_index {
        0 => Ok(CALIPTRA_FMC_RT_IDENTIFIER),
        1 => Ok(SOC_MANIFEST_IDENTIFIER),
        2 => Ok(MCU_RT_IDENTIFIER),
        _ => Err(()),
    }
}

pub fn load_flash_image_to_recovery(
    i3c_periph: StaticRef<i3c::regs::I3c>,
    flash_driver: &mut FlashPartition,
) -> Result<(), ()> {
    let context = Context::new();
    let mut state_machine = StateMachine::new(context);

    let mut prev_state = States::ReadProtCap;
    let mut next_print_offset = 0u32;
    let mut start_cycle = None;

    while *state_machine.state() != States::Done {
        if prev_state != *state_machine.state() {
            caliptra_mcu_romtime::println!(
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
                    state_machine.context_mut().recovery_image_index =
                        recovery_status.rec_img_index() as u8;
                    caliptra_mcu_romtime::println!(
                        "[mcu-rom] Starting recovery with image index {}",
                        state_machine.context().recovery_image_index
                    );
                    // Clear REC_INTF_CFG.REC_PAYLOAD_DONE bit to indicate image is not available
                    i3c_periph
                        .soc_mgmt_if_rec_intf_cfg
                        .modify(RecIntfCfg::RecPayloadDone.val(0));
                    let image_info = get_flash_image_info(
                        recovery_img_index_to_image_id(
                            state_machine.context().recovery_image_index as u32,
                        )?,
                        flash_driver,
                    )?;
                    state_machine.context_mut().flash_offset = image_info.0;
                    state_machine.context_mut().image_size = image_info.1;
                    state_machine.context_mut().transfer_offset = 0;
                    start_cycle = None;
                    next_print_offset = 0;
                    i3c_periph
                        .sec_fw_recovery_if_indirect_fifo_ctrl_1
                        .set(state_machine.context().image_size / 4);
                }
            }

            States::TransferringImage => {
                if start_cycle.is_none() {
                    start_cycle = Some(caliptra_mcu_romtime::mcycle());
                }

                if state_machine.context().transfer_offset >= next_print_offset {
                    caliptra_mcu_romtime::println!(
                        "[mcu-rom] Transferring image data at offset {} out of {}",
                        state_machine.context().transfer_offset,
                        state_machine.context().image_size
                    );
                    next_print_offset = state_machine.context().transfer_offset
                        + state_machine.context().image_size / 10;
                }

                if state_machine.context().transfer_offset >= state_machine.context().image_size {
                    // Set REC_INTF_CFG.REC_PAYLOAD_DONE bit to indicate transfer complete
                    i3c_periph
                        .soc_mgmt_if_rec_intf_cfg
                        .modify(RecIntfCfg::RecPayloadDone.val(1));

                    // If the transfer is complete, we can move to the next state
                    let _ = state_machine.process_event(Events::TransferComplete);
                    let end_cycle = caliptra_mcu_romtime::mcycle();
                    let cycles = (end_cycle - start_cycle.unwrap_or_default()).max(1);
                    caliptra_mcu_romtime::println!(
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
                        let mut data = [0u32; 64];
                        flash_driver
                            .read(
                                (state_machine.context().flash_offset
                                    + state_machine.context().transfer_offset)
                                    as usize,
                                data.as_mut_bytes(),
                            )
                            .map_err(|_| ())?;

                        let left = state_machine.context().image_size
                            - state_machine.context().transfer_offset;
                        let process = core::cmp::min(left, 256);
                        // load a dword at a time to recovery interface
                        for dword in data.iter().take(process.div_ceil(4) as usize) {
                            i3c_periph.tti_tx_data_port.set(*dword);
                        }
                        state_machine.context_mut().transfer_offset += process;
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
                // Check if the device is running recovery
                let recovery_status =
                    RecoveryStatus(i3c_periph.sec_fw_recovery_if_recovery_status.get());
                let _ = state_machine.process_event(Events::RecoveryStatus(recovery_status));
            }

            States::ActivateCheckRecoveryStatus => {
                // Check the recovery status after activation
                let recovery_status =
                    RecoveryStatus(i3c_periph.sec_fw_recovery_if_recovery_status.get());
                let _ = state_machine.process_event(Events::RecoveryStatus(recovery_status));
            }

            _ => {}
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flash::hil::{FlashDrvError, FlashStorage};
    use caliptra_mcu_flash_image::{
        calculate_checksum, FlashHeaderV1, FlashHeaderV2, FlashImageVersion,
    };
    use core::mem::offset_of;

    struct Storage([u8; 256]);

    impl FlashStorage for Storage {
        fn read(&self, buffer: &mut [u8], address: usize) -> Result<(), FlashDrvError> {
            let bytes = self
                .0
                .get(address..address + buffer.len())
                .ok_or(FlashDrvError::SIZE)?;
            buffer.copy_from_slice(bytes);
            Ok(())
        }

        fn write(&self, _: &[u8], _: usize) -> Result<(), FlashDrvError> {
            Err(FlashDrvError::NOSUPPORT)
        }

        fn erase(&self, _: usize, _: usize) -> Result<(), FlashDrvError> {
            Err(FlashDrvError::NOSUPPORT)
        }

        fn capacity(&self) -> usize {
            self.0.len()
        }
    }

    fn storage_with_v3_image(
        image_count: u16,
        table_offset: u32,
        image_offset: u32,
        image_size: u32,
    ) -> Storage {
        let mut storage = Storage([0; 256]);
        let mut header = FlashHeaderV3::new(image_count);
        header.image_headers_offset = table_offset;
        header.header_checksum =
            calculate_checksum(&header.as_bytes()[..offset_of!(FlashHeaderV3, header_checksum)]);
        storage.0[..size_of::<FlashHeaderV3>()].copy_from_slice(header.as_bytes());
        let mut image = ImageHeaderV3 {
            identifier: MCU_RT_IDENTIFIER,
            offset: image_offset,
            size: image_size,
            filename: [0; 64],
            image_checksum: 0,
            image_header_checksum: 0,
        };
        image.image_header_checksum = calculate_checksum(
            &image.as_bytes()[..offset_of!(ImageHeaderV3, image_header_checksum)],
        );
        let offset = table_offset as usize;
        if offset <= storage.0.len() - size_of::<ImageHeaderV3>() {
            storage.0[offset..offset + size_of::<ImageHeaderV3>()]
                .copy_from_slice(image.as_bytes());
        }
        storage
    }

    #[test]
    fn rom_rejects_complete_table_outside_partition() {
        for (image_count, table_offset, partition_len) in [
            (3, 12, 256),
            (2, 12, 176),
            (1, 200, 256),
            (1, u32::MAX - 3, 256),
            (u16::MAX, 12, 256),
        ] {
            let storage = storage_with_v3_image(image_count, table_offset, 192, 4);
            let mut partition = FlashPartition::new(&storage, "test", 0, partition_len).unwrap();
            assert!(get_flash_image_info(MCU_RT_IDENTIFIER, &mut partition).is_err());
        }
    }

    #[test]
    fn rom_rejects_payload_outside_partition_or_overlapping_table() {
        for (image_offset, image_size) in [(95, 4), (192, 65), (u32::MAX - 3, 8), (192, u32::MAX)] {
            let storage = storage_with_v3_image(1, 12, image_offset, image_size);
            let mut partition = FlashPartition::new(&storage, "test", 0, 256).unwrap();
            assert!(get_flash_image_info(MCU_RT_IDENTIFIER, &mut partition).is_err());
        }
    }

    #[test]
    fn rom_accepts_payload_at_table_and_partition_boundaries() {
        for (table_offset, image_offset, partition_len) in [(12, 96, 100), (168, 252, 256)] {
            let storage = storage_with_v3_image(1, table_offset, image_offset, 4);
            let mut partition = FlashPartition::new(&storage, "test", 0, partition_len).unwrap();
            assert_eq!(
                get_flash_image_info(MCU_RT_IDENTIFIER, &mut partition),
                Ok((image_offset, 4))
            );
        }
    }

    #[test]
    fn rom_accepts_only_v3() {
        for version in [
            FlashImageVersion::V1,
            FlashImageVersion::V2,
            FlashImageVersion::V3,
        ] {
            let mut storage = storage_with_v3_image(1, 16, 192, 4);
            let out = &mut storage.0[..version.header_size()];
            match version {
                FlashImageVersion::V1 => out.copy_from_slice(FlashHeaderV1::new(1).as_bytes()),
                FlashImageVersion::V2 => out.copy_from_slice(FlashHeaderV2::new(1).as_bytes()),
                FlashImageVersion::V3 => {}
            }
            let mut partition = FlashPartition::new(&storage, "test", 0, 256).unwrap();
            let result = get_flash_image_info(MCU_RT_IDENTIFIER, &mut partition);
            if version == FlashImageVersion::V3 {
                assert_eq!(result, Ok((192, 4)));
            } else {
                assert!(result.is_err());
            }
        }
    }

    #[test]
    fn rom_rejects_corrupt_header() {
        let mut storage = storage_with_v3_image(1, 12, 192, 4);
        storage.0[8] ^= 1;
        let mut partition = FlashPartition::new(&storage, "test", 0, 256).unwrap();
        assert!(get_flash_image_info(MCU_RT_IDENTIFIER, &mut partition).is_err());
    }

    #[test]
    fn dot_recovery_reset_ctrl_values_match_protocol() {
        assert_eq!(DOT_RECOVERY_DEVICE_STATUS, 0x0094_000E);
        assert_eq!(DEVICE_RESET_CTRL_PREVIOUS_DOT_FAILED, 0x10);
        assert_eq!(DEVICE_RESET_CTRL_PREVIOUS_DOT_SUCCEEDED, 0x11);
    }
}
