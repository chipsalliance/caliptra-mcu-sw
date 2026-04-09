// Licensed under the Apache-2.0 license
#![no_std]

pub mod certificate;
pub mod checksum;
pub mod crypto;
pub mod error;
pub mod evidence;
pub mod firmware_update;
pub mod image_loading;
pub mod mailbox_api;
pub mod signed_eat;

/// Max PLDM firmware data transfer size per RequestFirmwareData.
/// Derived from MAX_MCTP_PLDM_MSG_SIZE minus MCTP message type byte and PLDM response header overhead.
pub const MAX_PLDM_TRANSFER_SIZE: usize =
    caliptra_mcu_pldm_common::message::firmware_update::request_fw_data::MAX_PLDM_FW_DATA_SIZE;
