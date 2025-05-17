// Licensed under the Apache-2.0 license

use crate::control_context::ProtocolCapability;
use embassy_sync::lazy_lock::LazyLock;
use pldm_common::protocol::base::{PldmControlCmd, PldmSupportedType};
use pldm_common::protocol::firmware_update::{FwUpdateCmd, PldmFdTime};

pub const PLDM_PROTOCOL_CAP_COUNT: usize = 2;
pub const FD_MAX_XFER_SIZE: usize = 512; // Arbitrary limit and change as needed.
pub const DEFAULT_FD_T1_TIMEOUT: PldmFdTime = 120000; // FD_T1 update mode idle timeout, range is [60s, 120s].
pub const DEFAULT_FD_T2_RETRY_TIME: PldmFdTime = 5000; // FD_T2 retry request for firmware data, range is [1s, 5s].
pub const INSTANCE_ID_COUNT: u8 = 32;
pub const UA_EID: u8 = 8; // Update Agent Endpoint ID for testing.

pub static PLDM_PROTOCOL_CAPABILITIES: LazyLock<
    [ProtocolCapability<'static>; PLDM_PROTOCOL_CAP_COUNT],
> = LazyLock::new(|| {
    [
        ProtocolCapability {
            pldm_type: PldmSupportedType::Base,
            protocol_version: 0xF1F1F000, //"1.1.0"
            supported_commands: &[
                PldmControlCmd::SetTid as u8,
                PldmControlCmd::GetTid as u8,
                PldmControlCmd::GetPldmCommands as u8,
                PldmControlCmd::GetPldmVersion as u8,
                PldmControlCmd::GetPldmTypes as u8,
            ],
        },
        ProtocolCapability {
            pldm_type: PldmSupportedType::FwUpdate,
            protocol_version: 0xF1F3F000, // "1.3.0"
            supported_commands: &[
                FwUpdateCmd::QueryDeviceIdentifiers as u8,
                FwUpdateCmd::GetFirmwareParameters as u8,
                FwUpdateCmd::RequestUpdate as u8,
                FwUpdateCmd::PassComponentTable as u8,
                FwUpdateCmd::UpdateComponent as u8,
                FwUpdateCmd::RequestFirmwareData as u8,
                FwUpdateCmd::TransferComplete as u8,
                FwUpdateCmd::VerifyComplete as u8,
                FwUpdateCmd::ApplyComplete as u8,
                FwUpdateCmd::ActivateFirmware as u8,
                FwUpdateCmd::GetStatus as u8,
                FwUpdateCmd::CancelUpdateComponent as u8,
                FwUpdateCmd::CancelUpdate as u8,
            ],
        },
    ]
});
