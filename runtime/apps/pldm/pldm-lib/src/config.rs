// Licensed under the Apache-2.0 license

use crate::control_context::ProtocolCapability;
use pldm_common::message::firmware_update::get_fw_params::FirmwareParameters;
use pldm_common::protocol::base::{PldmControlCmd, PldmSupportedType};
use pldm_common::protocol::firmware_update::{
    ComponentActivationMethods, ComponentClassification, FirmwareDeviceCapability, FwUpdateCmd,
    PldmFirmwareString, PldmFirmwareVersion,
};
use pldm_common::protocol::firmware_update::{ComponentParameterEntry, Descriptor, DescriptorType};

use embassy_sync::lazy_lock::LazyLock;

pub const PLDM_PROTOCOL_CAP_COUNT: usize = 2;
pub const FD_DESCRIPTORS_COUNT: usize = 1;
pub const FD_FW_COMPONENTS_COUNT: usize = 1;

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
                FwUpdateCmd::CancelUpdate as u8,
            ],
        },
    ]
});

// This is a dummy UUID for development. The actual UUID is assigned by the vendor.
pub const UUID: [u8; 16] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
];

pub static DESCRIPTORS: LazyLock<[Descriptor; FD_DESCRIPTORS_COUNT]> =
    LazyLock::new(|| [Descriptor::new(DescriptorType::Uuid, &UUID).unwrap()]);

// This is dummy firmware parameter for development. The actual firmware parameters are
// retrieved from the SoC manifest via mailbox commands.
pub static FIRMWARE_PARAMS: LazyLock<FirmwareParameters> = LazyLock::new(|| {
    let active_firmware_string = PldmFirmwareString::new("UTF-8", "soc-fw-1.0").unwrap();
    let active_firmware_version =
        PldmFirmwareVersion::new(0x12345678, &active_firmware_string, Some("20250210"));
    let pending_firmware_string = PldmFirmwareString::new("UTF-8", "soc-fw-1.1").unwrap();
    let pending_firmware_version =
        PldmFirmwareVersion::new(0x87654321, &pending_firmware_string, Some("20250213"));
    let comp_activation_methods = ComponentActivationMethods(0x0001);
    let capabilities_during_update = FirmwareDeviceCapability(0x0010);
    let component_parameter_entry = ComponentParameterEntry::new(
        ComponentClassification::Firmware,
        0x0001,
        0,
        &active_firmware_version,
        &pending_firmware_version,
        comp_activation_methods,
        capabilities_during_update,
    );
    FirmwareParameters::new(
        capabilities_during_update,
        FD_FW_COMPONENTS_COUNT as u16,
        &active_firmware_string,
        &pending_firmware_string,
        &[component_parameter_entry],
    )
});
