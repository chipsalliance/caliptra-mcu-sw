// Licensed under the Apache-2.0 license

use crate::codec::{PldmCodec, PldmCodecError};
use crate::error::PldmError;
use bitfield::bitfield;
use core::convert::TryFrom;
use core::fmt;
use zerocopy::{FromBytes, Immutable, IntoBytes};

pub const PLDM_FWUP_COMPONENT_RELEASE_DATA_LEN: usize = 8;
pub const PLDM_FWUP_BASELINE_TRANSFER_SIZE: usize = 32;
pub const PLDM_FWUP_MAX_PADDING_SIZE: usize = PLDM_FWUP_BASELINE_TRANSFER_SIZE;
pub const PLDM_FWUP_IMAGE_SET_VER_STR_MAX_LEN: usize = 255;
pub const DESCRIPTOR_DATA_MAX_LEN: usize = 64; // Arbitrary limit for static storage
pub const MAX_COMPONENT_COUNT: usize = 8; // Arbitrary limit, change as needed

#[repr(u8)]
pub enum FwUpdateCmd {
    QueryDeviceIdentifiers = 0x01,
    GetFirmwareParameters = 0x02,
    RequestUpdate = 0x10,
    PassComponentTable = 0x13,
    UpdateComponent = 0x14,
    RequestFirmwareData = 0x15,
    TransferComplete = 0x16,
    VerifyComplete = 0x17,
    ApplyComplete = 0x18,
    ActivateFirmware = 0x1A,
    GetStatus = 0x1B,
    CancelUpdateComponent = 0x1C,
    CancelUpdate = 0x1D,
}

impl TryFrom<u8> for FwUpdateCmd {
    type Error = PldmError;

    fn try_from(value: u8) -> Result<Self, PldmError> {
        match value {
            0x01 => Ok(FwUpdateCmd::QueryDeviceIdentifiers),
            0x02 => Ok(FwUpdateCmd::GetFirmwareParameters),
            0x10 => Ok(FwUpdateCmd::RequestUpdate),
            0x13 => Ok(FwUpdateCmd::PassComponentTable),
            0x14 => Ok(FwUpdateCmd::UpdateComponent),
            0x15 => Ok(FwUpdateCmd::RequestFirmwareData),
            0x16 => Ok(FwUpdateCmd::TransferComplete),
            0x17 => Ok(FwUpdateCmd::VerifyComplete),
            0x18 => Ok(FwUpdateCmd::ApplyComplete),
            0x1A => Ok(FwUpdateCmd::ActivateFirmware),
            0x1B => Ok(FwUpdateCmd::GetStatus),
            0x1C => Ok(FwUpdateCmd::CancelUpdateComponent),
            0x1D => Ok(FwUpdateCmd::CancelUpdate),
            _ => Err(PldmError::UnsupportedCmd),
        }
    }
}

#[repr(u8)]
pub enum FwUpdateCompletionCode {
    NotInUpdateMode = 0x80,
    AlreadyInUpdateMode = 0x81,
    DataOutOfRange = 0x82,
    InvalidTransferLength = 0x83,
    InvalidStateForCommand = 0x84,
    IncompleteUpdate = 0x85,
    BusyInBackground = 0x86,
    CancelPending = 0x87,
    CommandNotExpected = 0x88,
    RetryRequestFwData = 0x89,
    UnableToInitiateUpdate = 0x8A,
    ActivationNotRequired = 0x8B,
    SelfContainedActivationNotPermitted = 0x8C,
    NoDeviceMetadata = 0x8D,
    RetryRequestUpdate = 0x8E,
    NoPackageData = 0x8F,
    InvalidTransferHandle = 0x90,
    InvalidTransferOperationFlag = 0x91,
    ActivatePendingImageNotPermitted = 0x92,
    PackageDataError = 0x93,
}

impl TryFrom<u8> for FwUpdateCompletionCode {
    type Error = PldmError;

    fn try_from(value: u8) -> Result<Self, PldmError> {
        match value {
            0x80 => Ok(FwUpdateCompletionCode::NotInUpdateMode),
            0x81 => Ok(FwUpdateCompletionCode::AlreadyInUpdateMode),
            0x82 => Ok(FwUpdateCompletionCode::DataOutOfRange),
            0x83 => Ok(FwUpdateCompletionCode::InvalidTransferLength),
            0x84 => Ok(FwUpdateCompletionCode::InvalidStateForCommand),
            0x85 => Ok(FwUpdateCompletionCode::IncompleteUpdate),
            0x86 => Ok(FwUpdateCompletionCode::BusyInBackground),
            0x87 => Ok(FwUpdateCompletionCode::CancelPending),
            0x88 => Ok(FwUpdateCompletionCode::CommandNotExpected),
            0x89 => Ok(FwUpdateCompletionCode::RetryRequestFwData),
            0x8A => Ok(FwUpdateCompletionCode::UnableToInitiateUpdate),
            0x8B => Ok(FwUpdateCompletionCode::ActivationNotRequired),
            0x8C => Ok(FwUpdateCompletionCode::SelfContainedActivationNotPermitted),
            0x8D => Ok(FwUpdateCompletionCode::NoDeviceMetadata),
            0x8E => Ok(FwUpdateCompletionCode::RetryRequestUpdate),
            0x8F => Ok(FwUpdateCompletionCode::NoPackageData),
            0x90 => Ok(FwUpdateCompletionCode::InvalidTransferHandle),
            0x91 => Ok(FwUpdateCompletionCode::InvalidTransferOperationFlag),
            0x92 => Ok(FwUpdateCompletionCode::ActivatePendingImageNotPermitted),
            0x93 => Ok(FwUpdateCompletionCode::PackageDataError),
            _ => Err(PldmError::InvalidCompletionCode),
        }
    }
}

#[repr(u8)]
pub enum FirmwareDeviceState {
    Idle = 0,
    LearnComponents = 1,
    ReadyXfer = 2,
    Download = 3,
    Verify = 4,
    Apply = 5,
    Activate = 6,
}

impl TryFrom<u8> for FirmwareDeviceState {
    type Error = PldmError;

    fn try_from(value: u8) -> Result<Self, PldmError> {
        match value {
            0 => Ok(FirmwareDeviceState::Idle),
            1 => Ok(FirmwareDeviceState::LearnComponents),
            2 => Ok(FirmwareDeviceState::ReadyXfer),
            3 => Ok(FirmwareDeviceState::Download),
            4 => Ok(FirmwareDeviceState::Verify),
            5 => Ok(FirmwareDeviceState::Apply),
            6 => Ok(FirmwareDeviceState::Activate),
            _ => Err(PldmError::InvalidFdState),
        }
    }
}

bitfield! {
    #[derive(Clone, Copy, PartialEq, FromBytes, IntoBytes)]
    pub struct UpdateOptionFlags(u32);
    impl Debug;
    pub u32, reserved, _: 31, 3;
    pub u32, svn_delayed_update, set_svn_delayed_update: 2;
    pub u32, component_opaque_data, set_component_opaque_data: 1;
    pub u32, request_force_update, set_request_force_update: 0;
}

#[repr(u8)]
pub enum VersionStringType {
    Unspecified = 0,
    Ascii = 1,
    Utf8 = 2,
    Utf16 = 3,
    Utf16Le = 4,
    Utf16Be = 5,
}

impl VersionStringType {
    fn as_string(&self) -> &str {
        match *self {
            VersionStringType::Ascii => "ASCII",
            VersionStringType::Utf8 => "UTF-8",
            VersionStringType::Utf16 => "UTF-16",
            VersionStringType::Utf16Le => "UTF-16LE",
            VersionStringType::Utf16Be => "UTF-16BE",
            _ => "UNKNOWN",
        }
    }
}

impl fmt::Display for VersionStringType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.as_string())
    }
}
impl TryFrom<&str> for VersionStringType {
    type Error = PldmError;

    fn try_from(input: &str) -> Result<VersionStringType, Self::Error> {
        match input {
            "ASCII" | "ascii" => Ok(VersionStringType::Ascii),
            "UTF-8" | "utf-8" => Ok(VersionStringType::Utf8),
            "UTF-16" | "utf-16" => Ok(VersionStringType::Utf16),
            "UTF-16LE" | "utf-16le" => Ok(VersionStringType::Utf16Le),
            "UTF-16BE" | "utf-16be" => Ok(VersionStringType::Utf16Be),
            _ => Err(PldmError::InvalidVersionStringType),
        }
    }
}

#[derive(Clone, Copy, PartialEq)]
#[repr(u16)]
pub enum DescriptorType {
    PciVendorId = 0x0000,
    IanaEnterpriseId = 0x0001,
    Uuid = 0x0002,
    PnpVendorId = 0x0003,
    AcpiVendorId = 0x0004,
    IeeeAssignedCompanyId = 0x0005,
    ScsiVendorId = 0x0006,
    PciDeviceId = 0x0100,
    PciSubsystemVendorId = 0x0101,
    PciSubsystemId = 0x0102,
    PciRevisionId = 0x0103,
    PnpProductIdentifier = 0x0104,
    AcpiProductIdentifier = 0x0105,
    AsciiModelNumberLongString = 0x0106,
    AsciiModelNumberShortString = 0x0107,
    ScsiProductId = 0x0108,
    UbmControllerDeviceCode = 0x0109,
    VendorDefined = 0xFFFF,
}

impl TryFrom<u16> for DescriptorType {
    type Error = PldmError;

    fn try_from(value: u16) -> Result<Self, PldmError> {
        match value {
            0x0000 => Ok(DescriptorType::PciVendorId),
            0x0001 => Ok(DescriptorType::IanaEnterpriseId),
            0x0002 => Ok(DescriptorType::Uuid),
            0x0003 => Ok(DescriptorType::PnpVendorId),
            0x0004 => Ok(DescriptorType::AcpiVendorId),
            0x0005 => Ok(DescriptorType::IeeeAssignedCompanyId),
            0x0006 => Ok(DescriptorType::ScsiVendorId),
            0x0100 => Ok(DescriptorType::PciDeviceId),
            0x0101 => Ok(DescriptorType::PciSubsystemVendorId),
            0x0102 => Ok(DescriptorType::PciSubsystemId),
            0x0103 => Ok(DescriptorType::PciRevisionId),
            0x0104 => Ok(DescriptorType::PnpProductIdentifier),
            0x0105 => Ok(DescriptorType::AcpiProductIdentifier),
            0x0106 => Ok(DescriptorType::AsciiModelNumberLongString),
            0x0107 => Ok(DescriptorType::AsciiModelNumberShortString),
            0x0108 => Ok(DescriptorType::ScsiProductId),
            0x0109 => Ok(DescriptorType::UbmControllerDeviceCode),
            0xFFFF => Ok(DescriptorType::VendorDefined),
            _ => Err(PldmError::InvalidDescriptorType),
        }
    }
}

pub fn get_descriptor_length(descriptor_type: DescriptorType) -> usize {
    match &descriptor_type {
        DescriptorType::PciVendorId => 2,
        DescriptorType::IanaEnterpriseId => 4,
        DescriptorType::Uuid => 16,
        DescriptorType::PnpVendorId => 3,
        DescriptorType::AcpiVendorId => 5,
        DescriptorType::IeeeAssignedCompanyId => 3,
        DescriptorType::ScsiVendorId => 8,
        DescriptorType::PciDeviceId => 2,
        DescriptorType::PciSubsystemVendorId => 2,
        DescriptorType::PciSubsystemId => 2,
        DescriptorType::PciRevisionId => 1,
        DescriptorType::PnpProductIdentifier => 4,
        DescriptorType::AcpiProductIdentifier => 4,
        DescriptorType::AsciiModelNumberLongString => 40,
        DescriptorType::AsciiModelNumberShortString => 10,
        DescriptorType::ScsiProductId => 16,
        DescriptorType::UbmControllerDeviceCode => 4,
        DescriptorType::VendorDefined => DESCRIPTOR_DATA_MAX_LEN,
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
#[repr(C)]
pub struct Descriptor {
    pub descriptor_type: u16,
    pub descriptor_length: u16,
    pub descriptor_data: [u8; DESCRIPTOR_DATA_MAX_LEN],
}

impl Default for Descriptor {
    fn default() -> Self {
        Descriptor {
            descriptor_type: 0,
            descriptor_length: 0,
            descriptor_data: [0; DESCRIPTOR_DATA_MAX_LEN],
        }
    }
}

impl Descriptor {
    pub fn new_empty() -> Self {
        Descriptor {
            descriptor_type: 0,
            descriptor_length: 0,
            descriptor_data: [0; DESCRIPTOR_DATA_MAX_LEN],
        }
    }

    pub fn new(descriptor_type: DescriptorType, descriptor_data: &[u8]) -> Result<Self, PldmError> {
        let descriptor_length = get_descriptor_length(descriptor_type);
        if descriptor_data.len() != descriptor_length {
            return Err(PldmError::InvalidDescriptorLength);
        }

        let mut descriptor_data_array = [0u8; DESCRIPTOR_DATA_MAX_LEN];
        descriptor_data_array[..descriptor_length].copy_from_slice(descriptor_data);

        Ok(Descriptor {
            descriptor_type: descriptor_type as u16,
            descriptor_length: descriptor_length as u16,
            descriptor_data: descriptor_data_array,
        })
    }

    pub fn codec_size_in_bytes(&self) -> usize {
        core::mem::size_of::<u16>() * 2 + self.descriptor_length as usize
    }
}

impl PldmCodec for Descriptor {
    fn encode(&self, buffer: &mut [u8]) -> Result<usize, PldmCodecError> {
        if buffer.len() < self.codec_size_in_bytes() {
            return Err(PldmCodecError::BufferTooShort);
        }
        let mut offset = 0;

        self.descriptor_type
            .write_to(&mut buffer[offset..offset + core::mem::size_of::<u16>()])
            .unwrap();
        offset += core::mem::size_of::<u16>();

        self.descriptor_length
            .write_to(&mut buffer[offset..offset + core::mem::size_of::<u16>()])
            .unwrap();
        offset += core::mem::size_of::<u16>();

        self.descriptor_data[..self.descriptor_length as usize]
            .write_to(&mut buffer[offset..offset + self.descriptor_length as usize])
            .unwrap();
        offset += self.descriptor_length as usize;

        Ok(offset)
    }

    fn decode(buffer: &[u8]) -> Result<Self, PldmCodecError> {
        let mut offset = 0;

        let descriptor_type = u16::read_from_bytes(
            buffer
                .get(offset..offset + core::mem::size_of::<u16>())
                .ok_or(PldmCodecError::BufferTooShort)?,
        )
        .unwrap();
        offset += core::mem::size_of::<u16>();

        let descriptor_length = u16::read_from_bytes(
            buffer
                .get(offset..offset + core::mem::size_of::<u16>())
                .ok_or(PldmCodecError::BufferTooShort)?,
        )
        .unwrap();
        offset += core::mem::size_of::<u16>();

        let mut descriptor_data = [0u8; DESCRIPTOR_DATA_MAX_LEN];
        descriptor_data[..descriptor_length as usize].copy_from_slice(
            buffer
                .get(offset..offset + descriptor_length as usize)
                .ok_or(PldmCodecError::BufferTooShort)?,
        );

        Ok(Descriptor {
            descriptor_type,
            descriptor_length,
            descriptor_data,
        })
    }
}

bitfield! {
    #[derive(Clone, Copy, FromBytes, IntoBytes, Immutable, PartialEq, Eq, Default)]
    pub struct FirmwareDeviceCapability(u32);
    impl Debug;
    pub u32, reserved, _: 31, 10;
    pub u32, svn_update_support, set_svn_update_support: 9;
    pub u32, downgrade_restriction, set_downgrade_restriction: 8;
    pub u32, update_mode_restriction, set_update_mode_restriction: 7, 4;
    pub u32, partial_updates, set_partial_updates: 3;
    pub u32, host_func_reduced, set_func_reduced: 2;
    pub u32, update_failure_retry, set_update_failure_retry: 1;
    pub u32, update_failure_recovery, set_update_failure_recovery: 0;
}

bitfield! {
    #[derive(Clone, Copy, FromBytes, IntoBytes, Immutable, PartialEq, Eq)]
    pub struct ComponentActivationMethods(u16);
    impl Debug;
    pub u16, reserved, _: 15, 8;
    pub u16, activate_pending_comp_image_set, set_activate_pending_comp_image_set: 7;
    pub u16, activate_pending_image, set_activate_pending_image: 6;
    pub u16, ac_power_cycle, set_ac_power_cycle: 5;
    pub u16, dc_power_cycle, set_dc_power_cycle: 4;
    pub u16, system_reboot, set_system_reboot: 3;
    pub u16, medium_specific_reset, set_medium_specific_reset: 2;
    pub u16, self_contained, set_self_contained: 1;
    pub u16, automatic, set_automatic: 0;
}

#[repr(u16)]
pub enum ComponentClassification {
    Unspecified = 0x0000,
    Other = 0x0001,
    Driver = 0x0002,
    ConfigurationSoftware = 0x0003,
    ApplicationSoftware = 0x0004,
    Instrumentation = 0x0005,
    FirmwareOrBios = 0x0006,
    DiagnosticSoftware = 0x0007,
    OperatingSystem = 0x0008,
    Middleware = 0x0009,
    Firmware = 0x000A,
    BiosOrFcode = 0x000B,
    SupportOrServicePack = 0x000C,
    SoftwareBundle = 0x000D,
    DownstreamDevice = 0xFFFF,
}

impl TryFrom<u16> for ComponentClassification {
    type Error = PldmError;

    fn try_from(value: u16) -> Result<Self, PldmError> {
        match value {
            0x0000 => Ok(ComponentClassification::Unspecified),
            0x0001 => Ok(ComponentClassification::Other),
            0x0002 => Ok(ComponentClassification::Driver),
            0x0003 => Ok(ComponentClassification::ConfigurationSoftware),
            0x0004 => Ok(ComponentClassification::ApplicationSoftware),
            0x0005 => Ok(ComponentClassification::Instrumentation),
            0x0006 => Ok(ComponentClassification::FirmwareOrBios),
            0x0007 => Ok(ComponentClassification::DiagnosticSoftware),
            0x0008 => Ok(ComponentClassification::OperatingSystem),
            0x0009 => Ok(ComponentClassification::Middleware),
            0x000A => Ok(ComponentClassification::Firmware),
            0x000B => Ok(ComponentClassification::BiosOrFcode),
            0x000C => Ok(ComponentClassification::SupportOrServicePack),
            0x000D => Ok(ComponentClassification::SoftwareBundle),
            0xFFFF => Ok(ComponentClassification::DownstreamDevice),
            _ => Err(PldmError::InvalidComponentClassification),
        }
    }
}

#[derive(Clone)]
pub struct PldmFirmwareString {
    pub str_type: u8,
    pub str_len: u8,
    pub str_data: [u8; PLDM_FWUP_IMAGE_SET_VER_STR_MAX_LEN],
}

impl PldmFirmwareString {
    pub fn new(str_type: &str, fw_str: &str) -> Result<Self, PldmError> {
        let str_type = VersionStringType::try_from(str_type)?;

        if fw_str.len() > PLDM_FWUP_IMAGE_SET_VER_STR_MAX_LEN {
            return Err(PldmError::InvalidVersionStringLength);
        }

        let mut str_data = [0u8; PLDM_FWUP_IMAGE_SET_VER_STR_MAX_LEN];
        str_data[..fw_str.len()].copy_from_slice(fw_str.as_bytes());

        Ok(PldmFirmwareString {
            str_type: str_type as u8,
            str_len: fw_str.len() as u8,
            str_data,
        })
    }
}

#[derive(Clone)]
pub struct PldmFirmwareVersion<'a> {
    pub comparison_stamp: u32,
    pub str: &'a PldmFirmwareString,
    pub date: [u8; PLDM_FWUP_COMPONENT_RELEASE_DATA_LEN],
}

impl<'a> PldmFirmwareVersion<'a> {
    pub fn new(comparison_stamp: u32, str: &'a PldmFirmwareString, date_str: Option<&str>) -> Self {
        let mut date_array = [0u8; PLDM_FWUP_COMPONENT_RELEASE_DATA_LEN];
        if let Some(date_str) = date_str {
            let date_bytes = date_str.as_bytes();
            let len = date_bytes.len().min(PLDM_FWUP_COMPONENT_RELEASE_DATA_LEN);
            date_array[..len].copy_from_slice(&date_bytes[..len]);
        }
        PldmFirmwareVersion {
            comparison_stamp,
            str,
            date: date_array,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, FromBytes, IntoBytes, Immutable, Copy)]
#[repr(C, packed)]
pub struct ComponentParameterEntryFixed {
    pub comp_classification: u16,
    pub comp_identifier: u16,
    pub comp_classification_index: u8,
    pub active_comp_comparison_stamp: u32,
    pub active_comp_ver_str_type: u8,
    pub active_comp_ver_str_len: u8,
    pub active_comp_release_date: [u8; PLDM_FWUP_COMPONENT_RELEASE_DATA_LEN],
    pub pending_comp_comparison_stamp: u32,
    pub pending_comp_ver_str_type: u8,
    pub pending_comp_ver_str_len: u8,
    pub pending_comp_release_date: [u8; PLDM_FWUP_COMPONENT_RELEASE_DATA_LEN],
    pub comp_activation_methods: ComponentActivationMethods,
    pub capabilities_during_update: FirmwareDeviceCapability,
}

#[derive(Debug, Clone, PartialEq, Eq, Copy)]
#[repr(C)]
pub struct ComponentParameterEntry {
    pub comp_param_entry_fixed: ComponentParameterEntryFixed,
    pub active_comp_ver_str: [u8; PLDM_FWUP_IMAGE_SET_VER_STR_MAX_LEN],
    pub pending_comp_ver_str: Option<[u8; PLDM_FWUP_IMAGE_SET_VER_STR_MAX_LEN]>,
}

impl Default for ComponentParameterEntry {
    fn default() -> Self {
        ComponentParameterEntry {
            comp_param_entry_fixed: ComponentParameterEntryFixed {
                comp_classification: 0,
                comp_identifier: 0,
                comp_classification_index: 0,
                active_comp_comparison_stamp: 0,
                active_comp_ver_str_type: 0,
                active_comp_ver_str_len: 0,
                active_comp_release_date: [0; PLDM_FWUP_COMPONENT_RELEASE_DATA_LEN],
                pending_comp_comparison_stamp: 0,
                pending_comp_ver_str_type: 0,
                pending_comp_ver_str_len: 0,
                pending_comp_release_date: [0; PLDM_FWUP_COMPONENT_RELEASE_DATA_LEN],
                comp_activation_methods: ComponentActivationMethods(0),
                capabilities_during_update: FirmwareDeviceCapability(0),
            },
            active_comp_ver_str: [0; PLDM_FWUP_IMAGE_SET_VER_STR_MAX_LEN],
            pending_comp_ver_str: None,
        }
    }
}

impl ComponentParameterEntry {
    pub fn new(
        comp_classification: ComponentClassification,
        comp_identifier: u16,
        comp_classification_index: u8,
        active_firmware_version: &PldmFirmwareVersion,
        pending_firmware_version: &PldmFirmwareVersion,
        comp_activation_methods: ComponentActivationMethods,
        capabilities_during_update: FirmwareDeviceCapability,
    ) -> Self {
        ComponentParameterEntry {
            comp_param_entry_fixed: ComponentParameterEntryFixed {
                comp_classification: comp_classification as u16,
                comp_identifier,
                comp_classification_index,
                active_comp_comparison_stamp: active_firmware_version.comparison_stamp,
                active_comp_ver_str_type: active_firmware_version.str.str_type,
                active_comp_ver_str_len: active_firmware_version.str.str_len,
                active_comp_release_date: active_firmware_version.date,
                pending_comp_comparison_stamp: pending_firmware_version.comparison_stamp,
                pending_comp_ver_str_type: pending_firmware_version.str.str_type,
                pending_comp_ver_str_len: pending_firmware_version.str.str_len,
                pending_comp_release_date: pending_firmware_version.date,
                comp_activation_methods,
                capabilities_during_update,
            },
            active_comp_ver_str: {
                let mut arr = [0u8; PLDM_FWUP_IMAGE_SET_VER_STR_MAX_LEN];
                let len = active_firmware_version.str.str_len as usize;
                arr[..len].copy_from_slice(&active_firmware_version.str.str_data[..len]);
                arr
            },
            pending_comp_ver_str: {
                if pending_firmware_version.str.str_len > 0 {
                    let mut arr = [0u8; PLDM_FWUP_IMAGE_SET_VER_STR_MAX_LEN];
                    let len = pending_firmware_version.str.str_len as usize;
                    arr[..len].copy_from_slice(&pending_firmware_version.str.str_data[..len]);
                    Some(arr)
                } else {
                    None
                }
            },
        }
    }

    pub fn codec_size_in_bytes(&self) -> usize {
        let mut bytes = 0;
        bytes += core::mem::size_of::<ComponentParameterEntryFixed>();
        bytes += self.comp_param_entry_fixed.active_comp_ver_str_len as usize;
        if self.pending_comp_ver_str.is_some() {
            bytes += self.comp_param_entry_fixed.pending_comp_ver_str_len as usize;
        }
        bytes
    }
}

impl PldmCodec for ComponentParameterEntry {
    fn encode(&self, buffer: &mut [u8]) -> Result<usize, PldmCodecError> {
        if buffer.len() < self.codec_size_in_bytes() {
            return Err(PldmCodecError::BufferTooShort);
        }
        let mut offset = 0;

        self.comp_param_entry_fixed
            .write_to(
                &mut buffer[offset..offset + core::mem::size_of::<ComponentParameterEntryFixed>()],
            )
            .unwrap();

        offset += core::mem::size_of::<ComponentParameterEntryFixed>();

        let len = self.comp_param_entry_fixed.active_comp_ver_str_len as usize;
        self.active_comp_ver_str[..len]
            .write_to(&mut buffer[offset..offset + len])
            .unwrap();
        offset += len;

        if let Some(pending_comp_ver_str) = &self.pending_comp_ver_str {
            let len = self.comp_param_entry_fixed.pending_comp_ver_str_len as usize;
            pending_comp_ver_str[..len]
                .write_to(&mut buffer[offset..offset + len])
                .unwrap();
            offset += len;
        }

        Ok(offset)
    }

    fn decode(buffer: &[u8]) -> Result<Self, PldmCodecError> {
        let mut offset = 0;

        let comp_param_entry_fixed = ComponentParameterEntryFixed::read_from_bytes(
            buffer
                .get(offset..offset + core::mem::size_of::<ComponentParameterEntryFixed>())
                .ok_or(PldmCodecError::BufferTooShort)?,
        )
        .unwrap();

        offset += core::mem::size_of::<ComponentParameterEntryFixed>();

        let active_comp_ver_str_len = comp_param_entry_fixed.active_comp_ver_str_len as usize;
        let mut active_comp_ver_str = [0u8; PLDM_FWUP_IMAGE_SET_VER_STR_MAX_LEN];
        active_comp_ver_str[..active_comp_ver_str_len].copy_from_slice(
            buffer
                .get(offset..offset + active_comp_ver_str_len)
                .ok_or(PldmCodecError::BufferTooShort)?,
        );
        offset += active_comp_ver_str_len;

        let pending_comp_ver_str = if comp_param_entry_fixed.pending_comp_ver_str_len > 0 {
            let len = comp_param_entry_fixed.pending_comp_ver_str_len as usize;
            let mut arr = [0u8; PLDM_FWUP_IMAGE_SET_VER_STR_MAX_LEN];
            arr[..len].copy_from_slice(
                buffer
                    .get(offset..offset + len)
                    .ok_or(PldmCodecError::BufferTooShort)?,
            );
            Some(arr)
        } else {
            None
        };

        Ok(ComponentParameterEntry {
            comp_param_entry_fixed,
            active_comp_ver_str,
            pending_comp_ver_str,
        })
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum ComponentResponse {
    CompCanBeUpdated,
    CompCannotBeUpdated,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum ComponentResponseCode {
    CompCanBeUpdated = 0x00,
    CompComparisonStampIdentical = 0x01,
    CompComparisonStampLower = 0x02,
    InvalidCompComparisonStamp = 0x03,
    CompConflict = 0x04,
    CompPrerequisitesNotMet = 0x05,
    CompNotSupported = 0x06,
    CompSecurityRestrictions = 0x07,
    IncompleteCompImageSet = 0x08,
    ActiveImageNotUpdateableSubsequently = 0x09,
    CompVerStrIdentical = 0x0a,
    CompVerStrLower = 0x0b,
    VendorDefined, // 0xd0..=0xef
}

impl TryFrom<u8> for ComponentResponseCode {
    type Error = PldmError;

    fn try_from(val: u8) -> Result<Self, PldmError> {
        match val {
            0x00 => Ok(ComponentResponseCode::CompCanBeUpdated),
            0x01 => Ok(ComponentResponseCode::CompComparisonStampIdentical),
            0x02 => Ok(ComponentResponseCode::CompComparisonStampLower),
            0x03 => Ok(ComponentResponseCode::InvalidCompComparisonStamp),
            0x04 => Ok(ComponentResponseCode::CompConflict),
            0x05 => Ok(ComponentResponseCode::CompPrerequisitesNotMet),
            0x06 => Ok(ComponentResponseCode::CompNotSupported),
            0x07 => Ok(ComponentResponseCode::CompSecurityRestrictions),
            0x08 => Ok(ComponentResponseCode::IncompleteCompImageSet),
            0x09 => Ok(ComponentResponseCode::ActiveImageNotUpdateableSubsequently),
            0x0a => Ok(ComponentResponseCode::CompVerStrIdentical),
            0x0b => Ok(ComponentResponseCode::CompVerStrLower),
            0xd0..=0xef => Ok(ComponentResponseCode::VendorDefined),
            _ => Err(PldmError::InvalidComponentResponseCode),
        }
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum ComponentCompatibilityResponse {
    CompCanBeUpdated = 0,
    CompCannotBeUpdated = 1,
}

impl TryFrom<u8> for ComponentCompatibilityResponse {
    type Error = PldmError;

    fn try_from(val: u8) -> Result<Self, PldmError> {
        match val {
            0 => Ok(ComponentCompatibilityResponse::CompCanBeUpdated),
            1 => Ok(ComponentCompatibilityResponse::CompCannotBeUpdated),
            _ => Err(PldmError::InvalidComponentCompatibilityResponse),
        }
    }
}

#[repr(u8)]
pub enum ComponentCompatibilityResponseCode {
    NoResponseCode = 0x00,
    CompComparisonStampIdentical = 0x01,
    CompComparisonStampLower = 0x02,
    InvalidCompComparisonStamp = 0x03,
    CompConflict = 0x04,
    CompPrerequisitesNotMet = 0x05,
    CompNotSupported = 0x06,
    CompSecurityRestrictions = 0x07,
    IncompleteCompImageSet = 0x08,
    CompInfoNoMatch = 0x09,
    CompVerStrIdentical = 0x0a,
    CompVerStrLower = 0x0b,
    VendorDefined,
}

impl TryFrom<u8> for ComponentCompatibilityResponseCode {
    type Error = PldmError;

    fn try_from(val: u8) -> Result<Self, PldmError> {
        match val {
            0x00 => Ok(ComponentCompatibilityResponseCode::NoResponseCode),
            0x01 => Ok(ComponentCompatibilityResponseCode::CompComparisonStampIdentical),
            0x02 => Ok(ComponentCompatibilityResponseCode::CompComparisonStampLower),
            0x03 => Ok(ComponentCompatibilityResponseCode::InvalidCompComparisonStamp),
            0x04 => Ok(ComponentCompatibilityResponseCode::CompConflict),
            0x05 => Ok(ComponentCompatibilityResponseCode::CompPrerequisitesNotMet),
            0x06 => Ok(ComponentCompatibilityResponseCode::CompNotSupported),
            0x07 => Ok(ComponentCompatibilityResponseCode::CompSecurityRestrictions),
            0x08 => Ok(ComponentCompatibilityResponseCode::IncompleteCompImageSet),
            0x09 => Ok(ComponentCompatibilityResponseCode::CompInfoNoMatch),
            0x0a => Ok(ComponentCompatibilityResponseCode::CompVerStrIdentical),
            0x0b => Ok(ComponentCompatibilityResponseCode::CompVerStrLower),
            0xd0..=0xef => Ok(ComponentCompatibilityResponseCode::VendorDefined),
            _ => Err(PldmError::InvalidComponentCompatibilityResponseCode),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_descriptor_encode_decode() {
        let test_uid = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10,
        ];
        let descriptor = Descriptor::new(DescriptorType::Uuid, &test_uid).unwrap();
        assert_eq!(
            descriptor.descriptor_length,
            get_descriptor_length(DescriptorType::Uuid) as u16
        );
        let mut buffer = [0u8; 512];
        descriptor.encode(&mut buffer).unwrap();
        let decoded_descriptor = Descriptor::decode(&buffer).unwrap();
        assert_eq!(descriptor, decoded_descriptor);
    }

    #[test]
    fn test_component_parameter_entry() {
        let active_firmware_string = PldmFirmwareString::new("UTF-8", "mcu-runtime-1.0").unwrap();
        let active_firmware_version =
            PldmFirmwareVersion::new(0x12345678, &active_firmware_string, Some("20250210"));

        let pending_firmware_string = PldmFirmwareString::new("UTF-8", "mcu-runtime-1.5").unwrap();
        let pending_firmware_version =
            PldmFirmwareVersion::new(0x87654321, &pending_firmware_string, Some("20250213"));

        let comp_activation_methods = ComponentActivationMethods(0x0001);
        let capabilities_during_update = FirmwareDeviceCapability(0x0010);

        let component_parameter_entry = ComponentParameterEntry::new(
            ComponentClassification::Firmware,
            0x0001,
            0x01,
            &active_firmware_version,
            &pending_firmware_version,
            comp_activation_methods,
            capabilities_during_update,
        );

        let mut buffer = [0u8; 512];
        component_parameter_entry.encode(&mut buffer).unwrap();
        let decoded_component_parameter_entry = ComponentParameterEntry::decode(&buffer).unwrap();
        assert_eq!(component_parameter_entry, decoded_component_parameter_entry);
    }
}
