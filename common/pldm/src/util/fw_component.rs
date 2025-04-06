// Licensed under the Apache-2.0 license

use crate::message::firmware_update::get_fw_params::FirmwareParameters;
use crate::protocol::firmware_update::{
    ComponentResponseCode, PldmFirmwareString, UpdateOptionFlags,
};

// An entry for Pass Component Table or Update Component
#[derive(Clone, Default)]
pub struct FirmwareComponent {
    pub comp_classification: u16,
    pub comp_identifier: u16,
    pub comp_classification_index: u8,
    pub comp_comparison_stamp: u32,
    pub comp_version: PldmFirmwareString,
    pub comp_image_size: Option<u32>,
    pub update_option_flags: Option<UpdateOptionFlags>,
}

impl FirmwareComponent {
    pub fn new(
        comp_classification: u16,
        comp_identifier: u16,
        comp_classification_index: u8,
        comp_comparison_stamp: u32,
        comp_version: PldmFirmwareString,
        comp_image_size: Option<u32>,
        update_option_flags: Option<UpdateOptionFlags>,
    ) -> Self {
        Self {
            comp_classification,
            comp_identifier,
            comp_classification_index,
            comp_comparison_stamp,
            comp_version,
            comp_image_size,
            update_option_flags,
        }
    }

    // Determines if the component is eligible for an update based on the firmware parameters and returns the appropriate ComponentResponseCode
    // defined in the PLDM firmware update specification.
    pub fn evaluate_update_eligibility(
        &self,
        fw_params: &FirmwareParameters,
    ) -> ComponentResponseCode {
        if let Some(entry) = fw_params.comp_param_table.iter().find(|entry| {
            entry.comp_param_entry_fixed.comp_classification == self.comp_classification
                && entry.comp_param_entry_fixed.comp_identifier == self.comp_identifier
                && entry.comp_param_entry_fixed.comp_classification_index
                    == self.comp_classification_index
        }) {
            if self.comp_comparison_stamp
                == entry.comp_param_entry_fixed.active_comp_comparison_stamp
            {
                ComponentResponseCode::CompComparisonStampIdentical
            } else if self.comp_comparison_stamp
                < entry.comp_param_entry_fixed.active_comp_comparison_stamp
            {
                ComponentResponseCode::CompComparisonStampLower
            } else if self.comp_version == entry.get_active_fw_ver() {
                ComponentResponseCode::CompVerStrIdentical
            } else if self.comp_version < entry.get_active_fw_ver() {
                ComponentResponseCode::CompVerStrLower
            } else {
                ComponentResponseCode::CompCanBeUpdated
            }
        } else {
            ComponentResponseCode::CompNotSupported
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::protocol::firmware_update::{
        ComponentActivationMethods, ComponentClassification, ComponentParameterEntry,
        FirmwareDeviceCapability, PldmFirmwareVersion,
    };

    fn construct_firmware_params() -> FirmwareParameters {
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

        const COMP_COUNT: usize = 8;
        let comp_param_table: [ComponentParameterEntry; COMP_COUNT] =
            core::array::from_fn(|_| component_parameter_entry.clone());
        FirmwareParameters::new(
            capabilities_during_update,
            COMP_COUNT as u16,
            &active_firmware_string,
            &pending_firmware_string,
            &comp_param_table,
        )
    }

    #[test]
    fn test_check_update_component() {
        let fw_params = construct_firmware_params();
        let comp = FirmwareComponent::new(
            ComponentClassification::Firmware as u16,
            0x0001,
            0x01,
            0x12345680,
            PldmFirmwareString::new("UTF-8", "mcu-runtime-1.2").unwrap(),
            None,
            None,
        );
        assert_eq!(
            comp.evaluate_update_eligibility(&fw_params),
            ComponentResponseCode::CompCanBeUpdated
        );

        let comp = FirmwareComponent::new(
            ComponentClassification::Firmware as u16,
            0x0001,
            0x01,
            0x12345670,
            PldmFirmwareString::new("UTF-8", "mcu-runtime-1.2").unwrap(),
            None,
            None,
        );
        assert_eq!(
            comp.evaluate_update_eligibility(&fw_params),
            ComponentResponseCode::CompComparisonStampLower
        );

        let comp = FirmwareComponent::new(
            ComponentClassification::Firmware as u16,
            0x0001,
            0x01,
            0x12345678,
            PldmFirmwareString::new("UTF-8", "mcu-runtime-1.5").unwrap(),
            None,
            None,
        );
        assert_eq!(
            comp.evaluate_update_eligibility(&fw_params),
            ComponentResponseCode::CompComparisonStampIdentical
        );

        let comp = FirmwareComponent::new(
            ComponentClassification::Firmware as u16,
            0x0001,
            0x01,
            0x12345680,
            PldmFirmwareString::new("UTF-8", "mcu-runtime-0.5").unwrap(),
            None,
            None,
        );
        assert_eq!(
            comp.evaluate_update_eligibility(&fw_params),
            ComponentResponseCode::CompVerStrLower
        );

        let comp = FirmwareComponent::new(
            ComponentClassification::Firmware as u16,
            0x0001,
            0x01,
            0x12345680,
            PldmFirmwareString::new("UTF-8", "mcu-runtime-1.0").unwrap(),
            None,
            None,
        );
        assert_eq!(
            comp.evaluate_update_eligibility(&fw_params),
            ComponentResponseCode::CompVerStrIdentical
        );

        let comp = FirmwareComponent::new(
            ComponentClassification::Firmware as u16,
            0x0001,
            0x05,
            0x12345680,
            PldmFirmwareString::new("UTF-8", "mcu-runtime-1.0").unwrap(),
            None,
            None,
        );
        assert_eq!(
            comp.evaluate_update_eligibility(&fw_params),
            ComponentResponseCode::CompNotSupported
        );
    }
}
