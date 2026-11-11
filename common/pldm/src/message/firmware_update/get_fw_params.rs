// Licensed under the Apache-2.0 license

use crate::codec::{PldmCodec, PldmCodecError};
use crate::protocol::base::{
    InstanceId, PldmMsgHeader, PldmMsgType, PldmSupportedType, PLDM_MSG_HEADER_LEN,
};
use crate::protocol::firmware_update::{
    ComponentParameterEntry, FirmwareDeviceCapability, FwUpdateCmd, PldmFirmwareString,
    MAX_COMPONENT_COUNT, PLDM_FWUP_IMAGE_SET_VER_STR_MAX_LEN,
};
use zerocopy::{FromBytes, Immutable, IntoBytes};

#[derive(Debug, Clone, FromBytes, IntoBytes, Immutable, PartialEq)]
#[repr(C, packed)]
pub struct GetFirmwareParametersRequest {
    pub hdr: PldmMsgHeader<[u8; PLDM_MSG_HEADER_LEN]>,
}

impl GetFirmwareParametersRequest {
    pub fn new(instance_id: InstanceId, message_type: PldmMsgType) -> Self {
        GetFirmwareParametersRequest {
            hdr: PldmMsgHeader::new(
                instance_id,
                message_type,
                PldmSupportedType::FwUpdate,
                FwUpdateCmd::GetFirmwareParameters as u8,
            ),
        }
    }
}

#[derive(Debug, Clone, PartialEq, FromBytes, IntoBytes, Immutable)]
#[repr(C, packed)]
pub struct FirmwareParamFixed {
    pub capabilities_during_update: FirmwareDeviceCapability,
    pub comp_count: u16,
    pub active_comp_image_set_ver_str_type: u8,
    pub active_comp_image_set_ver_str_len: u8,
    pub pending_comp_image_set_ver_str_type: u8,
    pub pending_comp_image_set_ver_str_len: u8,
}

impl Default for FirmwareParamFixed {
    fn default() -> Self {
        FirmwareParamFixed {
            capabilities_during_update: FirmwareDeviceCapability(0),
            comp_count: 0,
            active_comp_image_set_ver_str_type: 0,
            active_comp_image_set_ver_str_len: 0,
            pending_comp_image_set_ver_str_type: 0,
            pending_comp_image_set_ver_str_len: 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
#[repr(C)]
pub struct FirmwareParameters {
    pub params_fixed: FirmwareParamFixed,
    pub active_comp_image_set_ver_str: [u8; PLDM_FWUP_IMAGE_SET_VER_STR_MAX_LEN],
    pub pending_comp_image_set_ver_str: Option<[u8; PLDM_FWUP_IMAGE_SET_VER_STR_MAX_LEN]>,
    pub comp_param_table: [ComponentParameterEntry; MAX_COMPONENT_COUNT],
}

impl FirmwareParameters {
    pub fn new(
        capabilities_during_update: FirmwareDeviceCapability,
        comp_count: u16,
        active_comp_image_set_version: &PldmFirmwareString,
        pending_comp_image_set_version: &PldmFirmwareString,
        comp_param_table: &[ComponentParameterEntry],
    ) -> Self {
        FirmwareParameters {
            params_fixed: FirmwareParamFixed {
                capabilities_during_update,
                comp_count,
                active_comp_image_set_ver_str_type: active_comp_image_set_version.str_type,
                active_comp_image_set_ver_str_len: active_comp_image_set_version.str_len,
                pending_comp_image_set_ver_str_type: pending_comp_image_set_version.str_type,
                pending_comp_image_set_ver_str_len: pending_comp_image_set_version.str_len,
            },
            pending_comp_image_set_ver_str: if pending_comp_image_set_version.str_len > 0 {
                let mut arr = [0u8; PLDM_FWUP_IMAGE_SET_VER_STR_MAX_LEN];
                let len = pending_comp_image_set_version.str_data.len();
                arr[..len].copy_from_slice(&pending_comp_image_set_version.str_data);
                Some(arr)
            } else {
                None
            },
            active_comp_image_set_ver_str: {
                let mut arr = [0u8; PLDM_FWUP_IMAGE_SET_VER_STR_MAX_LEN];
                let len = active_comp_image_set_version.str_data.len();
                arr[..len].copy_from_slice(&active_comp_image_set_version.str_data);
                arr
            },
            comp_param_table: {
                let count = comp_param_table.len().min(MAX_COMPONENT_COUNT);
                core::array::from_fn(|i| {
                    if i < count {
                        comp_param_table[i].clone()
                    } else {
                        ComponentParameterEntry::default()
                    }
                })
            },
        }
    }

    fn codec_size_in_bytes(&self) -> usize {
        let mut bytes = core::mem::size_of::<FirmwareParamFixed>();
        if self.pending_comp_image_set_ver_str.is_some() {
            bytes += self.params_fixed.pending_comp_image_set_ver_str_len as usize;
        }
        bytes += self.params_fixed.active_comp_image_set_ver_str_len as usize;

        for i in 0..self.params_fixed.comp_count as usize {
            bytes += self.comp_param_table[i].codec_size_in_bytes();
        }
        bytes
    }
}

impl PldmCodec for FirmwareParameters {
    fn encode(&self, buffer: &mut [u8]) -> Result<usize, PldmCodecError> {
        let entries = self
            .comp_param_table
            .get(..self.params_fixed.comp_count as usize)
            .ok_or(PldmCodecError::BufferTooShort)?;
        if buffer.len() < self.codec_size_in_bytes() {
            return Err(PldmCodecError::BufferTooShort);
        }
        let mut offset = self.params_fixed.encode(buffer)?;

        let len = self.params_fixed.active_comp_image_set_ver_str_len as usize;
        let active = self
            .active_comp_image_set_ver_str
            .get(..len)
            .ok_or(PldmCodecError::BufferTooShort)?;
        buffer
            .get_mut(offset..offset + len)
            .ok_or(PldmCodecError::BufferTooShort)?
            .copy_from_slice(active);
        offset += len;

        if let Some(pending_comp_image_set_ver_str) = &self.pending_comp_image_set_ver_str {
            let len = self.params_fixed.pending_comp_image_set_ver_str_len as usize;
            let pending = pending_comp_image_set_ver_str
                .get(..len)
                .ok_or(PldmCodecError::BufferTooShort)?;
            buffer
                .get_mut(offset..offset + len)
                .ok_or(PldmCodecError::BufferTooShort)?
                .copy_from_slice(pending);
            offset += len;
        }

        for entry in entries {
            let bytes = entry.encode(
                buffer
                    .get_mut(offset..)
                    .ok_or(PldmCodecError::BufferTooShort)?,
            )?;
            offset += bytes;
        }

        Ok(offset)
    }

    fn decode(buffer: &[u8]) -> Result<Self, PldmCodecError> {
        let mut offset = 0;

        let params_fixed = FirmwareParamFixed::read_from_bytes(
            buffer
                .get(offset..offset + core::mem::size_of::<FirmwareParamFixed>())
                .ok_or(PldmCodecError::BufferTooShort)?,
        )
        .unwrap();
        offset += core::mem::size_of::<FirmwareParamFixed>();

        let mut active_comp_image_set_ver_str = [0u8; PLDM_FWUP_IMAGE_SET_VER_STR_MAX_LEN];
        let len = params_fixed.active_comp_image_set_ver_str_len as usize;
        active_comp_image_set_ver_str[..len].copy_from_slice(
            buffer
                .get(offset..offset + len)
                .ok_or(PldmCodecError::BufferTooShort)?,
        );

        offset += len;

        let pending_comp_image_set_ver_str = if params_fixed.pending_comp_image_set_ver_str_len > 0
        {
            let mut arr = [0u8; PLDM_FWUP_IMAGE_SET_VER_STR_MAX_LEN];
            let len = params_fixed.pending_comp_image_set_ver_str_len as usize;
            arr[..len].copy_from_slice(
                buffer
                    .get(offset..offset + len)
                    .ok_or(PldmCodecError::BufferTooShort)?,
            );
            Some(arr)
        } else {
            None
        };
        offset += params_fixed.pending_comp_image_set_ver_str_len as usize;

        let mut index = 0;
        let comp_param_table: [ComponentParameterEntry; MAX_COMPONENT_COUNT] =
            core::array::from_fn(|_| {
                if index < params_fixed.comp_count as usize {
                    let comp_param_table_entry =
                        ComponentParameterEntry::decode(&buffer[offset..]).unwrap();
                    offset += comp_param_table_entry.codec_size_in_bytes();
                    index += 1;
                    comp_param_table_entry
                } else {
                    ComponentParameterEntry::default() // Fill remaining slots with default values
                }
            });

        Ok(FirmwareParameters {
            params_fixed,
            active_comp_image_set_ver_str,
            pending_comp_image_set_ver_str,
            comp_param_table,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
#[repr(C)]
pub struct GetFirmwareParametersResponse {
    pub hdr: PldmMsgHeader<[u8; PLDM_MSG_HEADER_LEN]>,
    pub completion_code: u8,
    pub parms: FirmwareParameters,
}

impl GetFirmwareParametersResponse {
    pub fn new(instance_id: InstanceId, completion_code: u8, parms: &FirmwareParameters) -> Self {
        GetFirmwareParametersResponse {
            hdr: PldmMsgHeader::new(
                instance_id,
                PldmMsgType::Response,
                PldmSupportedType::FwUpdate,
                FwUpdateCmd::GetFirmwareParameters as u8,
            ),
            completion_code,
            parms: parms.clone(),
        }
    }

    // Calculate the size of the response in bytes for encoding
    pub fn codec_size_in_bytes(&self) -> usize {
        let mut bytes = 0;
        bytes +=
            PLDM_MSG_HEADER_LEN + core::mem::size_of::<u8>() + self.parms.codec_size_in_bytes();
        bytes
    }
}

impl PldmCodec for GetFirmwareParametersResponse {
    fn encode(&self, buffer: &mut [u8]) -> Result<usize, PldmCodecError> {
        if self.parms.params_fixed.comp_count as usize > self.parms.comp_param_table.len() {
            return Err(PldmCodecError::BufferTooShort);
        }
        if buffer.len() < self.codec_size_in_bytes() {
            return Err(PldmCodecError::BufferTooShort);
        }
        let mut offset = self.hdr.encode(buffer)?;

        offset += self.completion_code.encode(
            buffer
                .get_mut(offset..)
                .ok_or(PldmCodecError::BufferTooShort)?,
        )?;

        let bytes = self.parms.encode(
            buffer
                .get_mut(offset..)
                .ok_or(PldmCodecError::BufferTooShort)?,
        )?;
        offset += bytes;
        Ok(offset)
    }

    fn decode(buffer: &[u8]) -> Result<Self, PldmCodecError> {
        let mut offset = 0;

        let hdr = PldmMsgHeader::read_from_bytes(
            buffer
                .get(offset..offset + PLDM_MSG_HEADER_LEN)
                .ok_or(PldmCodecError::BufferTooShort)?,
        )
        .unwrap();

        offset += PLDM_MSG_HEADER_LEN;
        let completion_code = u8::read_from_bytes(
            buffer
                .get(offset..offset + core::mem::size_of::<u8>())
                .ok_or(PldmCodecError::BufferTooShort)?,
        )
        .unwrap();
        offset += core::mem::size_of::<u8>();

        let parms = FirmwareParameters::decode(&buffer[offset..])?;
        Ok(GetFirmwareParametersResponse {
            hdr,
            completion_code,
            parms,
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use crate::protocol::firmware_update::{
        ComponentActivationMethods, ComponentClassification, FirmwareDeviceCapability,
        PldmFirmwareString, PldmFirmwareVersion,
    };

    fn construct_firmware_params() -> FirmwareParameters {
        // Construct firmware params
        let active_firmware_string = PldmFirmwareString::new("ASCII", "mcu-runtime-1.0").unwrap();
        let active_firmware_version =
            PldmFirmwareVersion::new(0x12345678, &active_firmware_string, Some("20250210"));
        let pending_firmware_string = PldmFirmwareString::new("ASCII", "mcu-runtime-1.5").unwrap();
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
    fn test_get_firmware_parameters_request() {
        let request = GetFirmwareParametersRequest::new(0, PldmMsgType::Request);
        let mut buffer = [0u8; PLDM_MSG_HEADER_LEN];
        request.encode(&mut buffer).unwrap();
        let decoded_request = GetFirmwareParametersRequest::decode(&buffer).unwrap();
        assert_eq!(request, decoded_request);
    }

    #[test]
    fn test_get_firmware_parameters() {
        let firmware_parameters = construct_firmware_params();
        let mut buffer = [0u8; 1024];
        let size = firmware_parameters.encode(&mut buffer).unwrap();
        assert_eq!(size, firmware_parameters.codec_size_in_bytes());
        let decoded_firmware_parameters = FirmwareParameters::decode(&buffer[..size]).unwrap();
        assert_eq!(firmware_parameters, decoded_firmware_parameters);
    }

    #[test]
    fn test_get_firmware_parameters_response() {
        let firmware_parameters = construct_firmware_params();
        let response = GetFirmwareParametersResponse::new(0, 0, &firmware_parameters);
        let mut buffer = [0u8; 1024];
        let size = response.encode(&mut buffer).unwrap();
        assert_eq!(size, response.codec_size_in_bytes());
        let decoded_response = GetFirmwareParametersResponse::decode(&buffer[..size]).unwrap();
        assert_eq!(response, decoded_response);
    }

    #[test]
    fn test_encode_firmware_parameters_oversized_count() {
        let mut parameters = FirmwareParameters::default();
        parameters.params_fixed.comp_count = (MAX_COMPONENT_COUNT + 1) as u16;
        let mut buffer = [0u8; 1024];
        assert_eq!(
            parameters.encode(&mut buffer),
            Err(PldmCodecError::BufferTooShort)
        );
        let response = GetFirmwareParametersResponse::new(0, 0, &parameters);
        assert_eq!(
            response.encode(&mut buffer),
            Err(PldmCodecError::BufferTooShort)
        );
    }

    #[test]
    fn test_encode_firmware_parameters_oversized_versions() {
        for pending in [false, true] {
            let mut parameters = FirmwareParameters::default();
            if pending {
                parameters.params_fixed.pending_comp_image_set_ver_str_len =
                    (PLDM_FWUP_IMAGE_SET_VER_STR_MAX_LEN + 1) as u8;
                parameters.pending_comp_image_set_ver_str =
                    Some([0; PLDM_FWUP_IMAGE_SET_VER_STR_MAX_LEN]);
            } else {
                parameters.params_fixed.active_comp_image_set_ver_str_len =
                    (PLDM_FWUP_IMAGE_SET_VER_STR_MAX_LEN + 1) as u8;
            }
            let mut buffer = [0u8; 1024];
            assert_eq!(
                parameters.encode(&mut buffer),
                Err(PldmCodecError::BufferTooShort)
            );
            let response = GetFirmwareParametersResponse::new(0, 0, &parameters);
            assert_eq!(
                response.encode(&mut buffer),
                Err(PldmCodecError::BufferTooShort)
            );
        }
    }
}
