// Licensed under the Apache-2.0 license

//! Decoders take their input from a peer. A message that is cut short, or
//! that carries a length too large for the fixed-size fields it is copied
//! into, must be rejected with an error instead of panicking.

use caliptra_mcu_pldm_common::codec::{PldmCodec, PldmCodecError};
use caliptra_mcu_pldm_common::message::firmware_update::get_fw_params::{
    FirmwareParamFixed, FirmwareParameters, GetFirmwareParametersResponse,
};
use caliptra_mcu_pldm_common::message::firmware_update::pass_component::{
    PassComponentTableRequest, PassComponentTableRequestFixed,
};
use caliptra_mcu_pldm_common::message::firmware_update::query_devid::QueryDeviceIdentifiersResponse;
use caliptra_mcu_pldm_common::message::firmware_update::request_update::{
    RequestUpdateRequest, RequestUpdateRequestFixed,
};
use caliptra_mcu_pldm_common::message::firmware_update::update_component::{
    UpdateComponentRequest, UpdateComponentRequestFixed,
};
use caliptra_mcu_pldm_common::protocol::base::{PldmMsgType, TransferRespFlag};
use caliptra_mcu_pldm_common::protocol::firmware_update::{
    ComponentActivationMethods, ComponentClassification, ComponentParameterEntry,
    ComponentParameterEntryFixed, Descriptor, DescriptorType, FirmwareDeviceCapability,
    PldmFirmwareString, PldmFirmwareVersion, UpdateOptionFlags, DESCRIPTOR_DATA_MAX_LEN,
    MAX_COMPONENT_COUNT, PLDM_FWUP_IMAGE_SET_VER_STR_MAX_LEN,
};
use core::mem::{offset_of, size_of};

const STR_TOO_LONG: u8 = PLDM_FWUP_IMAGE_SET_VER_STR_MAX_LEN as u8 + 1;

fn encode<T: PldmCodec>(msg: &T) -> Vec<u8> {
    let mut buf = vec![0u8; 2048];
    let len = msg.encode(&mut buf).unwrap();
    buf.truncate(len);
    buf
}

/// Every strict prefix of a valid message is too short.
fn check_truncated<T: PldmCodec>(msg: &T) {
    let buf = encode(msg);
    for len in 0..buf.len() {
        assert_eq!(
            T::decode(&buf[..len]).err(),
            Some(PldmCodecError::BufferTooShort),
            "decoding {len} of {} bytes",
            buf.len()
        );
    }
}

/// Overwrite the length byte at `at` with `len`. The buffer is padded so that
/// the data the length claims is present, and only the length is wrong.
fn check_length_rejected<T: PldmCodec>(msg: &T, at: usize, len: u8) {
    let mut buf = encode(msg);
    buf[at] = len;
    buf.resize(buf.len() + 256, 0);
    assert_eq!(T::decode(&buf).err(), Some(PldmCodecError::InvalidData));
}

fn version_string() -> PldmFirmwareString {
    PldmFirmwareString::new("ASCII", "mcu-fw-1.2.0").unwrap()
}

fn request_update() -> RequestUpdateRequest {
    RequestUpdateRequest::new(0, PldmMsgType::Request, 512, 1, 1, 0, &version_string())
}

fn pass_component() -> PassComponentTableRequest {
    PassComponentTableRequest::new(
        0,
        PldmMsgType::Request,
        TransferRespFlag::StartAndEnd,
        ComponentClassification::Firmware,
        1,
        0,
        1,
        &version_string(),
    )
}

fn update_component() -> UpdateComponentRequest {
    UpdateComponentRequest::new(
        0,
        PldmMsgType::Request,
        ComponentClassification::Firmware,
        1,
        0,
        1,
        0x1000,
        UpdateOptionFlags(0),
        &version_string(),
    )
}

fn descriptor() -> Descriptor {
    Descriptor::new(DescriptorType::Uuid, &[0x5a; 16]).unwrap()
}

fn query_devid() -> QueryDeviceIdentifiersResponse {
    QueryDeviceIdentifiersResponse::new(0, 0, &descriptor(), Some(&[descriptor()])).unwrap()
}

fn comp_param_entry() -> ComponentParameterEntry {
    let ver = version_string();
    let active = PldmFirmwareVersion::new(1, &ver, Some("20260101"));
    let pending = PldmFirmwareVersion::new(2, &ver, Some("20260102"));
    ComponentParameterEntry::new(
        ComponentClassification::Firmware,
        1,
        0,
        &active,
        &pending,
        ComponentActivationMethods(1),
        FirmwareDeviceCapability(0),
    )
}

fn fw_params(comp_count: usize) -> FirmwareParameters {
    let table = vec![comp_param_entry(); comp_count];
    FirmwareParameters::new(
        FirmwareDeviceCapability(0),
        comp_count as u16,
        &version_string(),
        &version_string(),
        &table,
    )
}

#[test]
fn truncated_messages() {
    check_truncated(&request_update());
    check_truncated(&pass_component());
    check_truncated(&update_component());
    check_truncated(&descriptor());
    check_truncated(&query_devid());
    check_truncated(&comp_param_entry());
    check_truncated(&fw_params(2));
    check_truncated(&GetFirmwareParametersResponse::new(0, 0, &fw_params(2)));
}

#[test]
fn version_string_too_long() {
    check_length_rejected(
        &request_update(),
        offset_of!(RequestUpdateRequestFixed, comp_image_set_ver_str_len),
        STR_TOO_LONG,
    );
    check_length_rejected(
        &pass_component(),
        offset_of!(PassComponentTableRequestFixed, comp_ver_str_len),
        STR_TOO_LONG,
    );
    check_length_rejected(
        &update_component(),
        offset_of!(UpdateComponentRequestFixed, comp_ver_str_len),
        STR_TOO_LONG,
    );
    check_length_rejected(
        &fw_params(1),
        offset_of!(FirmwareParamFixed, active_comp_image_set_ver_str_len),
        STR_TOO_LONG,
    );
    check_length_rejected(
        &fw_params(1),
        offset_of!(FirmwareParamFixed, pending_comp_image_set_ver_str_len),
        STR_TOO_LONG,
    );
}

#[test]
fn descriptor_too_long() {
    // The length follows the 16-bit type.
    let at = size_of::<u16>();
    check_length_rejected(&descriptor(), at, DESCRIPTOR_DATA_MAX_LEN as u8 + 1);

    // The initial descriptor is followed by one more.
    let resp = query_devid();
    let at = encode(&resp).len() - 2 * encode(&descriptor()).len() + at;
    check_length_rejected(&resp, at, DESCRIPTOR_DATA_MAX_LEN as u8 + 1);
}

#[test]
fn component_count_too_large() {
    let at = offset_of!(FirmwareParamFixed, comp_count);
    check_length_rejected(&fw_params(1), at, MAX_COMPONENT_COUNT as u8 + 1);
}

#[test]
fn invalid_component_parameter_entry() {
    let active = offset_of!(ComponentParameterEntryFixed, active_comp_ver_str_len);
    let pending = offset_of!(ComponentParameterEntryFixed, pending_comp_ver_str_len);
    check_length_rejected(&comp_param_entry(), active, STR_TOO_LONG);
    check_length_rejected(&comp_param_entry(), pending, STR_TOO_LONG);

    // The same entry inside GetFirmwareParameters, as the second of two.
    let params = fw_params(2);
    let second = encode(&params).len() - encode(&comp_param_entry()).len();
    check_length_rejected(&params, second + active, STR_TOO_LONG);
    check_length_rejected(&params, second + pending, STR_TOO_LONG);
}
