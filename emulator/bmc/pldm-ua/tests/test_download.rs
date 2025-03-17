// Licensed under the Apache-2.0 license

#[cfg(test)]
mod common;

use std::cmp::min;

use chrono::Utc;
use common::CustomDiscoverySm;
use pldm_common::{
    codec::PldmCodec,
    message::firmware_update::{
        get_fw_params::GetFirmwareParametersResponse,
        pass_component::PassComponentTableResponse,
        query_devid::QueryDeviceIdentifiersResponse,
        request_fw_data::{RequestFirmwareDataRequest, RequestFirmwareDataResponseFixed},
        request_update::RequestUpdateResponse,
        transfer_complete::{TransferCompleteRequest, TransferResult},
    },
    protocol::{
        base::{PldmMsgHeader, PldmMsgType, PldmSupportedType},
        firmware_update::{ComponentResponseCode, FwUpdateCmd},
    },
};
use pldm_fw_pkg::{
    manifest::{
        ComponentImageInformation, Descriptor, DescriptorType, FirmwareDeviceIdRecord,
        PackageHeaderInformation, StringType,
    },
    FirmwareManifest,
};
use pldm_ua::{daemon::Options, events::PldmEvents, transport::PldmSocket, update_sm};
use uuid::Uuid;

// Test UUID
pub const TEST_UUID: [u8; 16] = [
    0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
];
const BASELINE_TRANSFER_SIZE: u32 = 32;

/* Override the Update SM, go directly to UpdateComponent */
struct UpdateSmBypassed {}
impl update_sm::StateMachineActions for UpdateSmBypassed {
    fn on_start_update(
        &mut self,
        ctx: &mut update_sm::InnerContext<impl PldmSocket>,
    ) -> Result<(), ()> {
        ctx.device_id = Some(ctx.pldm_fw_pkg.firmware_device_id_records[0].clone());
        ctx.components = ctx.pldm_fw_pkg.component_image_information.clone();
        for _ in &ctx.components {
            ctx.component_response_codes
                .push(ComponentResponseCode::CompCanBeUpdated);
        }
        ctx.current_component_index = Some(0);
        ctx.event_queue
            .send(PldmEvents::Update(
                update_sm::Events::QueryDeviceIdentifiersResponse(QueryDeviceIdentifiersResponse {
                    ..Default::default()
                }),
            ))
            .map_err(|_| ())?;
        Ok(())
    }
    fn on_query_device_identifiers_response(
        &mut self,
        ctx: &mut update_sm::InnerContext<impl PldmSocket>,
        _response: QueryDeviceIdentifiersResponse,
    ) -> Result<(), ()> {
        ctx.event_queue
            .send(PldmEvents::Update(
                update_sm::Events::SendGetFirmwareParameters,
            ))
            .map_err(|_| ())?;
        Ok(())
    }
    fn on_send_get_firmware_parameters(
        &mut self,
        ctx: &mut update_sm::InnerContext<impl PldmSocket>,
    ) -> Result<(), ()> {
        ctx.event_queue
            .send(PldmEvents::Update(
                update_sm::Events::GetFirmwareParametersResponse(GetFirmwareParametersResponse {
                    ..Default::default()
                }),
            ))
            .map_err(|_| ())
    }
    fn on_get_firmware_parameters_response(
        &mut self,
        ctx: &mut update_sm::InnerContext<impl PldmSocket>,
        _response: pldm_common::message::firmware_update::get_fw_params::GetFirmwareParametersResponse,
    ) -> Result<(), ()> {
        ctx.event_queue
            .send(PldmEvents::Update(update_sm::Events::SendRequestUpdate))
            .map_err(|_| ())
    }
    fn on_send_request_update(
        &mut self,
        ctx: &mut update_sm::InnerContext<impl PldmSocket>,
    ) -> Result<(), ()> {
        ctx.event_queue
            .send(PldmEvents::Update(
                update_sm::Events::RequestUpdateResponse(RequestUpdateResponse {
                    ..Default::default()
                }),
            ))
            .map_err(|_| ())
    }
    fn on_request_update_response(
        &mut self,
        ctx: &mut update_sm::InnerContext<impl PldmSocket>,
        _response: RequestUpdateResponse,
    ) -> Result<(), ()> {
        ctx.event_queue
            .send(PldmEvents::Update(
                update_sm::Events::SendPassComponentRequest,
            ))
            .map_err(|_| ())
    }
    fn on_send_pass_component_request(
        &mut self,
        ctx: &mut update_sm::InnerContext<impl PldmSocket>,
    ) -> Result<(), ()> {
        ctx.event_queue
            .send(PldmEvents::Update(
                update_sm::Events::PassComponentResponse(PassComponentTableResponse {
                    ..Default::default()
                }),
            ))
            .map_err(|_| ())
    }
    fn are_all_components_passed(
        &self,
        _ctx: &update_sm::InnerContext<impl PldmSocket>,
    ) -> Result<bool, ()> {
        Ok(true)
    }
    fn on_all_components_passed(
        &mut self,
        ctx: &mut update_sm::InnerContext<impl PldmSocket>,
    ) -> Result<(), ()> {
        ctx.event_queue
            .send(PldmEvents::Update(update_sm::Events::StartDownload))
            .map_err(|_| ())
    }
}

#[test]
fn test_download_size_divisible_by_transfer_size() {
    let pldm_fw_pkg = FirmwareManifest {
        package_header_information: PackageHeaderInformation {
            package_header_identifier: Uuid::parse_str("7B291C996DB64208801B02026E463C78").unwrap(),
            package_header_format_revision: 1,
            package_release_date_time: Utc::now(),
            package_version_string_type: StringType::Utf8,
            package_version_string: Some("1.0.0".to_string()),
            package_header_size: 0, // This will be computed during encoding
        },
        firmware_device_id_records: vec![FirmwareDeviceIdRecord {
            firmware_device_package_data: Some(vec![0x01, 0x02, 0x03, 0x04]),
            device_update_option_flags: 0xFFFF_FFFF,
            component_image_set_version_string_type: StringType::Ascii,
            component_image_set_version_string: Some("ComponentV1".to_string()),
            applicable_components: Some(vec![0x00]),
            initial_descriptor: Descriptor {
                descriptor_type: DescriptorType::Uuid,
                descriptor_data: vec![0xAA, 0xBB, 0xCC],
            },
            additional_descriptors: None,
            reference_manifest_data: None,
        }],
        downstream_device_id_records: None,
        component_image_information: vec![ComponentImageInformation {
            image_location: None, // Use image_data
            classification: 0x0001,
            identifier: 0x0002,
            comparison_stamp: Some(999),
            options: 0xAABB,
            requested_activation_method: 0x1122,
            version_string_type: StringType::Utf8,
            version_string: Some("FirmwareV1".to_string()),
            opaque_data: Some(vec![0x77, 0x88, 0x99]),
            offset: 0, // Will be calculated in encoding
            size: 256,
            image_data: Some(vec![0x55u8; 256]),
        }],
    };

    // Setup the test environment
    let mut setup = common::setup(Options {
        pldm_fw_pkg: Some(pldm_fw_pkg.clone()),
        discovery_sm_actions: CustomDiscoverySm {},
        update_sm_actions: UpdateSmBypassed {},
        fd_tid: 0x01,
    });

    setup.wait_for_state_transition(update_sm::States::Download);

    let mut instance_id = 0u8;
    let mut downloaded_data: Vec<u8> = Vec::new();
    let mut offset = 0u32;
    while offset < pldm_fw_pkg.component_image_information[0].size {
        let length = min(
            BASELINE_TRANSFER_SIZE,
            pldm_fw_pkg.component_image_information[0].size + BASELINE_TRANSFER_SIZE - offset,
        );

        let request =
            RequestFirmwareDataRequest::new(instance_id, PldmMsgType::Request, offset, length);

        setup.send_response(&setup.fd_sock, &request);

        let response = setup.fd_sock.receive(None).unwrap();

        let header = PldmMsgHeader::decode(&response.payload.data[..response.payload.len])
            .map_err(|_| ())
            .unwrap();

        assert!(header.is_hdr_ver_valid(), "Invalid header version!");
        assert_eq!(header.instance_id(), instance_id);
        assert!(!header.is_request());
        assert_eq!(header.pldm_type(), PldmSupportedType::FwUpdate as u8);
        assert_eq!(header.cmd_code(), FwUpdateCmd::RequestFirmwareData as u8);

        assert!(response.payload.len > core::mem::size_of::<RequestFirmwareDataResponseFixed>());

        let data = &response.payload.data
            [core::mem::size_of::<RequestFirmwareDataResponseFixed>()..response.payload.len];

        downloaded_data.extend_from_slice(data);

        instance_id += 1;
        offset += length;
    }

    assert!(downloaded_data.len() >= pldm_fw_pkg.component_image_information[0].size as usize);

    assert_eq!(
        downloaded_data[..pldm_fw_pkg.component_image_information[0].size as usize],
        pldm_fw_pkg.component_image_information[0]
            .image_data
            .as_ref()
            .unwrap()[..]
    );

    let request = TransferCompleteRequest::new(
        instance_id,
        PldmMsgType::Request,
        TransferResult::TransferSuccess,
    );

    setup.send_response(&setup.fd_sock, &request);

    setup.wait_for_state_transition(update_sm::States::Verify);

    setup.daemon.stop();
}

#[test]
fn test_download_size_not_divisible_by_transfer_size() {
    let mut image_data = vec![0x55u8; 128];
    image_data.extend(vec![0xAAu8, 129]);

    let pldm_fw_pkg = FirmwareManifest {
        package_header_information: PackageHeaderInformation {
            package_header_identifier: Uuid::parse_str("7B291C996DB64208801B02026E463C78").unwrap(),
            package_header_format_revision: 1,
            package_release_date_time: Utc::now(),
            package_version_string_type: StringType::Utf8,
            package_version_string: Some("1.0.0".to_string()),
            package_header_size: 0, // This will be computed during encoding
        },
        firmware_device_id_records: vec![FirmwareDeviceIdRecord {
            firmware_device_package_data: Some(vec![0x01, 0x02, 0x03, 0x04]),
            device_update_option_flags: 0xFFFF_FFFF,
            component_image_set_version_string_type: StringType::Ascii,
            component_image_set_version_string: Some("ComponentV1".to_string()),
            applicable_components: Some(vec![0x00]),
            initial_descriptor: Descriptor {
                descriptor_type: DescriptorType::Uuid,
                descriptor_data: vec![0xAA, 0xBB, 0xCC],
            },
            additional_descriptors: None,
            reference_manifest_data: None,
        }],
        downstream_device_id_records: None,
        component_image_information: vec![ComponentImageInformation {
            image_location: None, // Use image_data
            classification: 0x0001,
            identifier: 0x0002,
            comparison_stamp: Some(999),
            options: 0xAABB,
            requested_activation_method: 0x1122,
            version_string_type: StringType::Utf8,
            version_string: Some("FirmwareV1".to_string()),
            opaque_data: Some(vec![0x77, 0x88, 0x99]),
            offset: 0, // Will be calculated in encoding
            size: image_data.len() as u32,
            image_data: Some(image_data),
        }],
    };

    // Setup the test environment
    let mut setup = common::setup(Options {
        pldm_fw_pkg: Some(pldm_fw_pkg.clone()),
        discovery_sm_actions: CustomDiscoverySm {},
        update_sm_actions: UpdateSmBypassed {},
        fd_tid: 0x01,
    });

    setup.wait_for_state_transition(update_sm::States::Download);

    let mut instance_id = 0u8;
    let mut offset = 0u32;
    let mut downloaded_data: Vec<u8> = Vec::new();
    while offset < pldm_fw_pkg.component_image_information[0].size {
        let length = min(
            BASELINE_TRANSFER_SIZE,
            pldm_fw_pkg.component_image_information[0].size + BASELINE_TRANSFER_SIZE - offset,
        );

        let request =
            RequestFirmwareDataRequest::new(instance_id, PldmMsgType::Request, offset, length);

        setup.send_response(&setup.fd_sock, &request);

        let response = setup.fd_sock.receive(None).unwrap();

        let header = PldmMsgHeader::decode(&response.payload.data[..response.payload.len])
            .map_err(|_| ())
            .unwrap();

        assert!(header.is_hdr_ver_valid(), "Invalid header version!");
        assert_eq!(header.instance_id(), instance_id);
        assert!(!header.is_request());
        assert_eq!(header.pldm_type(), PldmSupportedType::FwUpdate as u8);
        assert_eq!(header.cmd_code(), FwUpdateCmd::RequestFirmwareData as u8);

        assert!(response.payload.len > core::mem::size_of::<RequestFirmwareDataResponseFixed>());

        let data = &response.payload.data
            [core::mem::size_of::<RequestFirmwareDataResponseFixed>()..response.payload.len];

        downloaded_data.extend_from_slice(data);

        instance_id += 1;
        offset += length;
    }

    assert!(downloaded_data.len() >= pldm_fw_pkg.component_image_information[0].size as usize);

    assert_eq!(
        downloaded_data[..pldm_fw_pkg.component_image_information[0].size as usize],
        pldm_fw_pkg.component_image_information[0]
            .image_data
            .as_ref()
            .unwrap()[..]
    );

    // Simulate a transfer error
    let request = TransferCompleteRequest::new(
        instance_id,
        PldmMsgType::Request,
        TransferResult::TransferErrorImageCorrupt,
    );

    setup.send_response(&setup.fd_sock, &request);

    setup.wait_for_state_transition(update_sm::States::Idle);

    setup.daemon.stop();
}
