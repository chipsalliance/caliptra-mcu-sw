// Licensed under the Apache-2.0 license

#[cfg(test)]
mod mock_transport;
use std::time::Duration;

use log::{error, info, LevelFilter};
use mock_transport::{MockPldmSocket, MockTransport};
use pldm_common::message::firmware_update::query_devid::{QueryDeviceIdentifiersRequest, QueryDeviceIdentifiersResponse};
use pldm_common::protocol::base::{
    PldmBaseCompletionCode, PldmControlCmd, PldmMsgHeader, PldmSupportedType, TransferRespFlag
};
use pldm_common::protocol::firmware_update::FwUpdateCmd;
use pldm_common::protocol::version::{PLDM_BASE_PROTOCOL_VERSION, PLDM_FW_UPDATE_PROTOCOL_VERSION};
use pldm_fw_pkg::manifest::{Descriptor, DescriptorType, FirmwareDeviceIdRecord};
use pldm_fw_pkg::FirmwareManifest;
use pldm_ua::events::PldmEvents;
use simple_logger::SimpleLogger;

use pldm_common::codec::PldmCodec;
use pldm_common::message::control::*;
use pldm_ua::daemon::{Options, PldmDaemon};
use pldm_ua::transport::{PldmSocket, PldmTransport};
use pldm_ua::{discovery_sm,update_sm};

const COMPLETION_CODE_SUCCESSFUL: u8 = 0x00;

struct TestSetup {
    pub transport: MockTransport,
    pub ua_sid: pldm_ua::transport::EndpointId,
    pub fd_sid: pldm_ua::transport::EndpointId,
    pub ua_sock: MockPldmSocket,
    pub fd_sock: MockPldmSocket,
    pub daemon: PldmDaemon,
    pub device_tid: u8,
}

// Test UUID
const TEST_UUID: [u8; 16]  = [
        0x12, 0x34, 0x56, 0x78,
        0x9A, 0xBC,
        0xDE, 0xF0,
        0x12, 0x34,
        0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0
    ];

const TEST_UUID2: [u8; 16]  = [
    0x12, 0x34, 0x56, 0x78,
    0x9A, 0xBC,
    0xDE, 0xF0,
    0x12, 0x34,
    0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xFF
];

fn setup<D: discovery_sm::StateMachineActions + Send + 'static,
        U: update_sm::StateMachineActions + Send + 'static>(daemon_options: Options<D,U>) -> TestSetup {
    // Initialize log level to info (only once)
    let _ = SimpleLogger::new()
        .with_level(LevelFilter::Debug)
        .init();

    // Setup the PLDM transport
    let transport = MockTransport::new();

    // Define the update agent endpoint id
    let ua_sid = pldm_ua::transport::EndpointId(0x01);

    // Define the device endpoint id
    let fd_sid = pldm_ua::transport::EndpointId(0x02);

    // Create socket used by the PLDM daemon (update agent)
    let ua_sock = transport.create_socket(ua_sid, fd_sid).unwrap();

    // Create socket to be used by the device (FD)
    let fd_sock = transport.create_socket(fd_sid, ua_sid).unwrap();

    // Run the PLDM daemon
    let daemon = PldmDaemon::run(ua_sock.clone(), daemon_options);

    // Define the device TID constant
    const DEVICE_TID: u8 = 0x01;



    TestSetup {
        transport,
        ua_sid,
        fd_sid,
        ua_sock,
        fd_sock,
        daemon,
        device_tid: DEVICE_TID,
    }
}

/* Override the Discovery SM, essentially bypassing it */
struct CustomDiscoverySm {}
impl discovery_sm::StateMachineActions for CustomDiscoverySm {
    fn on_start_discovery(&self, ctx: &discovery_sm::InnerContext<impl PldmSocket>) -> Result<(), ()> {
        ctx.event_queue.enqueue(PldmEvents::Update(update_sm::Events::StartUpdate));
        Ok(())
    }
}

struct UpdateSmQueryValidDeviceIdentifiers {
    is_query_device_identifiers_response_valid : bool,
}
impl update_sm::StateMachineActions for UpdateSmQueryValidDeviceIdentifiers {
    fn on_query_device_identifiers_response(&mut self, ctx: &mut update_sm::InnerContext<impl PldmSocket>, response : pldm_common::message::firmware_update::query_devid::QueryDeviceIdentifiersResponse) -> Result<(), ()> {
        ctx.event_queue.enqueue(PldmEvents::Stop);
        self.is_query_device_identifiers_response_valid = true;
        Ok(())
    }
    fn on_unsupported_device_identifiers_response(&mut self, ctx: &mut update_sm::InnerContext<impl PldmSocket>, response : pldm_common::message::firmware_update::query_devid::QueryDeviceIdentifiersResponse) -> Result<(), ()> {
        assert_eq!(self.is_query_device_identifiers_response_valid,false);
        Ok(())
    }
}

fn send_response<P: PldmCodec>(socket: &MockPldmSocket, response: &P) {
    let mut buffer = [0u8; 512];
    let sz = response.encode(&mut buffer).unwrap();
    socket.send(&buffer[..sz]).unwrap();
}

fn receive_request<P: PldmCodec>(
    socket: &MockPldmSocket,
    cmd_code: u8,
) -> Result<P, ()> {
    let request = socket.receive(None).unwrap();

    let header = PldmMsgHeader::decode(&request.payload.data[..request.payload.len])
        .map_err(|_| (error!("Error decoding packet!")))?;
    if !header.is_hdr_ver_valid() {
        error!("Invalid header version!");
        return Err(());
    }
    if header.cmd_code() != cmd_code as u8 {
        error!("Invalid command code!");
        return Err(());
    }

    P::decode(&request.payload.data[..request.payload.len])
        .map_err(|_| (error!("Error decoding packet!")))
}


fn encode_descriptor(pkg_descriptor: &pldm_fw_pkg::manifest::Descriptor) -> Result<pldm_common::protocol::firmware_update::Descriptor,()>
{
    let descriptor = pldm_common::protocol::firmware_update::Descriptor {
        descriptor_type: pkg_descriptor.descriptor_type as u16,
        descriptor_length: pkg_descriptor.descriptor_data.len() as u16,
        descriptor_data: {
            let mut array = [0u8; 64];
            let data_slice = pkg_descriptor.descriptor_data.as_slice();
            let len = data_slice.len().min(64);
            array[..len].copy_from_slice(&data_slice[..len]);
            array
        }
    };
    Ok(descriptor)
}

#[test]
fn test_valid_device_identifier_one_descriptor() {
    let pldm_fw_pkg = FirmwareManifest {
        firmware_device_id_records: vec![
            FirmwareDeviceIdRecord {
                initial_descriptor: Descriptor {
                    descriptor_type: DescriptorType::Uuid,
                    descriptor_data: TEST_UUID.to_vec(),
                },
                .. Default::default()
            },
        ],
        ..Default::default()
    };


    // Setup the test environment
    let mut setup = setup(Options{
        pldm_fw_pkg: Some(pldm_fw_pkg.clone()),
        discovery_sm_actions: CustomDiscoverySm{},
        update_sm_actions: UpdateSmQueryValidDeviceIdentifiers {
            is_query_device_identifiers_response_valid: false,
        },
    });

    // Receive QueryDevicdeIdentifiers request
    let request: QueryDeviceIdentifiersRequest =
        receive_request(&setup.fd_sock, FwUpdateCmd::QueryDeviceIdentifiers as u8).unwrap();


    let initial_descriptor = encode_descriptor(&pldm_fw_pkg.firmware_device_id_records[0].initial_descriptor).unwrap();

    let response =  QueryDeviceIdentifiersResponse::new(
        request.hdr.instance_id(), 
        PldmBaseCompletionCode::Success as u8, 
        std::mem::size_of::<pldm_common::protocol::firmware_update::Descriptor>() as u32,
        1, 
        &initial_descriptor, 
        None, 
        ).unwrap();

    // Send the response
    send_response(&setup.fd_sock, &response);
    
    
    setup.daemon.stop();

}


#[test]
fn test_valid_device_identifier_not_matched() {
    let pldm_fw_pkg = FirmwareManifest {
        firmware_device_id_records: vec![
            FirmwareDeviceIdRecord {
                initial_descriptor: Descriptor {
                    descriptor_type: DescriptorType::Uuid,
                    descriptor_data: TEST_UUID.to_vec(),
                },
                .. Default::default()
            },
        ],
        ..Default::default()
    };


    // Setup the test environment
    let mut setup = setup(Options{
        pldm_fw_pkg: Some(pldm_fw_pkg.clone()),
        discovery_sm_actions: CustomDiscoverySm{},
        update_sm_actions: UpdateSmQueryValidDeviceIdentifiers {
            is_query_device_identifiers_response_valid: false,
        },
    });

    // Receive QueryDevicdeIdentifiers request
    let request: QueryDeviceIdentifiersRequest =
        receive_request(&setup.fd_sock, FwUpdateCmd::QueryDeviceIdentifiers as u8).unwrap();


    let response_id_record=             FirmwareDeviceIdRecord {
        initial_descriptor: Descriptor {
            descriptor_type: DescriptorType::Uuid,
            descriptor_data: TEST_UUID2.to_vec(),
        },
        .. Default::default()
    };
    let initial_descriptor = encode_descriptor(&response_id_record.initial_descriptor).unwrap();

    let response =  QueryDeviceIdentifiersResponse::new(
        request.hdr.instance_id(), 
        PldmBaseCompletionCode::Success as u8, 
        std::mem::size_of::<pldm_common::protocol::firmware_update::Descriptor>() as u32,
        1, 
        &initial_descriptor, 
        None, 
        ).unwrap();

    // Send the response
    send_response(&setup.fd_sock, &response);
    
    
    setup.daemon.stop();

}
