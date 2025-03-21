// Licensed under the Apache-2.0 license

/// This module tests the PLDM request/response interaction between the emulator and the device.
/// The emulator sends out different PLDM requests and expects a corresponding response for those requests.
use std::process::exit;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crate::mctp_transport::MctpPldmSocket;
use pldm_common::codec::PldmCodec;
use pldm_common::message::control::*;
use pldm_common::message::firmware_update::get_fw_params::{
    FirmwareParameters, GetFirmwareParametersRequest, GetFirmwareParametersResponse,
};
use pldm_common::message::firmware_update::query_devid::{
    QueryDeviceIdentifiersRequest, QueryDeviceIdentifiersResponse,
};
use pldm_common::message::firmware_update::request_fw_data::{RequestFirmwareDataResponse, RequestFirmwareDataResponseFixed};
use pldm_common::protocol::base::*;
use pldm_common::protocol::firmware_update::*;
use pldm_ua::transport::PldmSocket;

pub struct PldmRequestResponseTest2 {
    socket: MctpPldmSocket,
    running: Arc<AtomicBool>,
}


impl PldmRequestResponseTest2 {
    fn new(socket: MctpPldmSocket, running: Arc<AtomicBool>) -> Self {
        Self {
            socket,
            running,
        }
    }

    fn send_message<M: PldmCodec>(&self, 
        message: &M,

    ) {
        let mut buffer = [0u8; 512];
        let sz = message.encode(&mut buffer).unwrap();
        self.socket.send(&buffer[..sz]).unwrap();

    }

    fn receive_message(&self) -> Result<(),()>
    {
        let rx_pkt = self.socket.receive(None).unwrap();
        let cmd_code = self.decode(&rx_pkt.payload.data[..rx_pkt.payload.len])?;
        std::thread::sleep(Duration::from_secs(2));
        println!("Emulator: Received command_code {}", cmd_code);
        Ok(())
    }

    pub fn decode(&self, message: &[u8]) -> Result<u8,()>
    {
        let header:PldmMsgHeader<[u8;3]> = PldmMsgHeader::decode(message).map_err(|_| ())?;
                
        Ok(header.cmd_code())
    }

    pub fn test_send_receive(&mut self) -> Result<(), ()> {
        self.socket.connect().map_err(|_| ())?;

        // Send a request to the device
        let request = GetTidRequest::new(0, PldmMsgType::Request);
        self.send_message(&request);

        std::thread::sleep(Duration::from_secs(2));

        // Receive message
        self.receive_message();

        std::thread::sleep(Duration::from_secs(2));

        // Receive message
        self.receive_message();
        std::thread::sleep(Duration::from_secs(2));

        // Send a response, check device logs if initiator receives it
        let response = RequestFirmwareDataResponse::new(
            request.hdr.instance_id(),
            PldmBaseCompletionCode::InvalidLength as u8,
            &[],
        );

        self.send_message(&response);
        std::thread::sleep(Duration::from_secs(2));

        // Send another request, check device logs if responder receives it
        self.send_message(&request);

        std::thread::sleep(Duration::from_secs(2));



        
        Ok(())
    }

    pub fn run(socket: MctpPldmSocket, running: Arc<AtomicBool>) {
        std::thread::spawn(move || {
            print!("Emulator: Running PLDM Loopback Test: ",);
            let mut test = PldmRequestResponseTest2::new(socket, running);
            if test.test_send_receive().is_err() {
                println!("Failed");
                exit(-1);
            } else {
                println!("Passed");
            }
            test.running.store(false, Ordering::Relaxed);
        });
    }

}
