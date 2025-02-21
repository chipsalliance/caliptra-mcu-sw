use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::mctp_transport::MctpPldmSocket;
use pldm_common::message::control::*;
use pldm_common::codec::PldmCodec;
use pldm_common::protocol::base::PldmMsgType;
use pldm_ua::transport::{PldmSocket, FilterType};

pub struct PldmLoopbackTest{
    test_messages : Vec<PldmExpectedMessagePair>,
    socket: MctpPldmSocket,
    running: Arc<AtomicBool>,

}

pub struct PldmExpectedMessagePair {
    // PLDM Message Sent
    pub request: Vec<u8>,
    // Expected PLDM Message Response to receive
    pub response: Vec<u8>
}


impl PldmLoopbackTest {
    fn new(socket : MctpPldmSocket, running: Arc<AtomicBool>) -> Self {
        let mut test_messages:Vec<PldmExpectedMessagePair> = Vec::new();


        let req= GetTidRequest::new(1u8, PldmMsgType::Request);
        let mut buffer= [0u8; 1024];
        let sz = req.encode(&mut buffer).unwrap();
        println!("Emulator: PLDM Raw packet: {:02x?}", &buffer[..sz]);
        

        let mybuf = [1u8,2u8,3u8];
        println!("Emulator: mybuf: {:02x?}", &mybuf[..sz]);

        test_messages.push(PldmExpectedMessagePair{
            request: vec![0x81,00,02],
            response: vec![0x81,00,02]
        });
        test_messages.push(PldmExpectedMessagePair{
            request: vec![0x81,00,03],
            response: vec![0x81,00,03]
        });

/*
        Self::add_test_message(
            &mut test_messages,
            GetTidRequest::new(1u8, PldmMsgType::Request),
            GetTidResponse::new(1u8, 1u8, 0u8)
        );

        Self::add_test_message(
            &mut test_messages,
            GetTidRequest::new(1u8, PldmMsgType::Request),
            GetTidResponse::new(1u8, 1u8, 0u8)
        );

        Self::add_test_message(
            &mut test_messages,
            SetTidRequest::new(2u8, PldmMsgType::Request, 2u8),
            SetTidResponse::new(2u8, 0u8)
        );        
 */
        Self { test_messages, socket, running }

    }


    fn add_test_message<Req: PldmCodec, Resp: PldmCodec>(test_messages: &mut Vec<PldmExpectedMessagePair>, request: Req, response: Resp) {
        let mut buffer= [0u8; 1024];
        let sz = request.encode(&mut buffer).unwrap();
        let request = buffer[0..sz].to_vec();
        let sz = response.encode(&mut buffer).unwrap();
        let response = buffer[0..sz].to_vec();
        test_messages.push(PldmExpectedMessagePair{request, response});
    }

    pub fn test_send_receive(&mut self) -> Result<(), ()> {
        self.socket.connect()?;
        
        for message_pair in &self.test_messages {

            // hexdump the request
            println!("Emulator: Sending: {:02x?}", message_pair.request);

            self.socket.send(&message_pair.request)?;
            let rx_pkt = self.socket.receive(
                None,
                FilterType::Response)?;

            println!("Emulator: Received: {:02x?}", &rx_pkt.payload.data[..rx_pkt.payload.len]);

            assert_eq!(rx_pkt.payload.data[..rx_pkt.payload.len], message_pair.response);
            
        }
        Ok(())
    }

    pub fn run(socket : MctpPldmSocket, running: Arc<AtomicBool>) {
        std::thread::spawn(move || {
            print!(
                "Emulator: Running PLDM Loopback Test: ",
            );
            let mut test = PldmLoopbackTest::new(socket, running);
            if test.test_send_receive().is_err() {
                println!("Failed");
            } else {
                println!("Passed");
            }
            test.running.store(false, Ordering::Relaxed);
        });

    }
}