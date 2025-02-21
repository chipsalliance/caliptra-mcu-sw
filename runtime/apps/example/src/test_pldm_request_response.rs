#[cfg(feature = "test-marco")]
pub mod test {
    use libtock_platform::Syscalls;
    use pldm_common::codec::PldmCodec;
    use pldm_common::message::control::{GetTidRequest, GetTidResponse, SetTidRequest, SetTidResponse};
    use pldm_common::protocol::base::PldmMsgType;
    use libsyscall_caliptra::mctp::{driver_num, Mctp};
    use libtock_console::ConsoleWriter;
    use core::fmt::Write;

    const MAX_MCTP_PACKET_SIZE: usize = 512;
    const COMPLETION_CODE_SUCCESSFUL : u8 = 0x00;


    #[derive(Default, Clone, Copy)]
    // Expected PLDM Message to be received and response to send back
    struct PldmRequestResponsePair {
        // Expected PLDM Message to be received
        request: PldmMessage,
        // Response to send back after receiving request
        response: PldmMessage,
    }

    #[derive(Clone, Copy)]
    struct PldmMessage {
        buffer: [u8; MAX_MCTP_PACKET_SIZE],
        length: usize
    }

    impl Default for PldmMessage {
        fn default() -> Self {
            PldmMessage {
                buffer: [0; MAX_MCTP_PACKET_SIZE],
                length: 0
            }
        }
    }


    fn add_test_message<Req: PldmCodec, Resp: PldmCodec>(test_message: &mut PldmRequestResponsePair, request: Req, response: Resp) {
        let sz = request.encode(&mut test_message.request.buffer).unwrap();
        test_message.request.length = sz;

        let sz = response.encode(&mut test_message.request.buffer).unwrap();
        test_message.response.length = sz;

    }

    fn debug<S: Syscalls>(console_writer: &mut Option<&mut ConsoleWriter<S>>, message: &str) {
        if let Some(console) = console_writer {
            writeln!(console, "{}", message).unwrap();
        }
    }

    pub async fn test_marco<S: Syscalls>(console_writer: &mut Option<&mut ConsoleWriter<S>>) {
        debug(console_writer, "Device: test_marco");

        let mut test_messages = [PldmRequestResponsePair::default(); 2];

        add_test_message(&mut test_messages[0], 
            GetTidRequest::new(1u8, PldmMsgType::Request),
            GetTidResponse::new(1u8, 1u8, COMPLETION_CODE_SUCCESSFUL)
        );

        add_test_message(&mut test_messages[0], 
            SetTidRequest::new(2u8, PldmMsgType::Request, 2u8),
            SetTidResponse::new(2u8, COMPLETION_CODE_SUCCESSFUL)
        );

        let mctp_pldm = Mctp::<S>::new(driver_num::MCTP_PLDM);
        let mut msg_buffer: [u8; 1024] = [0; 1024];

        assert!(mctp_pldm.exists());
        let max_msg_size = mctp_pldm.max_message_size();
        assert!(max_msg_size.is_ok());
        assert!(max_msg_size.unwrap() > 0);

        for test_message in test_messages.iter() {
            debug(console_writer, "Device: Waiting for request");
            let (length, info) = mctp_pldm.receive_request(&mut msg_buffer).await.unwrap();
            
            if let Some(console_writer) = console_writer {
                writeln!(console_writer, "Device: Received request: {:02x?}", &msg_buffer[1..length as usize]).unwrap();
                writeln!(console_writer, "Device: Expected request: {:02x?}", &test_message.request.buffer[0..(length-1) as usize]).unwrap();
            }
            
            

            // Note: Compare only the 2nd to the last byte, since first byte is the MCTP common header
            assert!(test_message.request.length == (length - 1) as usize);
            assert!(test_message.request.buffer[0.. (length-1) as usize] == msg_buffer[1..length as usize]);
            
            debug(console_writer, "Device: Sending response");
            mctp_pldm.send_response(&msg_buffer[..length as usize], info).await.unwrap();
            debug(console_writer, "Device: Response sent");

        }



    }
}