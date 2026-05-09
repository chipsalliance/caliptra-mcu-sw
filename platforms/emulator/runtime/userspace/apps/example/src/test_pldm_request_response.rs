// Licensed under the Apache-2.0 license

#[cfg(feature = "test-pldm-request-response")]
pub mod test {
    use libsyscall_caliptra::mctp::{driver_num, Mctp};
    use pldm_common::codec::PldmCodec;
    use pldm_common::message::control::{
        GetTidRequest, GetTidResponse, SetTidRequest, SetTidResponse,
    };
    use pldm_common::protocol::base::PldmMsgType;

    const MAX_MCTP_PACKET_SIZE: usize = 512;
    const COMPLETION_CODE_SUCCESSFUL: u8 = 0x00;
    const MCTP_PLDM_COMMON_HEADER: u8 = 0x01;

    #[derive(Default, Clone, Copy)]
    struct PldmRequestResponsePair {
        // Expected PLDM Message to be received
        request: PldmMessage,
        // Response to send back after receiving request
        response: PldmMessage,
    }

    #[derive(Clone, Copy)]
    struct PldmMessage {
        buffer: [u8; MAX_MCTP_PACKET_SIZE],
        length: usize,
    }

    impl Default for PldmMessage {
        fn default() -> Self {
            PldmMessage {
                buffer: [0; MAX_MCTP_PACKET_SIZE],
                length: 0,
            }
        }
    }

    struct TestMessages<const MAX_NUM_MESSAGES: usize> {
        pub messages: [PldmRequestResponsePair; MAX_NUM_MESSAGES],
        pub size: usize,
    }

    impl<const MAX_NUM_MESSAGES: usize> Default for TestMessages<MAX_NUM_MESSAGES> {
        fn default() -> Self {
            TestMessages {
                messages: [PldmRequestResponsePair::default(); MAX_NUM_MESSAGES],
                size: 0,
            }
        }
    }

    impl<const MAX_NUM_MESSAGES: usize> TestMessages<MAX_NUM_MESSAGES> {
        fn add<Req: PldmCodec, Resp: PldmCodec>(&mut self, request: Req, response: Resp) {
            let index = self.size;

            self.messages[index].request.buffer[0] = MCTP_PLDM_COMMON_HEADER;
            let sz = request
                .encode(&mut self.messages[index].request.buffer[1..])
                .unwrap();
            self.messages[index].request.length = sz + 1;

            self.messages[index].response.buffer[0] = MCTP_PLDM_COMMON_HEADER;
            let sz = response
                .encode(&mut self.messages[index].response.buffer[1..])
                .unwrap();
            self.messages[index].response.length = sz + 1;

            self.size += 1;
        }
    }

    pub async fn test_pldm_request_response() {
        let mut test_messages = TestMessages::<2>::default();

        test_messages.add(
            GetTidRequest::new(1u8, PldmMsgType::Request),
            GetTidResponse::new(1u8, 1u8, COMPLETION_CODE_SUCCESSFUL),
        );

        test_messages.add(
            SetTidRequest::new(2u8, PldmMsgType::Request, 2u8),
            SetTidResponse::new(2u8, COMPLETION_CODE_SUCCESSFUL),
        );

        let mctp_pldm: Mctp = Mctp::new(driver_num::MCTP_PLDM);
        let mut msg_buffer: [u8; MAX_MCTP_PACKET_SIZE] = [0; MAX_MCTP_PACKET_SIZE];

        assert!(mctp_pldm.exists());
        let max_msg_size = mctp_pldm.max_message_size();
        assert!(max_msg_size.is_ok());
        assert!(max_msg_size.unwrap() > 0);

        for i in 0..test_messages.size {
            let test_message = &test_messages.messages[i];
            let (length, info) = mctp_pldm.receive_request(&mut msg_buffer).await.unwrap();

            assert!(test_message.request.length == length as usize);
            assert!(
                test_message.request.buffer[0..length as usize] == msg_buffer[0..length as usize]
            );

            mctp_pldm
                .send_response(
                    &test_message.response.buffer[..test_message.response.length],
                    info,
                )
                .await
                .unwrap();
        }
    }
}
