// Licensed under the Apache-2.0 license

use libsyscall_caliptra::mcu_mbox::{MbxCmdStatus, McuMbox, MCU_MBOX0_DRIVER_NUM};

/*
pub async fn test_doe_loopback() {
    let doe_spdm: Doe = Doe::new(driver_num::DOE_SPDM);
    loop {
        let mut msg_buffer: [u8; 1024] = [0; 1024];

        assert!(doe_spdm.exists());
        let max_msg_size = doe_spdm.max_message_size();
        assert!(max_msg_size.is_ok());
        assert!(max_msg_size.unwrap() > 0);

        let result = doe_spdm.receive_message(&mut msg_buffer).await;
        assert!(result.is_ok());
        let msg_len = result.unwrap();
        let msg_len = msg_len as usize;
        assert!(msg_len <= msg_buffer.len());

        let result = doe_spdm.send_message(&msg_buffer[..msg_len]).await;
        assert!(result.is_ok());
    }
}*/

pub async fn test_mcu_mbox_usermode_loopback() {
    let mcu_mbox0: McuMbox = McuMbox::new(MCU_MBOX0_DRIVER_NUM);

    assert!(mcu_mbox0.exists(), "MCU mailbox 0 driver does not exist");

    let mut request_buffer: [u8; 256] = [0; 256];

    romtime::println!("[xs debug] Listenting for incoming command on MCU mailbox 0...");
    loop {
        let recv_result = mcu_mbox0.receive_command(&mut request_buffer).await;

        assert!(
            recv_result.is_ok(),
            "Failed to receive command: {:?}",
            recv_result.err()
        );
        let (_cmd, payload_len) = recv_result.unwrap();
        assert!(
            payload_len <= request_buffer.len(),
            "Payload length exceeds buffer size"
        );

        // Prepare the response. Loop back
        let response_data = &request_buffer[..payload_len];
        let send_result = mcu_mbox0
            .send_response(response_data, MbxCmdStatus::Complete)
            .await;

        assert!(
            send_result.is_ok(),
            "Failed to send response: {:?}",
            send_result.err()
        );
    }
}
