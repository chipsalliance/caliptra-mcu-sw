// Licensed under the Apache-2.0 license

use libsyscall_caliptra::mcu_mbox::{MbxCmdStatus, McuMbox, MCU_MBOX0_DRIVER_NUM};

#[allow(dead_code)]
pub async fn test_mcu_mbox_usermode_loopback() {
    let mcu_mbox0: McuMbox = McuMbox::new(MCU_MBOX0_DRIVER_NUM);
    assert!(mcu_mbox0.exists(), "MCU mailbox 0 driver does not exist");

    let mut request_buffer: [u8; 256] = [0; 256];
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

        // Echo the received payload back as the response
        let response_data = &request_buffer[..payload_len];
        let send_result = mcu_mbox0.send_response(response_data).await;
        assert!(
            send_result.is_ok(),
            "Failed to send response: {:?}",
            send_result.err()
        );

        let finish_result = mcu_mbox0.finish_response(MbxCmdStatus::Complete);
        assert!(
            finish_result.is_ok(),
            "Failed to finish response: {:?}",
            finish_result.err()
        );
    }
}
