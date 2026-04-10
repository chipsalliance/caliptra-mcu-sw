// Licensed under the Apache-2.0 license

use libsyscall_caliptra::mcu_mbox::{MbxCmdStatus, McuMbox, MCU_MBOX0_DRIVER_NUM};
use romtime::println;

#[allow(dead_code)]
pub async fn test_mcu_mbox_usermode_loopback() {
    let mcu_mbox0: McuMbox = McuMbox::new(MCU_MBOX0_DRIVER_NUM);
    assert!(mcu_mbox0.exists(), "MCU mailbox 0 driver does not exist");
    println!("MCU MBOX usermode loopback: driver exists, starting loop");

    let mut request_buffer: [u8; 256] = [0; 256];
    let mut msg_count: u32 = 0;
    loop {
        let on_listening_cb: Option<fn()> = None;
        let recv_result = mcu_mbox0
            .receive_command(&mut request_buffer, on_listening_cb)
            .await;

        assert!(
            recv_result.is_ok(),
            "Failed to receive command: {:?}",
            recv_result.err()
        );
        let (cmd, payload_len) = recv_result.unwrap();
        msg_count += 1;
        println!(
            "MCU MBOX usermode loopback: msg #{}, cmd={:#X}, payload_len={}",
            msg_count,
            cmd,
            payload_len
        );
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
        println!(
            "MCU MBOX usermode loopback: msg #{} response sent, payload_len={}",
            msg_count,
            payload_len
        );
    }
}
