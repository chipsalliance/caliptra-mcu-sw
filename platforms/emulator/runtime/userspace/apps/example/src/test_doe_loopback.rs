// Licensed under the Apache-2.0 license

use libsyscall_caliptra::doe::{driver_num, Doe};

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
}
