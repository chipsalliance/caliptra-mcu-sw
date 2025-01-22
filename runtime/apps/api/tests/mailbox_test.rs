// Licensed under the Apache-2.0 license

#[cfg(test)]
mod tests {
    use libapi_caliptra::mailbox::*;
    use libtock_unittest::fake::{wait_for_future_ready, FakeMailboxDriver, Kernel, Syscalls};
    use std::rc::Rc;
    use zerocopy::{IntoBytes, TryFromBytes};

    #[test]
    fn test_verify_mailbox_request_checksum() {
        // Create the fake kernel and add the fake driver
        let fake_kernel = Kernel::new();
        let fake_driver = FakeMailboxDriver::new();

        // Add the fake driver to the kernel
        let fake_driver_rc = Rc::new(fake_driver);
        fake_kernel.add_driver(&fake_driver_rc);

        // Create the Mailbox instance
        let api: Mailbox<Syscalls> = Mailbox::new();

        // Prepare the mailbox request
        let mut request = GetImageLoadAddressRequest {
            fw_id: [0; 4],
            ..Default::default()
        };
        request.populate_checksum();
        let request = MailboxRequest::GetImageLoadAddress(request);

        // Generate a fake response
        let fake_response = GetImageLoadAddressResponse {
            load_address_high: 0x1122,
            load_address_low: 0x3344,
            ..Default::default()
        };

        // Set up the fake response
        fake_driver_rc.add_ready_response(
            GetImageLoadAddressRequest::COMMAND_ID,
            fake_response.as_bytes(),
        );

        // Create the future for the async operation
        let future = Box::pin(api.execute_command(&request));

        let _ = wait_for_future_ready(future);

        // check command id received by driver
        assert_eq!(
            fake_driver_rc.get_last_command().unwrap(),
            GetImageLoadAddressRequest::COMMAND_ID
        );

        let driver_request = fake_driver_rc.get_last_ro_input().unwrap();
        assert!(!driver_request.is_empty());
        GetImageLoadAddressRequest::try_read_from_bytes(driver_request.as_slice())
            .expect("Invalid request")
            .verify_checksum()
            .expect("Invalid checksum");
    }

    // Test case for checking response checksum
    #[test]
    fn test_verify_mailbox_response_checksum() {
        // Create the fake kernel and add the fake driver
        let fake_kernel = Kernel::new();
        let fake_driver = FakeMailboxDriver::new();

        // Add the fake driver to the kernel
        let fake_driver_rc = Rc::new(fake_driver);
        fake_kernel.add_driver(&fake_driver_rc);

        // Create the Mailbox instance
        let api: Mailbox<Syscalls> = Mailbox::new();

        // Prepare the mailbox request
        let mut request = GetImageLoadAddressRequest {
            fw_id: [0; 4],
            ..Default::default()
        };
        request.populate_checksum();
        let request = MailboxRequest::GetImageLoadAddress(request);

        // Generate a fake response
        let mut fake_response = GetImageLoadAddressResponse {
            load_address_high: 0x1122,
            load_address_low: 0x3344,
            ..Default::default()
        };
        fake_response.populate_checksum();

        // Set up the fake response
        fake_driver_rc.add_ready_response(
            GetImageLoadAddressRequest::COMMAND_ID,
            fake_response.as_bytes(),
        );

        // Create the future for the async operation
        let future = Box::pin(api.execute_command(&request));

        let result = wait_for_future_ready(future).expect("Failed to execute command");

        if let MailboxResponse::GetImageLoadAddress(mut response) = result {
            response.verify_checksum().expect("Invalid checksum");
        } else {
            panic!("Invalid response type");
        }
    }

    // Test case for non-zero fips status
    #[test]
    fn test_non_zero_fips_status() {
        // Create the fake kernel and add the fake driver
        let fake_kernel = Kernel::new();
        let fake_driver = FakeMailboxDriver::new();

        // Add the fake driver to the kernel
        let fake_driver_rc = Rc::new(fake_driver);
        fake_kernel.add_driver(&fake_driver_rc);

        // Create the Mailbox instance
        let api: Mailbox<Syscalls> = Mailbox::new();

        // Prepare the mailbox request
        let mut request = GetImageLoadAddressRequest {
            fw_id: [0; 4],
            ..Default::default()
        };
        request.populate_checksum();

        // Generate a fake response
        let fake_response = GetImageLoadAddressResponse {
            load_address_high: 0x1122,
            load_address_low: 0x3344,
            hdr: MailboxRespHeader {
                fips_status: 1,
                ..Default::default()
            },
        };

        // Set up the fake response
        fake_driver_rc.add_ready_response(
            GetImageLoadAddressRequest::COMMAND_ID,
            fake_response.as_bytes(),
        );

        let request = MailboxRequest::GetImageLoadAddress(request);

        // Create the future for the async operation
        let future = Box::pin(api.execute_command(&request));

        let result = wait_for_future_ready(future);
        assert!(result.is_err());
    }
}
