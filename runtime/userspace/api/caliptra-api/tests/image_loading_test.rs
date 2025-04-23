// Licensed under the Apache-2.0 license

#[cfg(test)]
mod tests {
    use libapi_caliptra::image_loading::ImageLoaderAPI;
    use libapi_caliptra::mailbox::*;
    use libtock_unittest::fake::{
        wait_for_future_ready, FakeDMADriver, FakeFlashDriver, FakeMailboxDriver, Kernel,
    };
    use std::rc::Rc;

    fn add_mailbox_response<Response: MailboxResponseType>(
        mailbox_driver: &Rc<FakeMailboxDriver>,
        command_id: u32,
        response: &mut Response,
    ) {
        response.populate_checksum();
        mailbox_driver.add_ready_response(command_id, response.as_bytes());
    }

    #[test]
    fn test_load_image1_authorized() {
        // Create a fake mailbox driver
        let mailbox_driver = FakeMailboxDriver::new();
        let dma_driver = FakeDMADriver::new();
        let flash_driver = FakeFlashDriver::new();
        let fake_kernel = Kernel::new();

        let fake_mailbox_driver_rc = Rc::new(mailbox_driver);
        fake_kernel.add_driver(&fake_mailbox_driver_rc);

        let fake_dma_driver_rc = Rc::new(dma_driver);
        fake_kernel.add_driver(&fake_dma_driver_rc);

        let fake_flash_driver_rc = Rc::new(flash_driver);
        fake_kernel.add_driver(&fake_flash_driver_rc);

        // Firmware1 with length of 256 and contains 0x55
        let firmware1 = vec![0x55; 256];

        // Firmware2 with length of 1024 and contains 0xAA
        let firmware2 = vec![0xAA; 1024];

        // Prepare flash content, firmware1 at offset 0x0000A and firmware2 at offset 0x0200
        let mut flash_content = vec![0xFF; 2048];
        flash_content.splice(
            0x0000A..0x0000A + firmware1.len(),
            firmware1.iter().cloned(),
        );
        flash_content.splice(0x0200..0x0200 + firmware2.len(), firmware2.iter().cloned());

        // Add flash content to the flash driver
        fake_flash_driver_rc.set_flash_content(flash_content);

        // Set the address space size for DMA
        fake_dma_driver_rc.set_memory_size(2048);

        // Add responses to the mailbox driver
        add_mailbox_response(
            &fake_mailbox_driver_rc,
            GetImageLocationOffsetRequest::COMMAND_ID,
            &mut GetImageLocationOffsetResponse {
                offset: 0x0000A,
                ..Default::default()
            },
        );

        add_mailbox_response(
            &fake_mailbox_driver_rc,
            GetImageSizeRequest::COMMAND_ID,
            &mut GetImageSizeResponse {
                size: 256,
                ..Default::default()
            },
        );

        add_mailbox_response(
            &fake_mailbox_driver_rc,
            GetImageLoadAddressRequest::COMMAND_ID,
            &mut GetImageLoadAddressResponse {
                load_address_high: 0x0000,
                load_address_low: 0x00000,
                ..Default::default()
            },
        );

        add_mailbox_response(
            &fake_mailbox_driver_rc,
            AuthorizeAndStashRequest::COMMAND_ID,
            &mut AuthorizeAndStashResponse {
                auth_req_result: AUTHORIZED_IMAGE,
                ..Default::default()
            },
        );

        let image_loader: ImageLoaderAPI = ImageLoaderAPI::new();

        // Load and authorize the image
        let image_id = 1;
        let future = Box::pin(image_loader.load_and_authorize(image_id));
        let result = wait_for_future_ready(future);
        assert_eq!(result, Ok(()));

        // Check if firmware is loaded into the correct memory location
        let dma_memory = fake_dma_driver_rc.read_memory(0, 1024);

        // Check memory 0..255 are 0x55
        assert_eq!(&dma_memory[0..256], &firmware1[..]);

        // Check memory 256..1023 are 0x0
        assert_eq!(&dma_memory[256..1024], &[0x0; 768][..]);
    }

    #[test]
    fn test_load_image1_not_authorized() {
        // Create a fake mailbox driver
        let mailbox_driver = FakeMailboxDriver::new();
        let dma_driver = FakeDMADriver::new();
        let flash_driver = FakeFlashDriver::new();
        let fake_kernel = Kernel::new();

        let fake_mailbox_driver_rc = Rc::new(mailbox_driver);
        fake_kernel.add_driver(&fake_mailbox_driver_rc);

        let fake_dma_driver_rc = Rc::new(dma_driver);
        fake_kernel.add_driver(&fake_dma_driver_rc);

        let fake_flash_driver_rc = Rc::new(flash_driver);
        fake_kernel.add_driver(&fake_flash_driver_rc);

        // Firmware1 with length of 256 and contains 0x55
        let firmware1 = vec![0x55; 256];

        // Firmware2 with length of 1024 and contains 0xAA
        let firmware2 = vec![0xAA; 1024];

        // Prepare flash content, firmware1 at offset 0x0000A and firmware2 at offset 0x0200
        let mut flash_content = vec![0xFF; 2048];
        flash_content.splice(
            0x0000A..0x0000A + firmware1.len(),
            firmware1.iter().cloned(),
        );
        flash_content.splice(0x0200..0x0200 + firmware2.len(), firmware2.iter().cloned());

        // Add flash content to the flash driver
        fake_flash_driver_rc.set_flash_content(flash_content);

        fake_dma_driver_rc.set_memory_size(2048);

        // Add responses to the mailbox driver
        add_mailbox_response(
            &fake_mailbox_driver_rc,
            GetImageLocationOffsetRequest::COMMAND_ID,
            &mut GetImageLocationOffsetResponse {
                offset: 0x0000A,
                ..Default::default()
            },
        );

        add_mailbox_response(
            &fake_mailbox_driver_rc,
            GetImageSizeRequest::COMMAND_ID,
            &mut GetImageSizeResponse {
                size: 256,
                ..Default::default()
            },
        );

        add_mailbox_response(
            &fake_mailbox_driver_rc,
            GetImageLoadAddressRequest::COMMAND_ID,
            &mut GetImageLoadAddressResponse {
                load_address_high: 0x0000,
                load_address_low: 0x00000,
                ..Default::default()
            },
        );

        add_mailbox_response(
            &fake_mailbox_driver_rc,
            AuthorizeAndStashRequest::COMMAND_ID,
            &mut AuthorizeAndStashResponse {
                auth_req_result: IMAGE_NOT_AUTHORIZED,
                ..Default::default()
            },
        );

        let image_loader: ImageLoaderAPI = ImageLoaderAPI::new();

        // Load and authorize the image
        let image_id = 1;
        let future = Box::pin(image_loader.load_and_authorize(image_id));
        let result = wait_for_future_ready(future);
        assert!(result.is_err());
    }

    #[test]
    fn test_load_image1_image2_authorized() {
        // Create a fake mailbox driver
        let mailbox_driver = FakeMailboxDriver::new();
        let dma_driver = FakeDMADriver::new();
        let flash_driver = FakeFlashDriver::new();
        let fake_kernel = Kernel::new();

        let fake_mailbox_driver_rc = Rc::new(mailbox_driver);
        fake_kernel.add_driver(&fake_mailbox_driver_rc);

        let fake_dma_driver_rc = Rc::new(dma_driver);
        fake_kernel.add_driver(&fake_dma_driver_rc);

        let fake_flash_driver_rc = Rc::new(flash_driver);
        fake_kernel.add_driver(&fake_flash_driver_rc);

        // Firmware1 with length of 256 and contains 0x55
        let firmware1 = vec![0x55; 256];

        // Firmware2 with length of 1024 and contains 0xAA
        let firmware2 = vec![0xAA; 1024];

        // Prepare flash content, firmware1 at offset 0x0000A and firmware2 at offset 0x0200
        let mut flash_content = vec![0xFF; 2048];
        flash_content.splice(
            0x0000A..0x0000A + firmware1.len(),
            firmware1.iter().cloned(),
        );
        flash_content.splice(0x0200..0x0200 + firmware2.len(), firmware2.iter().cloned());

        // Add flash content to the flash driver
        fake_flash_driver_rc.set_flash_content(flash_content);

        fake_dma_driver_rc.set_memory_size(2048);

        // Add responses to the mailbox driver
        add_mailbox_response(
            &fake_mailbox_driver_rc,
            GetImageLocationOffsetRequest::COMMAND_ID,
            &mut GetImageLocationOffsetResponse {
                offset: 0x0000A,
                ..Default::default()
            },
        );

        add_mailbox_response(
            &fake_mailbox_driver_rc,
            GetImageSizeRequest::COMMAND_ID,
            &mut GetImageSizeResponse {
                size: 256,
                ..Default::default()
            },
        );

        add_mailbox_response(
            &fake_mailbox_driver_rc,
            GetImageLoadAddressRequest::COMMAND_ID,
            &mut GetImageLoadAddressResponse {
                load_address_high: 0x0000,
                load_address_low: 0x00000,
                ..Default::default()
            },
        );

        add_mailbox_response(
            &fake_mailbox_driver_rc,
            AuthorizeAndStashRequest::COMMAND_ID,
            &mut AuthorizeAndStashResponse {
                auth_req_result: AUTHORIZED_IMAGE,
                ..Default::default()
            },
        );

        // Prepare responses for firmware2
        add_mailbox_response(
            &fake_mailbox_driver_rc,
            GetImageLocationOffsetRequest::COMMAND_ID,
            &mut GetImageLocationOffsetResponse {
                offset: 0x0200,
                ..Default::default()
            },
        );

        add_mailbox_response(
            &fake_mailbox_driver_rc,
            GetImageSizeRequest::COMMAND_ID,
            &mut GetImageSizeResponse {
                size: 1024,
                ..Default::default()
            },
        );

        add_mailbox_response(
            &fake_mailbox_driver_rc,
            GetImageLoadAddressRequest::COMMAND_ID,
            &mut GetImageLoadAddressResponse {
                load_address_high: 0x0000,
                load_address_low: 0x00200,
                ..Default::default()
            },
        );

        add_mailbox_response(
            &fake_mailbox_driver_rc,
            AuthorizeAndStashRequest::COMMAND_ID,
            &mut AuthorizeAndStashResponse {
                auth_req_result: AUTHORIZED_IMAGE,
                ..Default::default()
            },
        );

        let image_loader: ImageLoaderAPI = ImageLoaderAPI::new();

        // Load and authorize the image 1
        let image_id = 1;
        let future = Box::pin(image_loader.load_and_authorize(image_id));
        let result = wait_for_future_ready(future);
        assert!(result.is_ok());

        // Load and authorize the image 2
        let image_id = 2;
        let future = Box::pin(image_loader.load_and_authorize(image_id));
        let result = wait_for_future_ready(future);
        assert!(result.is_ok());

        // Check if firmware is loaded into the correct memory location
        let dma_memory = fake_dma_driver_rc.read_memory(0, 2048);

        // Check memory 0..255 are 0x55
        assert_eq!(&dma_memory[0..256], &firmware1[..]);

        // Check memory 0x200..0x5FF are 0xAA
        assert_eq!(&dma_memory[0x200..0x600], &firmware2[..]);
    }
}
