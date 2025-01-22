// Licensed under the Apache-2.0 license

use crate::mailbox::{
    AuthorizeAndStashRequest, GetImageLoadAddressRequest, GetImageLocationOffsetRequest,
    GetImageSizeRequest, Mailbox, MailboxRequest, MailboxRequestType, MailboxResponse,
    AUTHORIZED_IMAGE,
};
use libsyscall_caliptra::dma::{AXIAddr, DMASource, DMATransaction, DMA as DMASyscall};
use libsyscall_caliptra::flash::{driver_num, SpiFlash as FlashSyscall};
use libtock_platform::ErrorCode;
use libtock_platform::Syscalls;

pub struct ImageLoaderAPI<S: Syscalls> {
    mailbox_api: Mailbox<S>,
}

/// This is the size of the buffer used for DMA transfers.
const MAX_TRANSFER_SIZE: usize = 1024;

impl<S: Syscalls> Default for ImageLoaderAPI<S> {
    fn default() -> Self {
        Self::new()
    }
}

impl<S: Syscalls> ImageLoaderAPI<S> {
    /// Creates a new instance of the ImageLoaderAPI.
    pub fn new() -> Self {
        Self {
            mailbox_api: Mailbox::new(),
        }
    }

    /// Loads the specified image to a storage mapped to the AXI bus memory map.
    ///
    /// # Parameters
    /// image_id: The unsigned integer identifier of the image.
    ///
    /// # Returns
    /// - `Ok()`: Image has been loaded and authorized succesfully.
    /// - `Err(ErrorCode)`: Indication of the failure to load or authorize the image.
    pub async fn load_and_authorize(&self, image_id: u32) -> Result<(), ErrorCode> {
        let offset = self.get_image_offset(image_id).await?;
        let img_size = self.get_image_size(image_id).await?;
        let load_address = self.get_image_load_address(image_id).await?;
        self.load_image(load_address, offset as usize, img_size)
            .await?;
        self.authorize_image(image_id).await?;
        Ok(())
    }

    /// Retrieves the offset of the image in memory.
    async fn get_image_offset(&self, image_id: u32) -> Result<u32, ErrorCode> {
        let mut request = GetImageLocationOffsetRequest {
            fw_id: image_id.to_be_bytes(),
            ..Default::default()
        };
        request.populate_checksum();
        let response = self
            .mailbox_api
            .execute_command(&MailboxRequest::GetImageLocationOffset(request))
            .await?;
        if let MailboxResponse::GetImageLocationOffset(res) = response {
            Ok(res.offset)
        } else {
            Err(ErrorCode::Fail)
        }
    }

    /// Fetches the load address of the image.
    async fn get_image_load_address(&self, image_id: u32) -> Result<u64, ErrorCode> {
        let mut request = GetImageLoadAddressRequest {
            fw_id: image_id.to_be_bytes(),
            ..Default::default()
        };
        request.populate_checksum();
        let response = self
            .mailbox_api
            .execute_command(&MailboxRequest::GetImageLoadAddress(request))
            .await?;
        if let MailboxResponse::GetImageLoadAddress(res) = response {
            Ok((res.load_address_high as u64) << 32 | res.load_address_low as u64)
        } else {
            Err(ErrorCode::Fail)
        }
    }

    /// Retrieves the size of the image in bytes.
    async fn get_image_size(&self, image_id: u32) -> Result<usize, ErrorCode> {
        let mut request = GetImageSizeRequest {
            fw_id: image_id.to_be_bytes(),
            ..Default::default()
        };
        request.populate_checksum();
        let response = self
            .mailbox_api
            .execute_command(&MailboxRequest::GetImageSize(request))
            .await?;
        if let MailboxResponse::GetImageSize(res) = response {
            Ok(res.size as usize)
        } else {
            Err(ErrorCode::Fail)
        }
    }

    /// Authorizes an image based on its ID.
    async fn authorize_image(&self, image_id: u32) -> Result<(), ErrorCode> {
        let mut request = AuthorizeAndStashRequest {
            fw_id: image_id.to_be_bytes(),
            ..Default::default()
        };
        request.populate_checksum();
        let response = self
            .mailbox_api
            .execute_command(&MailboxRequest::AuthorizeAndStash(request))
            .await?;
        if let MailboxResponse::AuthorizeAndStash(res) = response {
            if res.auth_req_result == AUTHORIZED_IMAGE {
                return Ok(());
            }
        }
        Err(ErrorCode::Fail)
    }

    /// Loads an image from flash into the specified address using DMA transfers.
    async fn load_image(
        &self,
        load_address: AXIAddr,
        offset: usize,
        img_size: usize,
    ) -> Result<(), ErrorCode> {
        let dma_syscall = DMASyscall::<S>::new();
        let flash_syscall = FlashSyscall::<S>::new(driver_num::ACTIVE_IMAGE_PARTITION);
        let mut remaining_size = img_size;
        let mut current_offset = offset;
        let mut current_address = load_address;

        while remaining_size > 0 {
            let transfer_size = remaining_size.min(MAX_TRANSFER_SIZE);
            let mut buffer = [0; MAX_TRANSFER_SIZE];
            flash_syscall
                .read(current_offset, transfer_size, &mut buffer)
                .await?;
            let transaction = DMATransaction {
                byte_count: transfer_size,
                source: DMASource::Buffer(&buffer[..transfer_size]),
                dest_addr: current_address,
            };
            dma_syscall.xfer(&transaction).await?;
            remaining_size -= transfer_size;
            current_offset += transfer_size;
            current_address += transfer_size as u64;
        }

        Ok(())
    }
}
