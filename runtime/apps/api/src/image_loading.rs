use libtock_platform::ErrorCode;
use libtock_platform::Syscalls;
use crate::mailbox::{GetImageLocationOffsetRequest, GetImageLoadAddressRequest, MailboxAPI, MailboxAPIIntf, MailboxRequest,MailboxResponse,
GetImageSizeRequest};
use libsyscall_caliptra::dma::{AXIAddr, DMASource, DMATransaction, DMA as DMASyscall};
use libsyscall_caliptra::flash::{SpiFlash as FlashSyscall,driver_num};

/// Trait defining the Image Loading module
pub trait ImageLoaderApiIntf {
    /// Loads the specified image to a storage mapped to the AXI bus memory map.
    ///
    /// # Parameters
    /// image_id: The unsigned integer identifier of the image.
    ///
    /// # Returns
    /// - `Ok()`: Image has been loaded and authorized succesfully.
    /// - `Err(ErrorCode)`: Indication of the failure to load or authorize the image.
    async fn load_and_authorize(&self, image_id: u32) -> Result<(), ErrorCode>;
}

/// Implementation of the ImageLoaderAPI trait
pub struct ImageLoaderAPI<S: Syscalls> {
    mailbox_api: MailboxAPI<S>,
}

const MAX_DMA_TRANSFER_SIZE: usize = 1024;

impl<S:Syscalls> ImageLoaderApiIntf for ImageLoaderAPI<S> {
    async fn load_and_authorize(&self, image_id: u32) -> Result<(), ErrorCode> {
        // Get image Offset
        let offset = self.get_image_offset(image_id).await?;

        // Get the image size
        let img_size = self.get_image_image_size(image_id).await?;

        // Get load address
        let load_address = self.get_image_load_address(image_id).await?;

        // Load image to the specified address
        self.load_image(load_address, offset as usize, img_size).await?;

        // Authorize the image

        Ok(())
    }
}

impl<S: Syscalls> ImageLoaderAPI<S> {
    fn new() -> Self {
        Self {
            mailbox_api: MailboxAPI::new(),
        }
    }
    
    async fn get_image_offset(&self, image_id: u32) -> Result<u32, ErrorCode> {
        let request = GetImageLocationOffsetRequest::new(image_id);
        let response = self.mailbox_api.execute_command(&MailboxRequest::GetImageLocationOffset(request)).await?;
        if let MailboxResponse::GetImageLocationOffset(response) = response {
            Ok(response.offset)
        } else {
            Err(ErrorCode::Fail)
        }
    }

    async fn get_image_load_address(&self, image_id: u32) -> Result<u64, ErrorCode> {
        let request = GetImageLoadAddressRequest::new(image_id);
        let response = self.mailbox_api.execute_command(&MailboxRequest::GetImageLoadAddress(request)).await?;
        if let MailboxResponse::GetImageLoadAddress(response) = response {
            Ok((response.load_address_high << 32 | response.load_address_low) as u64)
        } else {
            Err(ErrorCode::Fail)
        }
    }

    async fn get_image_image_size(&self, image_id: u32) -> Result<usize, ErrorCode> {
        let request = GetImageSizeRequest::new(image_id);
        let response = self.mailbox_api.execute_command(&MailboxRequest::GetImageSize(request)).await?;
        if let MailboxResponse::GetImageSize(response) = response {
            Ok(response.size as usize)
        } else {
            Err(ErrorCode::Fail)
        }
    }

    async fn load_image(&self, load_address: AXIAddr, offset: usize, img_size: usize) -> Result<(), ErrorCode> {
        let dma_syscall = DMASyscall::<S>::new();
        let flash_syscall = FlashSyscall::<S>::new(driver_num::IMAGE_PARTITION);
        let mut buffer = [0; MAX_DMA_TRANSFER_SIZE];

        // Read a chunk from flash and transfer it through DMA until all the image chunks are copied
        let mut remaining_size = img_size;
        let mut current_offset = offset;
        let mut current_address = load_address;
        while remaining_size > 0 {
            let transfer_size = if remaining_size > MAX_DMA_TRANSFER_SIZE { MAX_DMA_TRANSFER_SIZE } else { remaining_size };
            flash_syscall.read(current_offset, transfer_size, &mut buffer).await?;
            let transaction = DMATransaction{
                byte_count: transfer_size,
                source: DMASource::Buffer(&mut buffer[..transfer_size]),
                dest_addr: current_address,
            };
            remaining_size -= transfer_size;
            current_offset += transfer_size;
            current_address += transfer_size as u64;
            dma_syscall.xfer(&transaction).await?;
        }


        
        Ok(())
    }
}