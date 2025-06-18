// Licensed under the Apache-2.0 license

extern crate alloc;
mod flash_client;
mod pldm_client;
mod pldm_context;
mod pldm_fdops;

use crate::flash_image::FlashHeader;
use alloc::boxed::Box;
use async_trait::async_trait;
use caliptra_api::mailbox::{
    AuthorizeAndStashReq, AuthorizeAndStashResp, GetImageInfoReq, GetImageInfoResp,
    ImageHashSource, MailboxReqHeader, Request,
};
use caliptra_auth_man_types::ImageMetadataFlags;
use embassy_executor::Spawner;
use libsyscall_caliptra::flash::SpiFlash as FlashSyscall;
use libsyscall_caliptra::mailbox::MailboxError;
use libsyscall_caliptra::{dma::AXIAddr, mailbox::Mailbox};
use libtock_platform::ErrorCode;
use libtockasync::TockExecutor;
use pldm_common::message::firmware_update::get_fw_params::FirmwareParameters;
use pldm_common::message::firmware_update::verify_complete::VerifyResult;
use pldm_common::protocol::firmware_update::Descriptor;
use pldm_lib::daemon::PldmService;
use zerocopy::{FromBytes, IntoBytes};

pub const IMAGE_AUTHORIZED: u32 = 0xDEADC0DE;

pub struct PldmInstance<'a> {
    pub pldm_service: Option<PldmService<'a>>,
    pub executor: TockExecutor,
}

#[async_trait(?Send)]
pub trait ImageLoader {
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

pub struct FlashImageLoader {
    mailbox: Mailbox,
    flash: FlashSyscall,
}

pub struct PldmImageLoader<'a> {
    mailbox: Mailbox,
    spawner: Spawner,
    params: &'a PldmFirmwareDeviceParams<'a>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PldmFirmwareDeviceParams<'a> {
    pub descriptors: &'a [Descriptor],
    pub fw_params: &'a FirmwareParameters,
}

impl FlashImageLoader {
    pub fn new(flash_syscall: FlashSyscall) -> Self {
        Self {
            mailbox: Mailbox::new(),
            flash: flash_syscall,
        }
    }
}

#[async_trait(?Send)]
impl ImageLoader for FlashImageLoader {
    async fn load_and_authorize(&self, image_id: u32) -> Result<(), ErrorCode> {
        let load_address = get_image_load_address(&self.mailbox, image_id).await?;
        let mut header: [u8; core::mem::size_of::<FlashHeader>()] =
            [0; core::mem::size_of::<FlashHeader>()];
        flash_client::flash_read_header(&self.flash, &mut header).await?;
        let (offset, size) = flash_client::flash_read_toc(&self.flash, &header, image_id).await?;
        flash_client::flash_load_image(&self.flash, load_address, offset as usize, size as usize)
            .await?;
        authorize_image(&self.mailbox, image_id, size).await?;
        Ok(())
    }
}

impl<'a> PldmImageLoader<'a> {
    pub fn new(params: &'a PldmFirmwareDeviceParams, spawner: Spawner) -> Self {
        Self {
            mailbox: Mailbox::new(),
            spawner,
            params,
        }
    }
    pub async fn finalize(&self) -> Result<(), ErrorCode> {
        pldm_client::finalize(VerifyResult::VerifySuccess).await
    }
}

#[async_trait(?Send)]
impl ImageLoader for PldmImageLoader<'_> {
    async fn load_and_authorize(&self, image_id: u32) -> Result<(), ErrorCode> {
        let load_address = get_image_load_address(&self.mailbox, image_id).await?;

        let result: Result<(), ErrorCode> = {
            pldm_client::initialize_pldm(
                self.spawner,
                self.params.descriptors,
                self.params.fw_params,
            )
            .await?;
            let (offset, size) = pldm_client::pldm_download_toc(image_id).await?;
            pldm_client::pldm_download_image(load_address, offset, size).await?;
            authorize_image(&self.mailbox, image_id, size).await
        };
        if result.is_err() {
            self.finalize().await?;
            return Err(ErrorCode::Fail);
        }

        Ok(())
    }
}

const MCU_SRAM_HI_OFFSET: u64 = 0x1000_0000;
pub fn local_ram_to_axi_address(addr: u32) -> u64 {
    // Convert a local address to an AXI address
    (MCU_SRAM_HI_OFFSET << 32) | (addr as u64)
}

pub fn caliptra_axi_addr_to_dma_addr(addr: AXIAddr) -> Result<AXIAddr, ErrorCode> {
    // Convert Caliptra's AXI address to this device DMA address
    // Caliptra's External SRAM is mapped at 0x0000_0000_8000_0000
    // that is mapped to this device's DMA 0x2000_0000_8000_0000
    const CALIPTRA_EXTERNAL_SRAM_BASE: u64 = 0x0000_0000_8000_0000;
    const DEVICE_EXTERNAL_SRAM_BASE: u64 = 0x2000_0000_0000_0000;
    if addr < CALIPTRA_EXTERNAL_SRAM_BASE {
        return Err(ErrorCode::Invalid);
    }

    Ok(addr - CALIPTRA_EXTERNAL_SRAM_BASE + DEVICE_EXTERNAL_SRAM_BASE)
}

async fn get_image_load_address(mailbox: &Mailbox, image_id: u32) -> Result<AXIAddr, ErrorCode> {
    let mut req = GetImageInfoReq {
        hdr: MailboxReqHeader::default(),
        fw_id: image_id.to_le_bytes(),
    };
    let req_data = req.as_mut_bytes();
    mailbox
        .populate_checksum(GetImageInfoReq::ID.into(), req_data)
        .unwrap();

    let response_buffer = &mut [0u8; core::mem::size_of::<GetImageInfoResp>()];

    loop {
        let result = mailbox
            .execute(GetImageInfoReq::ID.0, req_data, response_buffer)
            .await;
        match result {
            Ok(_) => break,
            Err(MailboxError::ErrorCode(ErrorCode::Busy)) => continue,
            Err(_) => return Err(ErrorCode::Fail),
        }
    }

    match GetImageInfoResp::ref_from_bytes(response_buffer) {
        Ok(resp) => {
            let caliptra_axi_addr =
                (resp.image_load_address_high as u64) << 32 | resp.image_load_address_low as u64;

            caliptra_axi_addr_to_dma_addr(caliptra_axi_addr)
        }
        Err(_) => Err(ErrorCode::Fail),
    }
}

/// Authorizes an image based on its ID.
async fn authorize_image(mailbox: &Mailbox, image_id: u32, size: u32) -> Result<(), ErrorCode> {
    let mut flags = ImageMetadataFlags(0);
    flags.set_ignore_auth_check(false);
    flags.set_image_source(ImageHashSource::LoadAddress as u32);

    let mut req = AuthorizeAndStashReq {
        hdr: MailboxReqHeader::default(),
        fw_id: image_id.to_le_bytes(),
        flags: flags.0,
        source: ImageHashSource::LoadAddress as u32,
        image_size: size,
        ..Default::default()
    };
    let req_data = req.as_mut_bytes();
    mailbox
        .populate_checksum(AuthorizeAndStashReq::ID.into(), req_data)
        .unwrap();

    let response_buffer = &mut [0u8; core::mem::size_of::<AuthorizeAndStashResp>()];

    loop {
        let result = mailbox
            .execute(AuthorizeAndStashReq::ID.0, req_data, response_buffer)
            .await;
        match result {
            Ok(_) => break,
            Err(MailboxError::ErrorCode(ErrorCode::Busy)) => continue,
            Err(_) => return Err(ErrorCode::Fail),
        }
    }

    let resp =
        AuthorizeAndStashResp::ref_from_bytes(response_buffer).map_err(|_| ErrorCode::Fail)?;
    if resp.auth_req_result != IMAGE_AUTHORIZED {
        return Err(ErrorCode::Fail);
    }
    Ok(())
}
