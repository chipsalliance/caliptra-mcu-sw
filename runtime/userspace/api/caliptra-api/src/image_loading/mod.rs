// Licensed under the Apache-2.0 license

extern crate alloc;
mod flash_client;
mod pldm_client;
mod pldm_context;
mod pldm_fdops;

use alloc::boxed::Box;
use async_trait::async_trait;
use caliptra_api::mailbox::{
    AuthorizeAndStashReq, AuthorizeAndStashResp, GetImageInfoReq, GetImageInfoResp,
    ImageHashSource, MailboxReqHeader, Request,
};
use caliptra_auth_man_types::ImageMetadataFlags;
use embassy_executor::Spawner;
use flash_image::FlashHeader;
use libsyscall_caliptra::dma::DMAMapping;
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

pub struct FlashImageLoader<D: DMAMapping + 'static> {
    mailbox: Mailbox,
    flash: FlashSyscall,
    dma_mapping: &'static D,
}

pub struct PldmImageLoader<'a, D: DMAMapping + 'static> {
    mailbox: Mailbox,
    spawner: Spawner,
    params: &'a PldmFirmwareDeviceParams<'a>,
    dma_mapping: &'static D,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PldmFirmwareDeviceParams<'a> {
    pub descriptors: &'a [Descriptor],
    pub fw_params: &'a FirmwareParameters,
}

impl<D: DMAMapping + 'static> FlashImageLoader<D> {
    pub fn new(flash_syscall: FlashSyscall, dma_mapping: &'static D) -> Self {
        Self {
            mailbox: Mailbox::new(),
            flash: flash_syscall,
            dma_mapping,
        }
    }
}

#[async_trait(?Send)]
impl<D: DMAMapping + 'static> ImageLoader for FlashImageLoader<D> {
    async fn load_and_authorize(&self, image_id: u32) -> Result<(), ErrorCode> {
        let load_address =
            get_image_load_address(&self.mailbox, image_id, self.dma_mapping).await?;
        let mut header: [u8; core::mem::size_of::<FlashHeader>()] =
            [0; core::mem::size_of::<FlashHeader>()];
        flash_client::flash_read_header(&self.flash, &mut header).await?;
        let (offset, size) = flash_client::flash_read_toc(&self.flash, &header, image_id).await?;
        flash_client::flash_load_image(
            &self.flash,
            load_address,
            offset as usize,
            size as usize,
            self.dma_mapping,
        )
        .await?;
        authorize_image(&self.mailbox, image_id, size).await?;
        Ok(())
    }
}

impl<'a, D: DMAMapping + 'static> PldmImageLoader<'a, D> {
    pub fn new(
        params: &'a PldmFirmwareDeviceParams,
        spawner: Spawner,
        dma_mapping: &'static D,
    ) -> Self {
        Self {
            mailbox: Mailbox::new(),
            spawner,
            params,
            dma_mapping,
        }
    }
    pub async fn finalize(&self) -> Result<(), ErrorCode> {
        pldm_client::finalize(VerifyResult::VerifySuccess).await
    }
}

#[async_trait(?Send)]
impl<D: DMAMapping + 'static> ImageLoader for PldmImageLoader<'_, D> {
    async fn load_and_authorize(&self, image_id: u32) -> Result<(), ErrorCode> {
        let load_address =
            get_image_load_address(&self.mailbox, image_id, self.dma_mapping).await?;

        let result: Result<(), ErrorCode> = {
            pldm_client::initialize_pldm(
                self.spawner,
                self.params.descriptors,
                self.params.fw_params,
                self.dma_mapping,
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

async fn get_image_load_address(
    mailbox: &Mailbox,
    image_id: u32,
    dma_mapping: &impl DMAMapping,
) -> Result<AXIAddr, ErrorCode> {
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

            dma_mapping
                .cptra_axi_to_mcu_axi(caliptra_axi_addr)
                .map_err(|_| ErrorCode::Fail)
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
