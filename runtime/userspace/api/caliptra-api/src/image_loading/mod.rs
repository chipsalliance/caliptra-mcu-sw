// Licensed under the Apache-2.0 license

extern crate alloc;
mod flash_client;
mod pldm_client;
mod pldm_context;
mod pldm_fdops;

use alloc::boxed::Box;
use async_trait::async_trait;
use caliptra_api::mailbox::{
    AuthorizeAndStashReq, AuthorizeAndStashResp, CommandId, GetImageInfoReq, GetImageInfoResp,
    ImageHashSource, MailboxReqHeader, MailboxRespHeader, Request,
};
use caliptra_auth_man_types::ImageMetadataFlags;
use embassy_executor::Spawner;
use flash_image::{FlashHeader, SOC_MANIFEST_IDENTIFIER};
use libsyscall_caliptra::dma::DMAMapping;
use libsyscall_caliptra::flash::SpiFlash as FlashSyscall;
use libsyscall_caliptra::mailbox::{MailboxError, PayloadStream};
use libsyscall_caliptra::{dma::AXIAddr, mailbox::Mailbox};
use libtock_platform::ErrorCode;
use libtockasync::TockExecutor;
use pldm_common::message::firmware_update::get_fw_params::FirmwareParameters;
use pldm_common::message::firmware_update::verify_complete::VerifyResult;
use pldm_common::protocol::firmware_update::Descriptor;
use pldm_lib::daemon::PldmService;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

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
        let image_info = get_image_info(&self.mailbox, image_id).await?;
        let load_address = convert_dma_cptra_addr_to_mcu_addr(
            self.dma_mapping,
            ((image_info.image_load_address_high as u64) << 32)
                | (image_info.image_load_address_low as u64),
        )?;
        let mut header: [u8; core::mem::size_of::<FlashHeader>()] =
            [0; core::mem::size_of::<FlashHeader>()];
        flash_client::flash_read_header(&self.flash, &mut header).await?;
        let (offset, size) =
            flash_client::flash_read_toc(&self.flash, &header, image_info.component_id).await?;
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

impl<D: DMAMapping + 'static> FlashImageLoader<D> {
    pub async fn set_auth_manifest(&self) -> Result<(), ErrorCode> {
        let mut header: [u8; core::mem::size_of::<FlashHeader>()] =
            [0; core::mem::size_of::<FlashHeader>()];
        flash_client::flash_read_header(&self.flash, &mut header).await?;
        let (offset, size) =
            flash_client::flash_read_toc(&self.flash, &header, SOC_MANIFEST_IDENTIFIER).await?;

        let mut stream =
            FlashMailboxPayloadStream::new(&self.flash, offset as usize, size as usize);

        let mut req = AuthManifestReqHeader {
            chksum: 0,
            manifest_size: size,
        };

        // Calculate the mailbox checksum
        let mut checksum = stream.get_bytesum().await;
        for b in CommandId::VERIFY_AUTH_MANIFEST.0.to_le_bytes().iter() {
            checksum = checksum.wrapping_add(u32::from(*b));
        }
        for b in req.as_mut_bytes().iter() {
            checksum = checksum.wrapping_add(u32::from(*b));
        }
        req.chksum = 0u32.wrapping_sub(checksum);

        let response_buffer = &mut [0u8; core::mem::size_of::<MailboxRespHeader>()];
        let header = req.as_mut_bytes();
        loop {
            let result = self
                .mailbox
                .execute_with_payload_stream(
                    CommandId::VERIFY_AUTH_MANIFEST.into(),
                    Some(header),
                    &mut stream,
                    response_buffer,
                )
                .await;
            match result {
                Ok(_) => return Ok(()),
                Err(MailboxError::ErrorCode(ErrorCode::Busy)) => continue,
                Err(_) => return Err(ErrorCode::Fail),
            }
        }
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
    pub fn finalize(&self) -> Result<(), ErrorCode> {
        pldm_client::finalize(VerifyResult::VerifySuccess)
    }
}

#[async_trait(?Send)]
impl<D: DMAMapping + 'static> ImageLoader for PldmImageLoader<'_, D> {
    async fn load_and_authorize(&self, image_id: u32) -> Result<(), ErrorCode> {
        let image_info = get_image_info(&self.mailbox, image_id).await?;
        let load_address = convert_dma_cptra_addr_to_mcu_addr(
            self.dma_mapping,
            ((image_info.image_load_address_high as u64) << 32)
                | (image_info.image_load_address_low as u64),
        )?;

        let result: Result<(), ErrorCode> = {
            pldm_client::initialize_pldm(
                self.spawner,
                self.params.descriptors,
                self.params.fw_params,
                self.dma_mapping,
            )
            .await?;
            let (offset, size) = pldm_client::pldm_download_toc(image_info.component_id).await?;
            pldm_client::pldm_download_image(load_address, offset, size).await?;
            authorize_image(&self.mailbox, image_id, size).await
        };
        if result.is_err() {
            self.finalize()?;
            return Err(ErrorCode::Fail);
        }

        Ok(())
    }
}

fn convert_dma_cptra_addr_to_mcu_addr(
    dma_mapping: &impl DMAMapping,
    caliptra_axi_addr: u64,
) -> Result<AXIAddr, ErrorCode> {
    dma_mapping
        .cptra_axi_to_mcu_axi(caliptra_axi_addr)
        .map_err(|_| ErrorCode::Fail)
}

async fn get_image_info(mailbox: &Mailbox, image_id: u32) -> Result<GetImageInfoResp, ErrorCode> {
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
        Ok(resp) => Ok(GetImageInfoResp {
            component_id: resp.component_id,
            flags: resp.flags,
            image_load_address_high: resp.image_load_address_high,
            image_load_address_low: resp.image_load_address_low,
            image_staging_address_high: resp.image_staging_address_high,
            image_staging_address_low: resp.image_staging_address_low,
            ..Default::default()
        }),
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

pub struct FlashMailboxPayloadStream<'a> {
    pub flash: &'a FlashSyscall,
    pub offset: usize,
    pub cursor: usize,
    pub len: usize,
}

impl<'a> FlashMailboxPayloadStream<'a> {
    pub fn new(flash: &'a FlashSyscall, starting_offset: usize, len: usize) -> Self {
        Self {
            flash,
            offset: starting_offset,
            cursor: starting_offset,
            len,
        }
    }
    pub fn reset(&mut self) {
        // Reset the cursor to the starting offset
        self.cursor = self.offset;
    }
    pub async fn get_bytesum(&mut self) -> u32 {
        self.reset();
        let mut sum = 0u32;
        let mut buffer = [0u8; 256];
        while let Ok(bytes_read) = self.read(&mut buffer).await {
            if bytes_read == 0 {
                break; // No more data to read
            }
            for byte in &buffer[..bytes_read] {
                sum = sum.wrapping_add(u32::from(*byte));
            }
        }
        self.reset();
        sum
    }
}

#[async_trait(?Send)]
impl PayloadStream for FlashMailboxPayloadStream<'_> {
    fn size(&self) -> usize {
        self.len
    }

    async fn read(&mut self, buffer: &mut [u8]) -> Result<usize, ErrorCode> {
        if (self.cursor - self.offset) >= self.len {
            return Ok(0); // No more data to read
        }

        let bytes_to_read = (self.len - (self.cursor - self.offset)).min(buffer.len());
        self.flash
            .read(self.cursor, bytes_to_read, &mut buffer[..bytes_to_read])
            .await?;
        self.cursor += bytes_to_read;
        Ok(bytes_to_read)
    }
}

#[repr(C)]
#[derive(Debug, FromBytes, IntoBytes, Clone, Copy, Immutable, KnownLayout)]
pub struct AuthManifestReqHeader {
    pub chksum: u32,
    pub manifest_size: u32,
}
