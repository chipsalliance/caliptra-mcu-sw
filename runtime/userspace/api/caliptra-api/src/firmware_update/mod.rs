// Licensed under the Apache-2.0 license

extern crate alloc;
mod pldm_client;
mod pldm_context;
mod pldm_fdops;

use alloc::boxed::Box;
use async_trait::async_trait;
use caliptra_api::mailbox::{
    CommandId, FwInfoResp, GetImageInfoResp, MailboxReqHeader, MailboxRespHeader,
};
use embassy_executor::Spawner;
use flash_image::{FlashHeader, ImageHeader, CALIPTRA_FMC_RT_IDENTIFIER, SOC_MANIFEST_IDENTIFIER};
use libsyscall_caliptra::mailbox::Mailbox;
use libsyscall_caliptra::mailbox::{MailboxError, PayloadStream};
use libtock_platform::ErrorCode;
use libtockasync::TockExecutor;
use pldm_common::message::firmware_update::get_fw_params::FirmwareParameters;
use pldm_common::protocol::firmware_update::Descriptor;
use pldm_lib::daemon::PldmService;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

pub struct FirmwareUpdater<'a> {
    staging_memory: &'static dyn StagingMemory,
    mailbox: Mailbox,
    params: &'a PldmFirmwareDeviceParams,
    spawner: Spawner,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PldmFirmwareDeviceParams {
    pub descriptors: &'static [Descriptor],
    pub fw_params: &'static FirmwareParameters,
}

impl<'a> FirmwareUpdater<'a> {
    pub fn new(
        staging_memory: &'static dyn StagingMemory,
        params: &'a PldmFirmwareDeviceParams,
        spawner: Spawner,
    ) -> Self {
        Self {
            staging_memory,
            mailbox: Mailbox::new(),
            params,
            spawner,
        }
    }

    pub async fn start(&mut self) -> Result<(), ErrorCode> {
        // Download firmware image to staging memory
        pldm_client::initialize_pldm(
            self.spawner,
            self.params.descriptors,
            self.params.fw_params,
            self.staging_memory,
        )
        .await?;
        pldm_client::pldm_wait_completion().await?;

        // Parse the downloaded firmware image
        let mut flash_header = [0u8; core::mem::size_of::<FlashHeader>()];
        self.staging_memory
            .read(0, &mut flash_header)
            .await
            .map_err(|_| ErrorCode::Fail)?;
        let (flash_header, _) =
            FlashHeader::read_from_prefix(&flash_header).map_err(|_| ErrorCode::Fail)?;
        flash_header.verify().then_some(()).ok_or(ErrorCode::Fail)?;
        let image_headers_offset = flash_header.image_headers_offset as usize;

        // Update Caliptra
        let (image_offset, image_len) = self
            .get_image_toc(
                flash_header.image_count as usize,
                image_headers_offset,
                CALIPTRA_FMC_RT_IDENTIFIER,
            )
            .await
            .map_err(|_| ErrorCode::Fail)?;
        self.update_caliptra(image_offset, image_len).await?;
        self.wait_caliptra_rt_execution().await?;

        // Set the new Auth Manifest
        let (image_offset, image_len) = self
            .get_image_toc(
                flash_header.image_count as usize,
                image_headers_offset,
                SOC_MANIFEST_IDENTIFIER,
            )
            .await
            .map_err(|_| ErrorCode::Fail)?;
        self.update_manifest(image_offset, image_len).await
    }

    pub async fn get_image_toc(
        &self,
        num_images: usize,
        image_headers_offset: usize,
        image_id: u32,
    ) -> Result<(usize, usize), ErrorCode> {
        let mut current_header_offset = image_headers_offset;
        for _ in 0..num_images {
            let mut image_header = [0u8; core::mem::size_of::<ImageHeader>()];
            self.staging_memory
                .read(current_header_offset, &mut image_header)
                .await?;
            let (image_header, _) =
                ImageHeader::read_from_prefix(&image_header).map_err(|_| ErrorCode::Fail)?;
            image_header.verify().then_some(()).ok_or(ErrorCode::Fail)?;

            if image_header.identifier == image_id {
                return Ok((image_header.offset as usize, image_header.size as usize));
            }
            current_header_offset += core::mem::size_of::<ImageHeader>();
        }

        Err(ErrorCode::Fail)
    }

    async fn update_caliptra(&mut self, offset: usize, len: usize) -> Result<(), ErrorCode> {
        let mut req = MailboxReqHeader { chksum: 0 };
        let req_data = req.as_mut_bytes();
        self.mailbox
            .populate_checksum(CommandId::FIRMWARE_LOAD.into(), req_data)
            .unwrap();

        let response_buffer = &mut [0u8; core::mem::size_of::<GetImageInfoResp>()];

        let mut payload_stream = MailboxPayloadStream::new(self.staging_memory, offset, len);

        loop {
            let result = self
                .mailbox
                .execute_with_payload_stream(
                    CommandId::FIRMWARE_LOAD.into(),
                    None,
                    &mut payload_stream,
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

    async fn update_manifest(&mut self, offset: usize, len: usize) -> Result<(), ErrorCode> {
        let mut req = AuthManifestReqHeader {
            chksum: 0,
            manifest_size: len as u32,
        };

        let mut payload_stream = MailboxPayloadStream::new(self.staging_memory, offset, len);

        // Calculate the mailbox checksum
        let mut checksum = payload_stream.get_bytesum().await;
        for b in CommandId::SET_AUTH_MANIFEST.0.to_le_bytes().iter() {
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
                    CommandId::SET_AUTH_MANIFEST.into(),
                    Some(header),
                    &mut payload_stream,
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

    async fn wait_caliptra_rt_execution(&mut self) -> Result<(), ErrorCode> {
        let mut req = MailboxReqHeader { chksum: 0 };
        let req_data = req.as_mut_bytes();
        self.mailbox
            .populate_checksum(CommandId::FW_INFO.into(), req_data)
            .unwrap();

        let response_buffer = &mut [0u8; core::mem::size_of::<FwInfoResp>()];

        // Wait indefinitely until Caliptra RT is ready
        // Todo: Implement a timeout mechanism
        loop {
            let result = self
                .mailbox
                .execute(CommandId::FW_INFO.into(), req_data, response_buffer)
                .await;
            match result {
                Ok(_) => break,
                Err(_) => continue,
            }
        }

        Ok(())
    }
}

pub struct PldmInstance<'a> {
    pub pldm_service: Option<PldmService<'a>>,
    pub executor: TockExecutor,
}

#[async_trait]
pub trait StagingMemory: core::fmt::Debug + Send + Sync {
    async fn write(&self, offset: usize, data: &[u8]) -> Result<(), ErrorCode>;
    async fn read(&self, offset: usize, data: &mut [u8]) -> Result<(), ErrorCode>;
    fn size(&self) -> usize;
}

pub struct MailboxPayloadStream {
    pub staging_memory: &'static dyn StagingMemory,
    pub offset: usize,
    pub cursor: usize,
    pub len: usize,
}

impl MailboxPayloadStream {
    pub fn new(
        staging_memory: &'static dyn StagingMemory,
        starting_offset: usize,
        len: usize,
    ) -> Self {
        Self {
            staging_memory,
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
impl PayloadStream for MailboxPayloadStream {
    fn size(&self) -> usize {
        self.len
    }

    async fn read(&mut self, buffer: &mut [u8]) -> Result<usize, ErrorCode> {
        if (self.cursor - self.offset) >= self.len {
            return Ok(0); // No more data to read
        }

        let bytes_to_read = (self.len - (self.cursor - self.offset)).min(buffer.len());
        self.staging_memory
            .read(self.cursor, buffer[..bytes_to_read].as_mut())
            .await
            .map_err(|_| ErrorCode::Fail)?;
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
