// Licensed under the Apache-2.0 license

extern crate alloc;
mod pldm_client;
mod pldm_context;
mod pldm_fdops;

use alloc::boxed::Box;
use async_trait::async_trait;
use caliptra_api::mailbox::{
    ActivateFirmwareReq, ActivateFirmwareResp, CommandId, FwInfoResp, GetImageInfoReq,
    GetImageInfoResp, MailboxReqHeader, MailboxRespHeader, Request,
};
use embassy_executor::Spawner;
use flash_image::{
    FlashHeader, ImageHeader, CALIPTRA_FMC_RT_IDENTIFIER, MCU_RT_IDENTIFIER,
    SOC_MANIFEST_IDENTIFIER,
};
use libsyscall_caliptra::dma::AXIAddr;
use libsyscall_caliptra::dma::{DMASource, DMATransaction, DMA as DMASyscall};
use libsyscall_caliptra::mailbox::Mailbox;
use libsyscall_caliptra::mailbox::{MailboxError, PayloadStream};
use libtock_platform::ErrorCode;
use libtockasync::TockExecutor;
use mcu_config_emulator::dma::{caliptra_axi_addr_to_dma_addr, mcu_sram_to_axi_address};
use pldm_common::message::firmware_update::get_fw_params::FirmwareParameters;
use pldm_common::protocol::firmware_update::Descriptor;
use pldm_lib::daemon::PldmService;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

use core::fmt::Write;
use libsyscall_caliptra::DefaultSyscalls;
use libtock_console::Console;

const MAX_DMA_TRANSFER_SIZE: usize = 128;

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
        writeln!(
            Console::<DefaultSyscalls>::writer(),
            "[FW Upd] Updating Caliptra"
        )
        .unwrap();
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
        writeln!(
            Console::<DefaultSyscalls>::writer(),
            "[FW Upd] Updating Manifest"
        )
        .unwrap();
        let (image_offset, image_len) = self
            .get_image_toc(
                flash_header.image_count as usize,
                image_headers_offset,
                SOC_MANIFEST_IDENTIFIER,
            )
            .await
            .map_err(|_| ErrorCode::Fail)?;
        self.update_manifest(image_offset, image_len).await?;

        writeln!(
            Console::<DefaultSyscalls>::writer(),
            "[FW Upd] Updating MCU"
        )
        .unwrap();
        let (image_offset, image_len) = self
            .get_image_toc(
                flash_header.image_count as usize,
                image_headers_offset,
                MCU_RT_IDENTIFIER,
            )
            .await
            .map_err(|_| ErrorCode::Fail)?;

        self.update_mcu(image_offset, image_len).await?;

        Ok(())
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

    async fn get_dma_image_staging_address(&self, image_id: u32) -> Result<AXIAddr, ErrorCode> {
        let mut req = GetImageInfoReq {
            hdr: MailboxReqHeader::default(),
            fw_id: image_id.to_le_bytes(),
        };
        let req_data = req.as_mut_bytes();
        self.mailbox
            .populate_checksum(GetImageInfoReq::ID.into(), req_data)
            .unwrap();

        let response_buffer = &mut [0u8; core::mem::size_of::<GetImageInfoResp>()];

        loop {
            let result = self
                .mailbox
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
                let caliptra_axi_addr = (resp.image_staging_address_high as u64) << 32
                    | resp.image_staging_address_low as u64;

                caliptra_axi_addr_to_dma_addr(caliptra_axi_addr).map_err(|_| ErrorCode::Fail)
            }
            Err(_) => Err(ErrorCode::Fail),
        }
    }

    pub async fn copy_to_memory(
        &self,
        mem_address: AXIAddr,
        offset: usize,
        img_size: usize,
    ) -> Result<(), ErrorCode> {
        let dma_syscall: DMASyscall = DMASyscall::new();
        let mut remaining_size = img_size;
        let mut current_offset = offset;
        let mut current_address = mem_address;

        while remaining_size > 0 {
            let transfer_size = remaining_size.min(MAX_DMA_TRANSFER_SIZE);
            let mut buffer = [0; MAX_DMA_TRANSFER_SIZE];
            self.staging_memory
                .read(current_offset, &mut buffer[..transfer_size])
                .await?;

            let source_address = mcu_sram_to_axi_address(buffer.as_ptr() as u32);
            let transaction = DMATransaction {
                byte_count: transfer_size,
                source: DMASource::Address(source_address),
                dest_addr: current_address,
            };
            dma_syscall.xfer(&transaction).await?;
            remaining_size -= transfer_size;
            current_offset += transfer_size;
            current_address += transfer_size as u64;
        }

        Ok(())
    }

    async fn update_mcu(&mut self, image_offset: usize, len: usize) -> Result<(), ErrorCode> {
        // Get the DMA staging address for the MCU
        let staging_address = self
            .get_dma_image_staging_address(MCU_RT_IDENTIFIER)
            .await?;

        writeln!(
            Console::<DefaultSyscalls>::writer(),
            "[FW Upd] Copy MCU image to: {:#x}",
            staging_address
        )
        .unwrap();

        // Copy the firmware image to the MCU DMA staging area
        self.copy_to_memory(staging_address, image_offset, len)
            .await?;

        writeln!(
            Console::<DefaultSyscalls>::writer(),
            "[FW Upd] Activate MCU Image "
        )
        .unwrap();

        let mut req = ActivateFirmwareReq {
            hdr: MailboxReqHeader { chksum: 0 },
            fw_id_count: 1,
            fw_ids: {
                let mut fw_ids = [0u32; ActivateFirmwareReq::MAX_FW_ID_COUNT];
                fw_ids[0] = MCU_RT_IDENTIFIER;
                fw_ids
            },
            mcu_fw_image_size: len as u32,
        };

        let req = req.as_mut_bytes();

        self.mailbox
            .populate_checksum(CommandId::ACTIVATE_FIRMWARE.into(), req)
            .unwrap();

        let response_buffer = &mut [0u8; core::mem::size_of::<ActivateFirmwareResp>()];
        loop {
            let result = self
                .mailbox
                .execute(CommandId::ACTIVATE_FIRMWARE.into(), req, response_buffer)
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
