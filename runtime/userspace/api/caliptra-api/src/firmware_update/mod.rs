// Licensed under the Apache-2.0 license

extern crate alloc;
mod pldm_client;
mod pldm_context;
mod pldm_fdops;

use crate::firmware_update::pldm_client::pldm_total_component_size;
use crate::firmware_update::pldm_context::State;
use crate::mailbox_api::MAX_CRYPTO_MBOX_DATA_SIZE;
use alloc::boxed::Box;
use async_trait::async_trait;
use caliptra_api::mailbox::{
    ActivateFirmwareReq, ActivateFirmwareResp, CommandId, FirmwareVerifyResp, FirmwareVerifyResult,
    FwInfoResp, GetImageInfoReq, GetImageInfoResp, MailboxReqHeader, MailboxRespHeader, Request,
};
use caliptra_auth_man_types::{
    AuthManifestImageMetadata, AuthManifestImageMetadataCollection, AuthorizationManifest,
};
use caliptra_image_types::ImageManifest;
use caliptra_mcu_flash_image::{
    FlashHeader, ImageHeader, CALIPTRA_FMC_RT_IDENTIFIER, MCU_RT_IDENTIFIER,
    SOC_MANIFEST_IDENTIFIER,
};
use caliptra_mcu_libsyscall_caliptra::console_writeln;
use caliptra_mcu_libsyscall_caliptra::dma::AXIAddr;
use caliptra_mcu_libsyscall_caliptra::dma::{
    DMAMapping, DMASource, DMATransaction, DMA as DMASyscall,
};
use caliptra_mcu_libsyscall_caliptra::mailbox::Mailbox;
use caliptra_mcu_libsyscall_caliptra::mailbox::{MailboxError, PayloadStream};
use caliptra_mcu_libtock_platform::ErrorCode;
use caliptra_mcu_libtockasync::TockExecutor;
use caliptra_mcu_pldm_common::message::firmware_update::apply_complete::ApplyResult;
use caliptra_mcu_pldm_common::message::firmware_update::get_fw_params::FirmwareParameters;
use caliptra_mcu_pldm_common::message::firmware_update::verify_complete::VerifyResult;
use caliptra_mcu_pldm_common::protocol::firmware_update::Descriptor;
use caliptra_mcu_pldm_common::util::fw_component::FirmwareComponent;
use caliptra_mcu_pldm_lib::daemon::PldmService;
use embassy_executor::Spawner;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

use caliptra_mcu_libsyscall_caliptra::DefaultSyscalls;
use caliptra_mcu_libtock_console::Console;
use core::fmt::Write;
use core::mem::offset_of;

use crate::crypto::hash::{HashAlgoType, HashContext};

pub struct FirmwareUpdater<'a, D: DMAMapping> {
    staging_memory: &'static dyn StagingMemory,
    mailbox: Mailbox,
    params: &'a PldmFirmwareDeviceParams,
    soc_image_load_fw_ids: &'a [u32],
    dma_mapping: &'a D,
    spawner: Spawner,
    skip_activation: bool,
    verify_same_image: bool,
    hooks: Option<&'a dyn FirmwareUpdateHooks>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PldmFirmwareDeviceParams {
    pub descriptors: &'static [Descriptor],
    pub fw_params: &'static FirmwareParameters,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CaliptraFwAction {
    Verify = 1,
    Load = 2,
}

impl<'a, D: DMAMapping> FirmwareUpdater<'a, D> {
    pub fn new(
        staging_memory: &'static dyn StagingMemory,
        params: &'a PldmFirmwareDeviceParams,
        soc_image_load_fw_ids: &'a [u32],
        dma_mapping: &'a D,
        spawner: Spawner,
        hooks: Option<&'a dyn FirmwareUpdateHooks>,
    ) -> Self {
        Self {
            staging_memory,
            mailbox: Mailbox::new(),
            params,
            soc_image_load_fw_ids,
            dma_mapping,
            spawner,
            skip_activation: false,
            verify_same_image: false,
            hooks,
        }
    }

    pub fn set_skip_activation(&mut self, skip: bool) {
        self.skip_activation = skip;
    }

    pub fn set_verify_same_image(&mut self, verify: bool) {
        self.verify_same_image = verify;
    }

    pub fn set_hooks(&mut self, hooks: &'a dyn FirmwareUpdateHooks) {
        self.hooks = Some(hooks);
    }

    pub async fn start(&mut self) -> Result<(), ErrorCode> {
        // Store hooks in the shared static so that the PLDM FD ops can invoke
        // on_fw_update_request when the UA sends an UpdateComponent request.
        if let Some(hooks) = self.hooks {
            // Safety: the hooks reference is valid for the duration of start(),
            // which awaits until the entire firmware update completes.
            let hooks_static: &'static dyn FirmwareUpdateHooks =
                unsafe { core::mem::transmute(hooks) };
            pldm_context::FW_UPDATE_HOOKS.lock(|h| {
                *h.borrow_mut() = Some(hooks_static);
            });
        }

        // Download firmware image to staging memory
        pldm_client::initialize_pldm(
            self.spawner,
            self.params.descriptors,
            self.params.fw_params,
            self.staging_memory,
        )
        .await?;

        pldm_client::pldm_wait(State::Verifying).await?;

        // Download is complete, verify the image
        let flash_header = self.verify().await;
        if flash_header.is_err() {
            pldm_client::pldm_set_verification_result(VerifyResult::VerifyErrorVerificationFailure);
            // Abort firmware update
            return Err(ErrorCode::Fail);
        }
        let flash_header = flash_header.unwrap();

        // If verify_same_image is set, confirm the downloaded image matches running firmware
        if self.verify_same_image
            && self
                .verify_running_image_match(&flash_header)
                .await
                .is_err()
        {
            pldm_client::pldm_set_verification_result(VerifyResult::VerifyErrorVerificationFailure);
            return Err(ErrorCode::Fail);
        }

        pldm_client::pldm_set_verification_result(VerifyResult::VerifySuccess);
        pldm_client::pldm_wait(State::Apply).await?;

        // Mark image as valid in staging memory
        let img_len = pldm_total_component_size();
        self.staging_memory.image_valid(img_len).await?;

        pldm_client::pldm_set_apply_result(ApplyResult::ApplySuccess);
        pldm_client::pldm_wait(State::Activate).await?;

        if self.skip_activation {
            // Skip activation — image is persisted to flash but no reboot
            return Ok(());
        }

        // Update Caliptra
        if let Some(hooks) = self.hooks {
            hooks.pre_caliptra_activation().await?;
        }
        let result = self.update_caliptra(&flash_header).await;
        if result.is_err() {
            // Abort firmware update
            return Err(ErrorCode::Fail);
        }

        // Set SoC authorization manifest
        if let Some(hooks) = self.hooks {
            hooks.pre_auth_manifest_activation().await?;
        }
        self.set_auth_manifest().await?;

        // Update MCU and reboot
        if let Some(hooks) = self.hooks {
            hooks.pre_mcu_activation().await?;
        }
        self.update_mcu(&flash_header).await?;

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

    pub async fn get_image_toc_by_index(
        &self,
        num_images: usize,
        image_headers_offset: usize,
        index: usize,
    ) -> Result<ImageHeader, ErrorCode> {
        if index >= num_images {
            return Err(ErrorCode::Fail);
        }
        let offset = image_headers_offset + index * core::mem::size_of::<ImageHeader>();
        let mut image_header = [0u8; core::mem::size_of::<ImageHeader>()];
        self.staging_memory.read(offset, &mut image_header).await?;
        let (image_header, _) =
            ImageHeader::read_from_prefix(&image_header).map_err(|_| ErrorCode::Fail)?;
        image_header.verify().then_some(()).ok_or(ErrorCode::Fail)?;

        Ok(image_header)
    }

    pub async fn update_mcu_with_auth_manifest(
        &mut self,
        flash_header: &FlashHeader,
    ) -> Result<(), ErrorCode> {
        self.set_auth_manifest().await?;
        self.update_mcu(flash_header).await
    }

    async fn set_auth_manifest(&mut self) -> Result<(), ErrorCode> {
        let mut flash_header = [0u8; core::mem::size_of::<FlashHeader>()];
        self.staging_memory
            .read(0, &mut flash_header)
            .await
            .map_err(|_| ErrorCode::Fail)?;
        let (flash_header, _) =
            FlashHeader::read_from_prefix(&flash_header).map_err(|_| ErrorCode::Fail)?;
        console_writeln!(
            Console::<DefaultSyscalls>::writer(),
            "[FW Upd] Setting Manifest"
        );
        let (manifest_offset, manifest_len) = self
            .get_image_toc(
                flash_header.image_count as usize,
                flash_header.image_headers_offset as usize,
                SOC_MANIFEST_IDENTIFIER,
            )
            .await
            .map_err(|_| ErrorCode::Fail)?;
        self.validate_auth_manifest_soc_fw_id_set(manifest_offset, manifest_len)
            .await?;

        let mut req = AuthManifestReqHeader {
            chksum: 0,
            manifest_size: manifest_len as u32,
        };

        let mut payload_stream =
            MailboxPayloadStream::new(self.staging_memory, manifest_offset, manifest_len);

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

    async fn verify(&mut self) -> Result<FlashHeader, ErrorCode> {
        // Parse the downloaded firmware image
        let mut flash_header = [0u8; core::mem::size_of::<FlashHeader>()];
        self.staging_memory
            .read(0, &mut flash_header)
            .await
            .map_err(|_| ErrorCode::Fail)?;
        let (flash_header, _) =
            FlashHeader::read_from_prefix(&flash_header).map_err(|_| ErrorCode::Fail)?;
        flash_header.verify().then_some(()).ok_or(ErrorCode::Fail)?;

        // Verify Caliptra bundle
        console_writeln!(
            Console::<DefaultSyscalls>::writer(),
            "[FW Upd] Verifying Caliptra Bundle (image_count={} headers_off={})",
            flash_header.image_count,
            flash_header.image_headers_offset
        );
        let toc_result = self
            .get_image_toc(
                flash_header.image_count as usize,
                flash_header.image_headers_offset as usize,
                CALIPTRA_FMC_RT_IDENTIFIER,
            )
            .await;
        if toc_result.is_err() {
            console_writeln!(
                Console::<DefaultSyscalls>::writer(),
                "[FW Upd] ERROR: get_image_toc for Caliptra bundle failed"
            );
            return Err(ErrorCode::Fail);
        }
        let (cptra_image_offset, cptra_image_len) = toc_result.unwrap();
        console_writeln!(
            Console::<DefaultSyscalls>::writer(),
            "[FW Upd] Caliptra bundle at offset={} len={}",
            cptra_image_offset,
            cptra_image_len
        );
        let verify_result = self
            .process_caliptra_fw(
                cptra_image_offset,
                cptra_image_len,
                CaliptraFwAction::Verify,
            )
            .await;
        if verify_result.is_err() {
            console_writeln!(
                Console::<DefaultSyscalls>::writer(),
                "[FW Upd] ERROR: process_caliptra_fw(Verify) failed"
            );
            return Err(ErrorCode::Fail);
        }

        // Verify the new Auth Manifest
        console_writeln!(
            Console::<DefaultSyscalls>::writer(),
            "[FW Upd] Verifying Manifest"
        );
        let (manifest_offset, manifest_len) = self
            .get_image_toc(
                flash_header.image_count as usize,
                flash_header.image_headers_offset as usize,
                SOC_MANIFEST_IDENTIFIER,
            )
            .await
            .map_err(|_| ErrorCode::Fail)?;
        self.verify_manifest(manifest_offset, manifest_len).await?;
        self.validate_auth_manifest_soc_fw_id_set(manifest_offset, manifest_len)
            .await?;

        for i in 0..flash_header.image_count as usize {
            let image_header = self
                .get_image_toc_by_index(
                    flash_header.image_count as usize,
                    flash_header.image_headers_offset as usize,
                    i,
                )
                .await?;

            match image_header.identifier {
                CALIPTRA_FMC_RT_IDENTIFIER => {
                    // Skip Caliptra image verification
                    continue;
                }
                SOC_MANIFEST_IDENTIFIER => {
                    // Skip SOC Manifest verification
                    continue;
                }
                _ => {
                    // Verify MCU or SOC images
                }
            }

            let metadata = self
                .get_image_metadata(manifest_offset, manifest_len, image_header.identifier)
                .await?;

            self.verify_mcu_or_soc_image(
                image_header.offset as usize,
                image_header.size as usize,
                &metadata,
            )
            .await?;
        }
        Ok(flash_header)
    }

    /// Verify that the downloaded image matches the currently running firmware.
    ///
    /// Compares Caliptra FMC+RT digests from the downloaded ImageManifest against
    /// the running firmware's digests obtained via the FW_INFO mailbox command.
    /// Also compares MCU RT and SoC image digests against the active auth manifest.
    async fn verify_running_image_match(
        &mut self,
        flash_header: &FlashHeader,
    ) -> Result<(), ErrorCode> {
        console_writeln!(
            Console::<DefaultSyscalls>::writer(),
            "[FW Upd] Verifying image matches running firmware"
        );

        // 1. Verify Caliptra FMC+RT digests
        let (cptra_image_offset, _cptra_image_len) = self
            .get_image_toc(
                flash_header.image_count as usize,
                flash_header.image_headers_offset as usize,
                CALIPTRA_FMC_RT_IDENTIFIER,
            )
            .await?;

        // Read the ImageManifest from the downloaded Caliptra bundle
        let mut manifest_bytes = [0u8; core::mem::size_of::<ImageManifest>()];
        self.staging_memory
            .read(cptra_image_offset, &mut manifest_bytes)
            .await?;
        let (manifest, _) =
            ImageManifest::read_from_prefix(&manifest_bytes).map_err(|_| ErrorCode::Fail)?;

        // Get the running firmware digests via FW_INFO
        let mut req = MailboxReqHeader::default();
        let req_data = req.as_mut_bytes();
        self.mailbox
            .populate_checksum(CommandId::FW_INFO.into(), req_data)
            .unwrap();
        let response_buffer = &mut [0u8; core::mem::size_of::<FwInfoResp>()];
        loop {
            let result = self
                .mailbox
                .execute(CommandId::FW_INFO.into(), req_data, response_buffer)
                .await;
            match result {
                Ok(_) => break,
                Err(MailboxError::ErrorCode(ErrorCode::Busy)) => continue,
                Err(_) => return Err(ErrorCode::Fail),
            }
        }
        let fw_info = FwInfoResp::read_from_bytes(response_buffer).map_err(|_| ErrorCode::Fail)?;

        // Compare FMC digests
        if manifest.fmc.digest != fw_info.fmc_sha384_digest {
            console_writeln!(
                Console::<DefaultSyscalls>::writer(),
                "[FW Upd] FMC digest mismatch"
            );
            return Err(ErrorCode::Fail);
        }

        // Compare RT digests
        if manifest.runtime.digest != fw_info.runtime_sha384_digest {
            console_writeln!(
                Console::<DefaultSyscalls>::writer(),
                "[FW Upd] RT digest mismatch"
            );
            return Err(ErrorCode::Fail);
        }

        // 2. Verify MCU RT and SoC image digests against active auth manifest
        let (manifest_offset, manifest_len) = self
            .get_image_toc(
                flash_header.image_count as usize,
                flash_header.image_headers_offset as usize,
                SOC_MANIFEST_IDENTIFIER,
            )
            .await?;

        for i in 0..flash_header.image_count as usize {
            let image_header = self
                .get_image_toc_by_index(
                    flash_header.image_count as usize,
                    flash_header.image_headers_offset as usize,
                    i,
                )
                .await?;

            match image_header.identifier {
                CALIPTRA_FMC_RT_IDENTIFIER | SOC_MANIFEST_IDENTIFIER => continue,
                _ => {}
            }

            // Compute SHA-384 of the downloaded image
            let mut hasher = HashContext::new();
            hasher
                .init(HashAlgoType::SHA384, None)
                .await
                .map_err(|_| ErrorCode::Fail)?;
            let mut buffer = [0u8; MAX_CRYPTO_MBOX_DATA_SIZE / 2];
            let mut total_bytes_read = 0;
            let img_offset = image_header.offset as usize;
            let img_size = image_header.size as usize;
            while total_bytes_read < img_size {
                let bytes_to_read =
                    (img_size - total_bytes_read).min(MAX_CRYPTO_MBOX_DATA_SIZE / 2);
                self.staging_memory
                    .read(img_offset + total_bytes_read, &mut buffer[..bytes_to_read])
                    .await?;
                hasher
                    .update(&buffer[..bytes_to_read])
                    .await
                    .map_err(|_| ErrorCode::Fail)?;
                total_bytes_read += bytes_to_read;
            }
            let mut hash = [0u8; 48];
            hasher
                .finalize(&mut hash)
                .await
                .map_err(|_| ErrorCode::Fail)?;

            // Compare against the digest in the active auth manifest
            let metadata = self
                .get_image_metadata(manifest_offset, manifest_len, image_header.identifier)
                .await?;
            if hash != metadata.digest {
                console_writeln!(
                    Console::<DefaultSyscalls>::writer(),
                    "[FW Upd] Image 0x{:x} digest mismatch with running firmware",
                    image_header.identifier
                );
                return Err(ErrorCode::Fail);
            }
        }

        console_writeln!(
            Console::<DefaultSyscalls>::writer(),
            "[FW Upd] Running image verification passed"
        );
        Ok(())
    }

    pub async fn get_image_metadata(
        &self,
        manifest_staging_mem_offset: usize,
        manifest_size: usize,
        image_id: u32,
    ) -> Result<AuthManifestImageMetadata, ErrorCode> {
        let entry_count = self
            .get_image_metadata_entry_count(manifest_staging_mem_offset, manifest_size)
            .await?;

        for i in 0..entry_count as usize {
            let metadata = self
                .get_image_metadata_by_index(manifest_staging_mem_offset, manifest_size, i)
                .await?;

            if metadata.fw_id == image_id {
                return Ok(metadata);
            }
        }

        Err(ErrorCode::Fail)
    }

    async fn get_image_metadata_entry_count(
        &self,
        manifest_staging_mem_offset: usize,
        manifest_size: usize,
    ) -> Result<u32, ErrorCode> {
        let entry_count_offset = manifest_staging_mem_offset
            + offset_of!(AuthorizationManifest, image_metadata_col)
            + offset_of!(AuthManifestImageMetadataCollection, entry_count);
        if entry_count_offset + 4 > manifest_staging_mem_offset + manifest_size {
            return Err(ErrorCode::Fail);
        }

        let mut entry_count = [0u8; 4];
        self.staging_memory
            .read(entry_count_offset, &mut entry_count)
            .await?;
        Ok(u32::from_le_bytes(entry_count))
    }

    async fn get_image_metadata_by_index(
        &self,
        manifest_staging_mem_offset: usize,
        manifest_size: usize,
        index: usize,
    ) -> Result<AuthManifestImageMetadata, ErrorCode> {
        let image_metadata_collection_offset = manifest_staging_mem_offset
            + offset_of!(AuthorizationManifest, image_metadata_col)
            + offset_of!(AuthManifestImageMetadataCollection, image_metadata_list);
        let metadata_offset = image_metadata_collection_offset
            + index * core::mem::size_of::<AuthManifestImageMetadata>();
        let mut metadata_bytes = [0u8; core::mem::size_of::<AuthManifestImageMetadata>()];
        if metadata_offset + metadata_bytes.len() > manifest_staging_mem_offset + manifest_size {
            return Err(ErrorCode::Fail);
        }
        self.staging_memory
            .read(metadata_offset, &mut metadata_bytes)
            .await?;

        let (metadata, _) = AuthManifestImageMetadata::read_from_prefix(&metadata_bytes)
            .map_err(|_| ErrorCode::Fail)?;
        Ok(metadata)
    }

    async fn validate_auth_manifest_soc_fw_id_set(
        &self,
        manifest_staging_mem_offset: usize,
        manifest_size: usize,
    ) -> Result<(), ErrorCode> {
        let entry_count = self
            .get_image_metadata_entry_count(manifest_staging_mem_offset, manifest_size)
            .await?;
        let mut manifest_soc_fw_id_count = 0usize;
        for i in 0..entry_count as usize {
            let metadata = self
                .get_image_metadata_by_index(manifest_staging_mem_offset, manifest_size, i)
                .await?;
            if metadata.fw_id != MCU_RT_IDENTIFIER {
                manifest_soc_fw_id_count = manifest_soc_fw_id_count
                    .checked_add(1)
                    .ok_or(ErrorCode::Fail)?;
                if !self.soc_image_load_fw_ids.contains(&metadata.fw_id) {
                    return Err(ErrorCode::Fail);
                }
            }
        }

        if manifest_soc_fw_id_count != self.soc_image_load_fw_ids.len() {
            return Err(ErrorCode::Fail);
        }

        for expected_fw_id in self.soc_image_load_fw_ids.iter().copied() {
            if !self
                .auth_manifest_contains_fw_id(
                    manifest_staging_mem_offset,
                    manifest_size,
                    entry_count,
                    expected_fw_id,
                )
                .await?
            {
                return Err(ErrorCode::Fail);
            }
        }

        Ok(())
    }

    async fn auth_manifest_contains_fw_id(
        &self,
        manifest_staging_mem_offset: usize,
        manifest_size: usize,
        entry_count: u32,
        fw_id: u32,
    ) -> Result<bool, ErrorCode> {
        for i in 0..entry_count as usize {
            let metadata = self
                .get_image_metadata_by_index(manifest_staging_mem_offset, manifest_size, i)
                .await?;
            if metadata.fw_id == fw_id {
                return Ok(true);
            }
        }
        Ok(false)
    }

    async fn process_caliptra_fw(
        &mut self,
        image_offset: usize,
        image_len: usize,
        action: CaliptraFwAction,
    ) -> Result<(), ErrorCode> {
        let cmd: u32 = match action {
            CaliptraFwAction::Verify => CommandId::FIRMWARE_VERIFY.into(),
            CaliptraFwAction::Load => CommandId::FIRMWARE_LOAD.into(),
        };

        let response_buffer = &mut [0u8; core::mem::size_of::<FirmwareVerifyResp>()];

        let mut payload_stream =
            MailboxPayloadStream::new(self.staging_memory, image_offset, image_len);

        loop {
            let result = self
                .mailbox
                .execute_with_payload_stream(cmd, None, &mut payload_stream, response_buffer)
                .await;
            match result {
                Ok(_) => break,
                Err(MailboxError::ErrorCode(ErrorCode::Busy)) => continue,
                Err(e) => {
                    console_writeln!(
                        Console::<DefaultSyscalls>::writer(),
                        "[FW Upd] ERROR: mailbox cmd={:#x} failed: {:?}",
                        cmd,
                        e
                    );
                    return Err(ErrorCode::Fail);
                }
            }
        }
        if action == CaliptraFwAction::Verify {
            let resp =
                FirmwareVerifyResp::ref_from_bytes(response_buffer).map_err(|_| ErrorCode::Fail)?;
            if resp.verify_result != FirmwareVerifyResult::Success as u32 {
                console_writeln!(
                    Console::<DefaultSyscalls>::writer(),
                    "[FW Upd] ERROR: FIRMWARE_VERIFY result={} (expected {})",
                    resp.verify_result,
                    FirmwareVerifyResult::Success as u32
                );
                return Err(ErrorCode::Fail);
            }
        }
        Ok(())
    }
    async fn update_caliptra(&mut self, flash_header: &FlashHeader) -> Result<(), ErrorCode> {
        console_writeln!(
            Console::<DefaultSyscalls>::writer(),
            "[FW Upd] Updating Caliptra"
        );
        let (image_offset, image_len) = self
            .get_image_toc(
                flash_header.image_count as usize,
                flash_header.image_headers_offset as usize,
                CALIPTRA_FMC_RT_IDENTIFIER,
            )
            .await
            .map_err(|_| ErrorCode::Fail)?;

        self.process_caliptra_fw(image_offset, image_len, CaliptraFwAction::Load)
            .await?;
        self.wait_caliptra_rt_execution().await
    }

    async fn verify_manifest(&mut self, offset: usize, len: usize) -> Result<(), ErrorCode> {
        let mut req = AuthManifestReqHeader {
            chksum: 0,
            manifest_size: len as u32,
        };

        let mut payload_stream = MailboxPayloadStream::new(self.staging_memory, offset, len);

        // Calculate the mailbox checksum
        let mut checksum = payload_stream.get_bytesum().await;
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
                let caliptra_axi_addr = ((resp.image_staging_address_high as u64) << 32)
                    | resp.image_staging_address_low as u64;
                self.dma_mapping.cptra_axi_to_mcu_axi(caliptra_axi_addr)
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
        if let Some(hooks) = self.hooks {
            hooks
                .transfer_to_dma_staging(
                    self.staging_memory,
                    self.dma_mapping,
                    mem_address,
                    offset,
                    img_size,
                )
                .await
        } else {
            default_copy_to_memory::<1024>(
                self.staging_memory,
                self.dma_mapping,
                mem_address,
                offset,
                img_size,
            )
            .await
        }
    }

    async fn verify_mcu_or_soc_image(
        &mut self,
        image_offset: usize,
        len: usize,
        metadata: &AuthManifestImageMetadata,
    ) -> Result<(), ErrorCode> {
        let mut hasher = HashContext::new();
        hasher
            .init(HashAlgoType::SHA384, None)
            .await
            .map_err(|_| ErrorCode::Fail)?;
        let mut buffer = [0u8; MAX_CRYPTO_MBOX_DATA_SIZE / 2]; // Size decreased to avoid stack overflow
        let mut hash = [0u8; 48]; // SHA-384 produces a 48-byte hash
        let mut total_bytes_read = 0;
        while total_bytes_read < len {
            let bytes_to_read = (len - total_bytes_read).min(MAX_CRYPTO_MBOX_DATA_SIZE / 2);
            self.staging_memory
                .read(
                    image_offset + total_bytes_read,
                    &mut buffer[..bytes_to_read],
                )
                .await
                .map_err(|_| ErrorCode::Fail)?;
            hasher
                .update(&buffer[..bytes_to_read])
                .await
                .map_err(|_| ErrorCode::Fail)?;
            total_bytes_read += bytes_to_read;
        }

        hasher
            .finalize(&mut hash)
            .await
            .map_err(|_| ErrorCode::Fail)?;

        // Compare the computed hash with the expected hash from the metadata
        if hash != metadata.digest {
            return Err(ErrorCode::Fail);
        }

        Ok(())
    }

    pub async fn update_mcu(&mut self, flash_header: &FlashHeader) -> Result<(), ErrorCode> {
        console_writeln!(
            Console::<DefaultSyscalls>::writer(),
            "[FW Upd] Updating MCU"
        );
        let (mcu_image_offset, mcu_image_len) = self
            .get_image_toc(
                flash_header.image_count as usize,
                flash_header.image_headers_offset as usize,
                MCU_RT_IDENTIFIER,
            )
            .await
            .map_err(|_| ErrorCode::Fail)?;

        // Get the DMA staging address for the MCU
        let staging_address = self
            .get_dma_image_staging_address(MCU_RT_IDENTIFIER)
            .await?;

        console_writeln!(
            Console::<DefaultSyscalls>::writer(),
            "[FW Upd] MCU update: staging_address={:#x}, mcu_image_offset={}, mcu_image_len={}",
            staging_address,
            mcu_image_offset,
            mcu_image_len
        );

        // Copy the firmware image to the MCU DMA staging area
        self.copy_to_memory(staging_address, mcu_image_offset, mcu_image_len)
            .await?;

        let mut req = ActivateFirmwareReq {
            hdr: MailboxReqHeader { chksum: 0 },
            fw_id_count: 1,
            fw_ids: {
                let mut fw_ids = [0u32; ActivateFirmwareReq::MAX_FW_ID_COUNT];
                fw_ids[0] = MCU_RT_IDENTIFIER;
                fw_ids
            },
            mcu_fw_image_size: mcu_image_len as u32,
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
    async fn image_valid(&self, img_sz: usize) -> Result<(), ErrorCode>;
    fn size(&self) -> usize;
}

/// Trait for platform-specific hooks invoked during the firmware update flow.
///
/// Platforms can implement this trait to inject SoC-specific actions at key
/// points in the update sequence (e.g., quiescing host I/O before activation).
/// All methods have default no-op implementations, so platforms only need to
/// override the hooks they care about.
#[async_trait]
pub trait FirmwareUpdateHooks: Send + Sync {
    /// Called when a firmware update request is received, before any flash I/O occurs.
    ///
    /// Platforms can implement this to apply rate-limiting or other policies that
    /// protect flash from wear-out attacks. Return `Ok(())` to allow the update
    /// to proceed, or `Err` to reject it.
    fn on_fw_update_request(&self, _component: &FirmwareComponent) -> Result<(), ErrorCode> {
        Ok(())
    }

    /// Called before updating the Caliptra firmware. Returning an error aborts the update.
    async fn pre_caliptra_activation(&self) -> Result<(), ErrorCode> {
        Ok(())
    }

    /// Called before setting the SoC authorization manifest. Returning an error aborts the update.
    async fn pre_auth_manifest_activation(&self) -> Result<(), ErrorCode> {
        Ok(())
    }

    /// Called before updating the MCU firmware and activating. Returning an error aborts the update.
    async fn pre_mcu_activation(&self) -> Result<(), ErrorCode> {
        Ok(())
    }

    /// Copy firmware image from staging memory to the destination address via DMA.
    /// Override this to control the transfer buffer size for your platform.
    async fn transfer_to_dma_staging(
        &self,
        staging_memory: &dyn StagingMemory,
        dma_mapping: &dyn DMAMapping,
        mem_address: AXIAddr,
        offset: usize,
        img_size: usize,
    ) -> Result<(), ErrorCode> {
        default_copy_to_memory::<1024>(staging_memory, dma_mapping, mem_address, offset, img_size)
            .await
    }
}

/// Default copy_to_memory implementation with configurable transfer buffer size.
pub async fn default_copy_to_memory<const TRANSFER_SIZE: usize>(
    staging_memory: &dyn StagingMemory,
    dma_mapping: &dyn DMAMapping,
    mem_address: AXIAddr,
    offset: usize,
    img_size: usize,
) -> Result<(), ErrorCode> {
    let dma_syscall: DMASyscall = DMASyscall::new();
    let mut remaining_size = img_size;
    let mut current_offset = offset;
    let mut current_address = mem_address;

    while remaining_size > 0 {
        let transfer_size = remaining_size.min(TRANSFER_SIZE);
        let mut buffer = [0u8; TRANSFER_SIZE];
        staging_memory
            .read(current_offset, &mut buffer[..transfer_size])
            .await?;

        // Print progress every 10KB
        if (current_offset - offset) % 10240 == 0 {
            console_writeln!(
                Console::<DefaultSyscalls>::writer(),
                "[FW Upd] copy_to_memory progress: {}/{} bytes",
                current_offset - offset,
                img_size
            );
        }

        let source_address = dma_mapping.mcu_sram_to_mcu_axi(buffer.as_ptr() as u32)?;
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

        if (self.cursor - self.offset) % 10240 == 0 {
            console_writeln!(
                Console::<DefaultSyscalls>::writer(),
                "[FW Upd] MailboxPayloadStream: read progress: {}/{} bytes",
                self.cursor - self.offset,
                self.len
            );
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

#[cfg(test)]
mod tests {
    use super::*;

    const A: u32 = 0x1000;
    const B: u32 = 0x2000;
    const C: u32 = 0x3000;
    const D: u32 = 0x4000;

    fn validate_soc_fw_id_same_set(
        cold_boot_soc_fw_ids: &[u32],
        manifest_soc_fw_ids: &[u32],
    ) -> Result<(), ErrorCode> {
        if cold_boot_soc_fw_ids.len() != manifest_soc_fw_ids.len() {
            return Err(ErrorCode::Fail);
        }

        for (index, fw_id) in manifest_soc_fw_ids.iter().copied().enumerate() {
            if manifest_soc_fw_ids
                .iter()
                .take(index)
                .any(|existing| *existing == fw_id)
            {
                return Err(ErrorCode::Fail);
            }
            if !cold_boot_soc_fw_ids.contains(&fw_id) {
                return Err(ErrorCode::Fail);
            }
        }

        Ok(())
    }

    #[test]
    fn validate_soc_fw_id_same_set_accepts_matching_sets() {
        for (cold_boot, manifest) in [
            (&[][..], &[][..]),
            (&[A][..], &[A][..]),
            (&[A, B][..], &[A, B][..]),
            (&[A, B][..], &[B, A][..]),
            (&[A, B, C][..], &[C, A, B][..]),
        ] {
            assert!(validate_soc_fw_id_same_set(cold_boot, manifest).is_ok());
        }
    }

    #[test]
    fn validate_soc_fw_id_same_set_rejects_mismatched_sets() {
        for (cold_boot, manifest) in [
            (&[][..], &[A][..]),
            (&[A][..], &[][..]),
            (&[A, B][..], &[A][..]),
            (&[A, B][..], &[A, B, C][..]),
            (&[A, B][..], &[A, C][..]),
            (&[A, B][..], &[C, A][..]),
            (&[A, B][..], &[A, A][..]),
            (&[A, B][..], &[B, B][..]),
            (&[A, B, C][..], &[A, B, B][..]),
            (&[A, B, C][..], &[A, B, D][..]),
        ] {
            assert!(validate_soc_fw_id_same_set(cold_boot, manifest).is_err());
        }
    }
}
