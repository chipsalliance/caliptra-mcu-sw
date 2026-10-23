// Licensed under the Apache-2.0 license

extern crate alloc;
mod pldm_client;
mod pldm_context;
mod pldm_fdops;

use alloc::boxed::Box;
use async_trait::async_trait;
use caliptra_api::mailbox::{
    ActivateFirmwareReq, ActivateFirmwareResp, CommandId, FirmwareVerifyResp, FirmwareVerifyResult,
    FwInfoResp, GetImageInfoReq, GetImageInfoResp, MailboxReqHeader, Request,
};
use caliptra_auth_man_types::{
    AuthManifestImageMetadata, AuthManifestImageMetadataCollection, AuthorizationManifest,
    OwnerAuthManifestImageMetadataCollection, OwnerAuthorizationManifest,
};
use caliptra_image_types::ImageManifest;
use caliptra_mcu_flash_image::{
    FlashHeader, ImageHeader, CALIPTRA_FMC_RT_IDENTIFIER, MAX_FLASH_HEADER_SIZE,
    MAX_IMAGE_HEADER_SIZE, MCU_RT_IDENTIFIER, OWNER_AUTH_MANIFEST_IDENTIFIER,
    SOC_MANIFEST_IDENTIFIER, V_AUTH_KEY_ID,
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
pub use caliptra_mcu_pldm_common::message::firmware_update::apply_complete::ApplyOutcome;
use caliptra_mcu_pldm_common::message::firmware_update::get_fw_params::FirmwareParameters;
use caliptra_mcu_pldm_common::message::firmware_update::verify_complete::VerifyResult;
use caliptra_mcu_pldm_common::protocol::firmware_update::Descriptor;
use caliptra_mcu_pldm_common::util::fw_component::FirmwareComponent;
use caliptra_mcu_pldm_lib::daemon::PldmService;
use embassy_executor::Spawner;
use pldm_client::pldm_total_component_size;
use pldm_context::State;
use zerocopy::{FromBytes, IntoBytes};

use caliptra_mcu_libsyscall_caliptra::DefaultSyscalls;
use caliptra_mcu_libtock_console::Console;
use core::fmt::Write;
use core::mem::offset_of;

use crate::{
    sha_finish, sha_init, sha_update, HashAlgo, ScratchAlloc, SHA_CHUNK_SIZE, SHA_CONTEXT_SIZE,
};

pub struct FirmwareUpdater<'a, D: DMAMapping, A: ScratchAlloc> {
    staging_memory: &'static dyn StagingMemory,
    alloc: &'a A,
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

impl<'a, D: DMAMapping, A: ScratchAlloc> FirmwareUpdater<'a, D, A> {
    pub fn new(
        staging_memory: &'static dyn StagingMemory,
        alloc: &'a A,
        params: &'a PldmFirmwareDeviceParams,
        soc_image_load_fw_ids: &'a [u32],
        dma_mapping: &'a D,
        spawner: Spawner,
        hooks: Option<&'a dyn FirmwareUpdateHooks>,
    ) -> Self {
        Self {
            staging_memory,
            alloc,
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

        let img_len = pldm_total_component_size();
        let outcome = apply_image(self.staging_memory, self.hooks, img_len).await?;

        pldm_client::pldm_report_apply_outcome(outcome).await?;
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
        let header = self.read_flash_header().await?;
        if num_images != header.image_count as usize
            || image_headers_offset != header.image_headers_offset as usize
        {
            return Err(ErrorCode::Invalid);
        }
        for index in 0..num_images {
            let image_header = self.read_image_header(&header, index).await?;
            if image_header.identifier == image_id {
                return Ok((image_header.offset as usize, image_header.size as usize));
            }
        }

        Err(ErrorCode::Fail)
    }

    pub async fn get_image_toc_by_index(
        &self,
        num_images: usize,
        image_headers_offset: usize,
        index: usize,
    ) -> Result<ImageHeader, ErrorCode> {
        let header = self.read_flash_header().await?;
        if num_images != header.image_count as usize
            || image_headers_offset != header.image_headers_offset as usize
        {
            return Err(ErrorCode::Invalid);
        }
        self.read_image_header(&header, index).await
    }

    async fn read_flash_header(&self) -> Result<FlashHeader, ErrorCode> {
        let mut bytes = [0; MAX_FLASH_HEADER_SIZE];
        self.staging_memory.read(0, &mut bytes).await?;
        FlashHeader::parse(&bytes).map_err(|error| {
            console_writeln!(
                Console::<DefaultSyscalls>::writer(),
                "[FW Upd] Invalid flash header: {:?}",
                error
            );
            ErrorCode::Invalid
        })
    }

    async fn read_image_header(
        &self,
        header: &FlashHeader,
        index: usize,
    ) -> Result<ImageHeader, ErrorCode> {
        let version = header.format().map_err(|_| ErrorCode::Invalid)?;
        let offset = header.image_header_offset(index).ok_or(ErrorCode::Size)?;
        let mut bytes = [0; MAX_IMAGE_HEADER_SIZE];
        self.staging_memory
            .read(offset, &mut bytes[..version.image_header_size()])
            .await?;
        ImageHeader::parse(&bytes, version).map_err(|error| {
            console_writeln!(
                Console::<DefaultSyscalls>::writer(),
                "[FW Upd] Invalid image header {}: {:?}",
                index,
                error
            );
            ErrorCode::Invalid
        })
    }

    fn check_rom_compatibility(header: &FlashHeader) -> Result<(), ErrorCode> {
        use caliptra_mcu_libsyscall_caliptra::system::System;
        let rom_version = match System::mcu_rom_version() {
            Ok(version) => Some(version),
            Err(ErrorCode::NoSupport) => None,
            Err(error) => {
                console_writeln!(
                    Console::<DefaultSyscalls>::writer(),
                    "[FW Upd] Unable to read ROM version: {:?}",
                    error
                );
                return Err(error);
            }
        };
        if !header
            .format()
            .map_err(|_| ErrorCode::Invalid)?
            .supports_rom(rom_version)
        {
            console_writeln!(
                Console::<DefaultSyscalls>::writer(),
                "[FW Upd] Flash format {} incompatible with ROM {:?}",
                header.version,
                rom_version
            );
            return Err(ErrorCode::NoSupport);
        }
        Ok(())
    }

    pub async fn update_mcu_with_auth_manifest(
        &mut self,
        flash_header: &FlashHeader,
    ) -> Result<(), ErrorCode> {
        Self::check_rom_compatibility(flash_header)?;
        self.set_auth_manifest().await?;
        self.update_mcu(flash_header).await
    }

    async fn set_auth_manifest(&mut self) -> Result<(), ErrorCode> {
        let flash_header = self.read_flash_header().await?;
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
        self.validate_auth_manifest_soc_fw_id_set(&StagedAuthManifest::soc(
            manifest_offset,
            manifest_len,
        ))
        .await?;

        let mut payload_stream =
            MailboxPayloadStream::new(self.staging_memory, manifest_offset, manifest_len);
        crate::image_loader::execute_auth_manifest_command(
            &self.mailbox,
            CommandId::SET_AUTH_MANIFEST,
            &mut payload_stream,
            manifest_len as u32,
        )
        .await
    }

    async fn verify(&mut self) -> Result<FlashHeader, ErrorCode> {
        // Parse the downloaded firmware image
        let flash_header = self.read_flash_header().await?;
        Self::check_rom_compatibility(&flash_header)?;
        let table_end = flash_header.table_end().ok_or(ErrorCode::Size)?;
        let staging_len = self.staging_memory.size();
        if table_end > staging_len {
            console_writeln!(
                Console::<DefaultSyscalls>::writer(),
                "[FW Upd] Image table exceeds staging area"
            );
            return Err(ErrorCode::Size);
        }
        for index in 0..flash_header.image_count as usize {
            let image = self.read_image_header(&flash_header, index).await?;
            let end = (image.offset as usize)
                .checked_add(image.size as usize)
                .ok_or(ErrorCode::Size)?;
            if (image.offset as usize) < table_end || end > staging_len {
                console_writeln!(
                    Console::<DefaultSyscalls>::writer(),
                    "[FW Upd] Image {} outside staging payload",
                    index
                );
                return Err(ErrorCode::Size);
            }
        }

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
        let soc_manifest = StagedAuthManifest::soc(manifest_offset, manifest_len);
        self.validate_auth_manifest_soc_fw_id_set(&soc_manifest)
            .await?;

        // Verify the staged Owner Auth Manifest, if the package carries one.
        let owner_manifest = self.get_staged_owner_manifest(&flash_header).await;
        if let Some(owner_manifest) = &owner_manifest {
            console_writeln!(
                Console::<DefaultSyscalls>::writer(),
                "[FW Upd] Verifying Owner Manifest"
            );
            self.verify_owner_manifest(owner_manifest.offset, owner_manifest.len)
                .await?;
        }

        for i in 0..flash_header.image_count as usize {
            let image_header = self
                .get_image_toc_by_index(
                    flash_header.image_count as usize,
                    flash_header.image_headers_offset as usize,
                    i,
                )
                .await?;

            if verified_by_caliptra_command(image_header.identifier) {
                continue;
            }

            let metadata = self
                .get_toc_entry_metadata(
                    &soc_manifest,
                    owner_manifest.as_ref(),
                    image_header.identifier,
                )
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
    /// Also compares MCU RT, SoC and owner image digests against the staged
    /// SoC and Owner Auth Manifests.
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

        // Read FMC and Runtime digests directly from staging memory at known offsets,
        // avoiding allocation of the full ~16KB ImageManifest.
        use caliptra_image_types::ImageTocEntry;

        let fmc_digest_offset =
            cptra_image_offset + offset_of!(ImageManifest, fmc) + offset_of!(ImageTocEntry, digest);
        let mut fmc_digest = [0u32; 12];
        self.staging_memory
            .read(fmc_digest_offset, fmc_digest.as_mut_bytes())
            .await?;

        let rt_digest_offset = cptra_image_offset
            + offset_of!(ImageManifest, runtime)
            + offset_of!(ImageTocEntry, digest);
        let mut rt_digest = [0u32; 12];
        self.staging_memory
            .read(rt_digest_offset, rt_digest.as_mut_bytes())
            .await?;

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
        if fmc_digest != fw_info.fmc_sha384_digest {
            console_writeln!(
                Console::<DefaultSyscalls>::writer(),
                "[FW Upd] FMC digest mismatch"
            );
            return Err(ErrorCode::Fail);
        }

        // Compare RT digests
        if rt_digest != fw_info.runtime_sha384_digest {
            console_writeln!(
                Console::<DefaultSyscalls>::writer(),
                "[FW Upd] RT digest mismatch"
            );
            return Err(ErrorCode::Fail);
        }

        // 2. Verify MCU RT, SoC and owner image digests against the staged auth manifests
        let (manifest_offset, manifest_len) = self
            .get_image_toc(
                flash_header.image_count as usize,
                flash_header.image_headers_offset as usize,
                SOC_MANIFEST_IDENTIFIER,
            )
            .await?;
        let soc_manifest = StagedAuthManifest::soc(manifest_offset, manifest_len);
        let owner_manifest = self.get_staged_owner_manifest(flash_header).await;

        for i in 0..flash_header.image_count as usize {
            let image_header = self
                .get_image_toc_by_index(
                    flash_header.image_count as usize,
                    flash_header.image_headers_offset as usize,
                    i,
                )
                .await?;

            if verified_by_caliptra_command(image_header.identifier) {
                continue;
            }

            // Compute SHA-384 of the downloaded image
            let hash_context = self
                .alloc
                .alloc(SHA_CONTEXT_SIZE)
                .map_err(|_| ErrorCode::Fail)?;
            let mut hasher = sha_init(self.alloc, hash_context, HashAlgo::Sha384, &[])
                .await
                .map_err(|_| ErrorCode::Fail)?;
            let mut buffer = [0u8; SHA_CHUNK_SIZE];
            let mut total_bytes_read = 0;
            let img_offset = image_header.offset as usize;
            let img_size = image_header.size as usize;
            while total_bytes_read < img_size {
                let bytes_to_read = (img_size - total_bytes_read).min(SHA_CHUNK_SIZE);
                self.staging_memory
                    .read(img_offset + total_bytes_read, &mut buffer[..bytes_to_read])
                    .await?;
                sha_update(self.alloc, &mut hasher, &buffer[..bytes_to_read])
                    .await
                    .map_err(|_| ErrorCode::Fail)?;
                total_bytes_read += bytes_to_read;
            }
            let mut hash = [0u8; 48];
            sha_finish(self.alloc, &mut hasher, &mut hash)
                .await
                .map_err(|_| ErrorCode::Fail)?;

            // Compare against the digest in the staged auth manifest
            let metadata = self
                .get_toc_entry_metadata(
                    &soc_manifest,
                    owner_manifest.as_ref(),
                    image_header.identifier,
                )
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

    /// Find the metadata entry authorizing a staged TOC entry. TOC entries are
    /// keyed by `component_id`, so the lookup matches on `component_id`.
    pub async fn get_image_metadata(
        &self,
        manifest: &StagedAuthManifest,
        component_id: u32,
    ) -> Result<Option<AuthManifestImageMetadata>, ErrorCode> {
        let entry_count = self.get_image_metadata_entry_count(manifest).await?;

        for i in 0..entry_count as usize {
            let metadata = self.get_image_metadata_by_index(manifest, i).await?;

            if metadata.component_id == component_id {
                return Ok(Some(metadata));
            }
        }

        Ok(None)
    }

    /// Resolve the metadata for a staged TOC entry from the staged SoC (vendor)
    /// auth manifest first, then from the staged Owner Auth Manifest (if any).
    async fn get_toc_entry_metadata(
        &self,
        soc_manifest: &StagedAuthManifest,
        owner_manifest: Option<&StagedAuthManifest>,
        component_id: u32,
    ) -> Result<AuthManifestImageMetadata, ErrorCode> {
        if let Some(metadata) = self.get_image_metadata(soc_manifest, component_id).await? {
            return Ok(metadata);
        }
        if let Some(owner_manifest) = owner_manifest {
            if let Some(metadata) = self
                .get_image_metadata(owner_manifest, component_id)
                .await?
            {
                return Ok(metadata);
            }
        }
        console_writeln!(
            Console::<DefaultSyscalls>::writer(),
            "[FW Upd] Image 0x{:x} not listed in any staged auth manifest",
            component_id
        );
        Err(ErrorCode::Fail)
    }

    async fn get_image_metadata_entry_count(
        &self,
        manifest: &StagedAuthManifest,
    ) -> Result<u32, ErrorCode> {
        let entry_count_offset = manifest.offset + manifest.kind.entry_count_offset();
        if entry_count_offset + 4 > manifest.offset + manifest.len {
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
        manifest: &StagedAuthManifest,
        index: usize,
    ) -> Result<AuthManifestImageMetadata, ErrorCode> {
        let metadata_offset = manifest.offset
            + manifest.kind.metadata_list_offset()
            + index * core::mem::size_of::<AuthManifestImageMetadata>();
        let mut metadata_bytes = [0u8; core::mem::size_of::<AuthManifestImageMetadata>()];
        if metadata_offset + metadata_bytes.len() > manifest.offset + manifest.len {
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
        manifest: &StagedAuthManifest,
    ) -> Result<(), ErrorCode> {
        let entry_count = self.get_image_metadata_entry_count(manifest).await?;
        let mut manifest_soc_fw_id_count = 0usize;
        for i in 0..entry_count as usize {
            let metadata = self.get_image_metadata_by_index(manifest, i).await?;
            // The Vendor Authorization Key entry anchors a key digest; it is
            // not a loadable SoC image.
            if metadata.fw_id != MCU_RT_IDENTIFIER && metadata.fw_id != V_AUTH_KEY_ID {
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
                .auth_manifest_contains_fw_id(manifest, entry_count, expected_fw_id)
                .await?
            {
                return Err(ErrorCode::Fail);
            }
        }

        Ok(())
    }

    async fn auth_manifest_contains_fw_id(
        &self,
        manifest: &StagedAuthManifest,
        entry_count: u32,
        fw_id: u32,
    ) -> Result<bool, ErrorCode> {
        for i in 0..entry_count as usize {
            let metadata = self.get_image_metadata_by_index(manifest, i).await?;
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
        let mut payload_stream = MailboxPayloadStream::new(self.staging_memory, offset, len);
        crate::image_loader::execute_auth_manifest_command(
            &self.mailbox,
            CommandId::VERIFY_AUTH_MANIFEST,
            &mut payload_stream,
            len as u32,
        )
        .await
    }

    /// Verify a staged Owner Auth Manifest without replacing the active one.
    async fn verify_owner_manifest(&mut self, offset: usize, len: usize) -> Result<(), ErrorCode> {
        let mut payload_stream = MailboxPayloadStream::new(self.staging_memory, offset, len);
        crate::image_loader::execute_auth_manifest_command(
            &self.mailbox,
            CommandId::VERIFY_OWNER_AUTH_MANIFEST,
            &mut payload_stream,
            len as u32,
        )
        .await
    }

    /// Locate the Owner Auth Manifest in the staged package, if present.
    async fn get_staged_owner_manifest(
        &self,
        flash_header: &FlashHeader,
    ) -> Option<StagedAuthManifest> {
        self.get_image_toc(
            flash_header.image_count as usize,
            flash_header.image_headers_offset as usize,
            OWNER_AUTH_MANIFEST_IDENTIFIER,
        )
        .await
        .ok()
        .map(|(offset, len)| StagedAuthManifest::owner(offset, len))
    }

    async fn get_dma_image_staging_address(&self, image_id: u32) -> Result<AXIAddr, ErrorCode> {
        let mut req = GetImageInfoReq {
            hdr: MailboxReqHeader::default(),
            fw_id: image_id.to_le_bytes(),
            flags: 0,
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
        let hash_context = self
            .alloc
            .alloc(SHA_CONTEXT_SIZE)
            .map_err(|_| ErrorCode::Fail)?;
        let mut hasher = sha_init(self.alloc, hash_context, HashAlgo::Sha384, &[])
            .await
            .map_err(|_| ErrorCode::Fail)?;
        let mut buffer = [0u8; SHA_CHUNK_SIZE];
        let mut hash = [0u8; 48]; // SHA-384 produces a 48-byte hash
        let mut total_bytes_read = 0;
        while total_bytes_read < len {
            let bytes_to_read = (len - total_bytes_read).min(SHA_CHUNK_SIZE);
            self.staging_memory
                .read(
                    image_offset + total_bytes_read,
                    &mut buffer[..bytes_to_read],
                )
                .await
                .map_err(|_| ErrorCode::Fail)?;
            sha_update(self.alloc, &mut hasher, &buffer[..bytes_to_read])
                .await
                .map_err(|_| ErrorCode::Fail)?;
            total_bytes_read += bytes_to_read;
        }

        sha_finish(self.alloc, &mut hasher, &mut hash)
            .await
            .map_err(|_| ErrorCode::Fail)?;

        // Compare the computed hash with the expected hash from the metadata
        if hash != metadata.digest {
            return Err(ErrorCode::Fail);
        }

        Ok(())
    }

    pub async fn update_mcu(&mut self, flash_header: &FlashHeader) -> Result<(), ErrorCode> {
        Self::check_rom_compatibility(flash_header)?;
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
            flags: 0,
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

async fn apply_image(
    staging_memory: &dyn StagingMemory,
    hooks: Option<&dyn FirmwareUpdateHooks>,
    img_len: usize,
) -> Result<ApplyOutcome, ErrorCode> {
    staging_memory.image_valid(img_len).await?;
    Ok(match hooks {
        Some(hooks) => hooks.post_apply().await,
        None => ApplyOutcome::default(),
    })
}

/// Trait for platform-specific hooks invoked during the firmware update flow.
///
/// Platforms can implement this trait to inject SoC-specific actions at key
/// points in the update sequence (e.g., quiescing host I/O before activation).
/// Methods default to the standard update behavior, so platforms only need to
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

    /// Called after `image_valid()` succeeds and before reporting ApplyComplete.
    ///
    /// Return `ApplySuccessWithActivationMethod` and the required activation
    /// methods when activation requirements change (for example, System Reboot
    /// when a hitless update is unsafe). The default is ApplySuccess with no
    /// modification. A failure result is reported to the update agent and aborts
    /// the update before activation. The updater waits for the ApplyComplete
    /// transaction before returning a failure, with a bounded reporting timeout.
    async fn post_apply(&self) -> ApplyOutcome {
        ApplyOutcome::default()
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
        if (current_offset - offset).is_multiple_of(10240) {
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
}

#[async_trait(?Send)]
impl PayloadStream for MailboxPayloadStream {
    fn size(&self) -> usize {
        self.len
    }

    fn reset(&mut self) {
        self.cursor = self.offset;
    }

    async fn read(&mut self, buffer: &mut [u8]) -> Result<usize, ErrorCode> {
        if (self.cursor - self.offset) >= self.len {
            return Ok(0); // No more data to read
        }

        if (self.cursor - self.offset).is_multiple_of(10240) {
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

pub use crate::image_loader::AuthManifestReqHeader;

/// Whether a flash image's digest is carried by the SoC authorization manifest.
///
/// The Caliptra bundle is checked by FIRMWARE_VERIFY and the SoC manifest by
/// VERIFY_AUTH_MANIFEST. The owner authorization manifest is authenticated by
/// Caliptra when it is installed with SET_OWNER_AUTH_MANIFEST at boot, and the
/// owner measurement policy digest is checked against that manifest; neither has
/// an entry in the SoC manifest. Owner SoC images are authorized against the
/// owner authorization manifest when they are loaded, so they are not listed in
/// the SoC manifest either.
/// TOC entries that are verified by dedicated Caliptra commands rather than by
/// a digest in an auth manifest: the Caliptra FMC+RT bundle, the SoC (vendor)
/// auth manifest and the Owner Auth Manifest. Every other TOC entry must be
/// listed (by component_id) in the staged SoC or Owner Auth Manifest.
fn verified_by_caliptra_command(identifier: u32) -> bool {
    matches!(
        identifier,
        CALIPTRA_FMC_RT_IDENTIFIER | SOC_MANIFEST_IDENTIFIER | OWNER_AUTH_MANIFEST_IDENTIFIER
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AuthManifestKind {
    Soc,
    Owner,
}

impl AuthManifestKind {
    fn entry_count_offset(self) -> usize {
        match self {
            AuthManifestKind::Soc => {
                offset_of!(AuthorizationManifest, image_metadata_col)
                    + offset_of!(AuthManifestImageMetadataCollection, entry_count)
            }
            AuthManifestKind::Owner => {
                offset_of!(OwnerAuthorizationManifest, image_metadata_col)
                    + offset_of!(OwnerAuthManifestImageMetadataCollection, entry_count)
            }
        }
    }

    fn metadata_list_offset(self) -> usize {
        match self {
            AuthManifestKind::Soc => {
                offset_of!(AuthorizationManifest, image_metadata_col)
                    + offset_of!(AuthManifestImageMetadataCollection, image_metadata_list)
            }
            AuthManifestKind::Owner => {
                offset_of!(OwnerAuthorizationManifest, image_metadata_col)
                    + offset_of!(
                        OwnerAuthManifestImageMetadataCollection,
                        image_metadata_list
                    )
            }
        }
    }
}

/// An auth manifest located in staging memory.
#[derive(Clone, Copy, Debug)]
pub struct StagedAuthManifest {
    kind: AuthManifestKind,
    offset: usize,
    len: usize,
}

impl StagedAuthManifest {
    pub fn soc(offset: usize, len: usize) -> Self {
        Self {
            kind: AuthManifestKind::Soc,
            offset,
            len,
        }
    }

    pub fn owner(offset: usize, len: usize) -> Self {
        Self {
            kind: AuthManifestKind::Owner,
            offset,
            len,
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use caliptra_mcu_flash_image::{
        OWNER_MEASUREMENT_POLICY_IDENTIFIER, OWNER_SOC_IMAGES_BASE_IDENTIFIER,
    };
    use caliptra_mcu_pldm_common::message::firmware_update::apply_complete::ApplyResult;
    use caliptra_mcu_pldm_common::protocol::firmware_update::ComponentActivationMethods;
    use core::future::Future;
    use core::sync::atomic::{AtomicBool, Ordering};
    use core::task::{Context, Poll, Waker};

    static PLDM_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn run_ready<F: Future>(future: F) -> F::Output {
        let mut future = core::pin::pin!(future);
        match future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
        {
            Poll::Ready(output) => output,
            Poll::Pending => panic!("test future unexpectedly yielded"),
        }
    }

    #[derive(Debug)]
    struct TestStagingMemory {
        valid: AtomicBool,
        fail: bool,
    }

    #[async_trait]
    impl StagingMemory for TestStagingMemory {
        async fn write(&self, _offset: usize, _data: &[u8]) -> Result<(), ErrorCode> {
            unreachable!()
        }

        async fn read(&self, _offset: usize, _data: &mut [u8]) -> Result<(), ErrorCode> {
            unreachable!()
        }

        async fn image_valid(&self, img_sz: usize) -> Result<(), ErrorCode> {
            assert_eq!(img_sz, 1024);
            if self.fail {
                return Err(ErrorCode::Fail);
            }
            self.valid.store(true, Ordering::SeqCst);
            Ok(())
        }

        fn size(&self) -> usize {
            1024
        }
    }

    struct DefaultHooks;

    #[async_trait]
    impl FirmwareUpdateHooks for DefaultHooks {}

    struct RebootHooks<'a> {
        staging: &'a TestStagingMemory,
        called: AtomicBool,
    }

    #[async_trait]
    impl FirmwareUpdateHooks for RebootHooks<'_> {
        async fn post_apply(&self) -> ApplyOutcome {
            assert!(self.staging.valid.load(Ordering::SeqCst));
            self.called.store(true, Ordering::SeqCst);
            let mut activation_methods = ComponentActivationMethods(0);
            activation_methods.set_system_reboot(true);
            ApplyOutcome {
                result: ApplyResult::ApplySuccessWithActivationMethod,
                activation_methods,
            }
        }
    }

    #[test]
    fn apply_image_defaults_to_success_without_modification() {
        for hooks in [None, Some(&DefaultHooks as &dyn FirmwareUpdateHooks)] {
            let staging = TestStagingMemory {
                valid: AtomicBool::new(false),
                fail: false,
            };
            let outcome = run_ready(apply_image(&staging, hooks, 1024)).unwrap();
            assert!(staging.valid.load(Ordering::SeqCst));
            assert_eq!(outcome.result, ApplyResult::ApplySuccess);
            assert_eq!(outcome.activation_methods.0, 0);
        }
    }

    #[test]
    fn apply_hook_runs_only_after_image_valid_and_reaches_fd_ops() {
        use caliptra_mcu_pldm_common::message::firmware_update::get_status::ProgressPercent;
        use caliptra_mcu_pldm_lib::firmware_device::fd_ops::FdOps;

        let _guard = PLDM_TEST_LOCK.lock().unwrap();
        for fail in [false, true] {
            let staging = TestStagingMemory {
                valid: AtomicBool::new(false),
                fail,
            };
            let hooks = RebootHooks {
                staging: &staging,
                called: AtomicBool::new(false),
            };
            let outcome = run_ready(apply_image(&staging, Some(&hooks), 1024));
            assert_eq!(hooks.called.load(Ordering::SeqCst), !fail);
            if fail {
                assert_eq!(outcome, Err(ErrorCode::Fail));
            } else {
                let outcome = outcome.unwrap();
                assert_eq!(outcome.result as u8, 0x01);
                assert_eq!(outcome.activation_methods.0, 0x0008);
                pldm_client::pldm_set_apply_outcome(outcome);
                let mut progress = ProgressPercent::default();
                let fd_outcome = run_ready(
                    pldm_fdops::UpdateFdOps::new()
                        .apply_outcome(&FirmwareComponent::default(), &mut progress),
                )
                .unwrap();
                assert_eq!(fd_outcome, outcome);
                assert_eq!(progress.value(), 100);
            }
        }
    }

    #[test]
    fn apply_failure_waits_for_reporting_or_timeout_before_returning() {
        use caliptra_mcu_libtock_platform::Syscalls;
        use caliptra_mcu_libtock_unittest::fake;
        use caliptra_mcu_pldm_lib::firmware_device::fd_ops::FdOps;
        use core::cell::Cell;

        let _guard = PLDM_TEST_LOCK.lock().unwrap();
        let kernel = fake::Kernel::new();
        let alarm = fake::Alarm::new(1000);
        kernel.add_driver(&alarm);
        let console = fake::Console::new();
        kernel.add_driver(&console);
        let ops = pldm_fdops::UpdateFdOps::new();
        let failure = ApplyOutcome {
            result: ApplyResult::ApplyGenericError,
            ..ApplyOutcome::default()
        };
        let mut cx = Context::from_waker(Waker::noop());

        for reporting_result in [Ok(()), Err(caliptra_mcu_pldm_lib::errors::TRANSPORT_ERROR)] {
            // A stale notification must not let a new failed update exit early.
            ops.apply_complete_reported(Ok(()));
            let activation_called = Cell::new(false);
            let mut updater = core::pin::pin!(async {
                pldm_client::pldm_report_apply_outcome(failure).await?;
                activation_called.set(true);
                Ok::<(), ErrorCode>(())
            });
            assert!(updater.as_mut().poll(&mut cx).is_pending());
            assert!(updater.as_mut().poll(&mut cx).is_pending());
            ops.apply_complete_reported(reporting_result);
            fake::Syscalls::yield_no_wait();
            assert_eq!(
                updater.as_mut().poll(&mut cx),
                Poll::Ready(Err(ErrorCode::Fail))
            );
            assert!(!activation_called.get());
        }

        for result in [
            ApplyResult::ApplySuccess,
            ApplyResult::ApplySuccessWithActivationMethod,
        ] {
            assert_eq!(
                run_ready(pldm_client::pldm_report_apply_outcome(ApplyOutcome {
                    result,
                    ..ApplyOutcome::default()
                })),
                Ok(())
            );
        }

        // An unresponsive update agent must not keep the application alive forever.
        let mut updater = core::pin::pin!(pldm_client::pldm_report_apply_outcome(failure));
        assert!(updater.as_mut().poll(&mut cx).is_pending());
        for _ in 0..caliptra_mcu_pldm_lib::config::DEFAULT_FD_T1_TIMEOUT / 10 - 1 {
            fake::Syscalls::yield_no_wait();
            assert!(updater.as_mut().poll(&mut cx).is_pending());
        }
        fake::Syscalls::yield_no_wait();
        assert_eq!(
            updater.as_mut().poll(&mut cx),
            Poll::Ready(Err(ErrorCode::Fail))
        );
    }

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
    fn only_caliptra_verified_artifacts_skip_manifest_digest_check() {
        for identifier in [
            CALIPTRA_FMC_RT_IDENTIFIER,
            SOC_MANIFEST_IDENTIFIER,
            OWNER_AUTH_MANIFEST_IDENTIFIER,
        ] {
            assert!(verified_by_caliptra_command(identifier));
        }
        for identifier in [
            MCU_RT_IDENTIFIER,
            OWNER_MEASUREMENT_POLICY_IDENTIFIER,
            A,
            OWNER_SOC_IMAGES_BASE_IDENTIFIER,
            u32::MAX,
        ] {
            assert!(!verified_by_caliptra_command(identifier));
        }
    }

    #[test]
    fn staged_manifest_metadata_offsets_match_manifest_layouts() {
        let soc = AuthManifestKind::Soc;
        let owner = AuthManifestKind::Owner;
        assert_eq!(
            soc.metadata_list_offset() - soc.entry_count_offset(),
            core::mem::size_of::<u32>()
        );
        assert_eq!(
            owner.metadata_list_offset() - owner.entry_count_offset(),
            core::mem::size_of::<u32>()
        );
        assert_eq!(
            soc.entry_count_offset(),
            core::mem::size_of::<caliptra_auth_man_types::AuthManifestPreamble>()
        );
        assert_eq!(
            owner.entry_count_offset(),
            core::mem::size_of::<caliptra_auth_man_types::OwnerAuthManifestPreamble>()
        );
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
