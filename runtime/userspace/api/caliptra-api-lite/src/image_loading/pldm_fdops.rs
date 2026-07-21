// Licensed under the Apache-2.0 license

extern crate alloc;

use alloc::boxed::Box;
use caliptra_mcu_flash_image::{FlashHeader, ImageHeader};
use caliptra_mcu_libsyscall_caliptra::dma::{
    AXIAddr, DMAMapping, DMASource, DMATransaction, DMA as DMASyscall,
};
use caliptra_mcu_pldm_common::message::firmware_update::apply_complete::ApplyResult;
use caliptra_mcu_pldm_common::message::firmware_update::get_fw_params::FirmwareParameters;
use caliptra_mcu_pldm_common::message::firmware_update::get_status::ProgressPercent;
use caliptra_mcu_pldm_common::message::firmware_update::request_fw_data::MAX_PLDM_FW_DATA_SIZE;
use caliptra_mcu_pldm_common::message::firmware_update::transfer_complete::TransferResult;
use caliptra_mcu_pldm_common::message::firmware_update::verify_complete::VerifyResult;
use caliptra_mcu_pldm_common::protocol::firmware_update::{
    ComponentResponseCode, Descriptor, PLDM_FWUP_BASELINE_TRANSFER_SIZE,
};
use caliptra_mcu_pldm_common::util::fw_component::FirmwareComponent;
use caliptra_mcu_pldm_lib::errors as pldm_errors;
use caliptra_mcu_pldm_lib::firmware_device::fd_ops::{ComponentOperation, FdOps};
use mcu_error::McuResult;

use super::pldm_client::{IMAGE_LOADING_TASK_YIELD, PLDM_TASK_YIELD};
use super::pldm_context::{State, DOWNLOAD_CTX, PLDM_STATE};

pub struct StreamingFdOps<'a> {
    descriptors: &'a [Descriptor],
    fw_params: &'a FirmwareParameters,
    dma_mapping: &'a dyn DMAMapping,
}

impl<'a> StreamingFdOps<'a> {
    /// Creates a new instance of the StreamingFdOps.
    pub const fn new(
        descriptors: &'a [Descriptor],
        fw_params: &'a FirmwareParameters,
        dma_mapping: &'a dyn DMAMapping,
    ) -> Self {
        Self {
            descriptors,
            fw_params,
            dma_mapping,
        }
    }

    async fn copy_buffer_to_load_address(
        &self,
        load_address: AXIAddr,
        offset: usize,
        data: &[u8],
        dma_mapping: &dyn DMAMapping,
    ) -> McuResult<()> {
        let dma_syscall: DMASyscall = DMASyscall::new();
        let source_address = dma_mapping
            .mcu_sram_to_mcu_axi(data.as_ptr() as u32)
            .map_err(|_| pldm_errors::FW_DOWNLOAD_ERROR)?;

        let dest_addr = load_address
            .checked_add(offset as u64)
            .ok_or(pldm_errors::FW_DOWNLOAD_ERROR)?;
        let transaction = DMATransaction {
            byte_count: data.len(),
            source: DMASource::Address(source_address),
            dest_addr,
        };
        dma_syscall
            .xfer(&transaction)
            .await
            .map_err(|_| pldm_errors::FW_DOWNLOAD_ERROR)?;

        Ok(())
    }

    async fn copy_data_to_buffer(&self, _offset: usize, data: &[u8]) -> McuResult<()> {
        let state = PLDM_STATE.lock(|state| *state.borrow());
        let dma_params = DOWNLOAD_CTX.lock(|ctx| -> McuResult<Option<(AXIAddr, usize)>> {
            let mut ctx = ctx.borrow_mut();
            ctx.total_downloaded = ctx
                .total_downloaded
                .checked_add(data.len())
                .ok_or(pldm_errors::FW_DOWNLOAD_ERROR)?;
            let start = ctx
                .current_offset
                .checked_sub(ctx.initial_offset)
                .ok_or(pldm_errors::FW_DOWNLOAD_ERROR)?;

            if state == State::DownloadingHeader {
                copy_prefix_chunk(&mut ctx.header, start, data)?;
            } else if state == State::DownloadingToc {
                copy_prefix_chunk(&mut ctx.image_info, start, data)?;
            } else if state == State::DownloadingImage {
                return Ok(Some((ctx.load_address, start)));
            }

            Ok(None)
        })?;
        if let Some(dma_params) = dma_params {
            return self
                .copy_buffer_to_load_address(dma_params.0, dma_params.1, data, self.dma_mapping)
                .await;
        }
        Ok(())
    }
}

#[async_trait::async_trait(?Send)]
impl FdOps for StreamingFdOps<'_> {
    fn get_device_identifiers(&self, device_identifiers: &mut [Descriptor]) -> McuResult<usize> {
        self.descriptors
            .iter()
            .enumerate()
            .for_each(|(i, descriptor)| {
                if i < device_identifiers.len() {
                    device_identifiers[i] = *descriptor;
                }
            });
        Ok(self.descriptors.len())
    }

    fn get_firmware_parms(&self, firmware_params: &mut FirmwareParameters) -> McuResult<()> {
        *firmware_params = (*self.fw_params).clone();
        Ok(())
    }

    async fn get_xfer_size(&self, ua_transfer_size: usize) -> McuResult<usize> {
        Ok(ua_transfer_size.min(MAX_PLDM_FW_DATA_SIZE))
    }

    fn handle_component(
        &self,
        component: &FirmwareComponent,
        fw_params: &FirmwareParameters,
        _op: ComponentOperation,
    ) -> McuResult<ComponentResponseCode> {
        if let Some(size) = component.comp_image_size {
            if size
                < (core::mem::size_of::<ImageHeader>() + core::mem::size_of::<FlashHeader>()) as u32
            {
                return Ok(ComponentResponseCode::CompPrerequisitesNotMet);
            }
        }

        Ok(component.evaluate_update_eligibility(fw_params))
    }

    async fn query_download_offset_and_length(
        &self,
        _component: &FirmwareComponent,
    ) -> McuResult<(usize, usize)> {
        let should_yield = PLDM_STATE.lock(|state| {
            let mut state = state.borrow_mut();
            if *state == State::Initializing {
                *state = State::Initialized;
                return true;
            } else if *state == State::HeaderDownloadComplete || *state == State::ImageDownloadReady
            {
                return true;
            }
            false
        });
        if should_yield {
            IMAGE_LOADING_TASK_YIELD.signal(());
            PLDM_TASK_YIELD.wait().await;
        }

        let (offset, request_length) = DOWNLOAD_CTX.lock(|ctx| {
            let mut ctx = ctx.borrow_mut();

            let length = if ctx.total_downloaded > ctx.total_length {
                PLDM_FWUP_BASELINE_TRANSFER_SIZE
            } else {
                let remaining = ctx.total_length - ctx.total_downloaded;
                remaining.clamp(PLDM_FWUP_BASELINE_TRANSFER_SIZE, MAX_PLDM_FW_DATA_SIZE)
            };

            ctx.last_requested_length = length;
            (ctx.current_offset, length)
        });

        Ok((offset, request_length))
    }

    async fn download_fw_data(
        &self,
        offset: usize,
        data: &[u8],
        _component: &FirmwareComponent,
    ) -> McuResult<TransferResult> {
        self.copy_data_to_buffer(offset, data).await?;
        let should_yield = DOWNLOAD_CTX.lock(|ctx| -> McuResult<bool> {
            let mut ctx = ctx.borrow_mut();
            if ctx.total_downloaded >= ctx.total_length {
                Ok(PLDM_STATE.lock(|state| {
                    let mut state = state.borrow_mut();
                    if *state == State::DownloadingHeader {
                        *state = State::HeaderDownloadComplete;
                        return false;
                    } else if *state == State::DownloadingToc {
                        *state = State::TocDownloadComplete;
                        return true;
                    } else if *state == State::DownloadingImage {
                        *state = State::ImageDownloadComplete;
                        return true;
                    }
                    false
                }))
            } else {
                ctx.current_offset = ctx
                    .current_offset
                    .checked_add(data.len())
                    .ok_or(pldm_errors::FW_DOWNLOAD_ERROR)?;
                Ok(false)
            }
        })?;

        if should_yield {
            IMAGE_LOADING_TASK_YIELD.signal(());
            PLDM_TASK_YIELD.wait().await;
        }

        Ok(TransferResult::TransferSuccess)
    }

    fn is_download_complete(&self, _component: &FirmwareComponent) -> bool {
        DOWNLOAD_CTX.lock(|ctx| ctx.borrow().download_complete)
    }

    fn query_download_progress(
        &self,
        _component: &FirmwareComponent,
        progress_percent: &mut ProgressPercent,
    ) -> McuResult<()> {
        *progress_percent = ProgressPercent::default();
        Ok(())
    }

    async fn verify(
        &self,
        _component: &FirmwareComponent,
        progress_percent: &mut ProgressPercent,
    ) -> McuResult<VerifyResult> {
        *progress_percent = ProgressPercent::new(100).map_err(|_| pldm_errors::VERIFY_ERROR)?;
        let verify_result = DOWNLOAD_CTX.lock(|ctx| ctx.borrow().verify_result);
        Ok(verify_result)
    }

    async fn apply(
        &self,
        _component: &FirmwareComponent,
        progress_percent: &mut ProgressPercent,
    ) -> McuResult<ApplyResult> {
        *progress_percent = ProgressPercent::new(100).map_err(|_| pldm_errors::APPLY_ERROR)?;
        Ok(ApplyResult::ApplySuccess)
    }

    fn cancel_update_component(&self, _component: &FirmwareComponent) -> McuResult<()> {
        Ok(())
    }

    fn activate(&self, _self_contained_activation: u8, estimated_time: &mut u16) -> McuResult<u8> {
        *estimated_time = 0;
        Ok(0)
    }
}

fn copy_prefix_chunk(dst: &mut [u8], start: usize, data: &[u8]) -> McuResult<()> {
    let remaining = dst
        .len()
        .checked_sub(start)
        .ok_or(pldm_errors::FW_DOWNLOAD_ERROR)?;
    let copy_len = remaining.min(data.len());
    let end = start
        .checked_add(copy_len)
        .ok_or(pldm_errors::FW_DOWNLOAD_ERROR)?;
    let dst = dst
        .get_mut(start..end)
        .ok_or(pldm_errors::FW_DOWNLOAD_ERROR)?;
    let src = data.get(..copy_len).ok_or(pldm_errors::FW_DOWNLOAD_ERROR)?;
    dst.copy_from_slice(src);
    Ok(())
}
