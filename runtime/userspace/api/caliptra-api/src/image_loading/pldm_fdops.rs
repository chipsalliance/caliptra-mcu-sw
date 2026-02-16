// Licensed under the Apache-2.0 license

extern crate alloc;

use super::pldm_client::{IMAGE_LOADING_TASK_YIELD, PLDM_TASK_YIELD};
use super::pldm_context::{State, DOWNLOAD_CTX, PLDM_STATE};
use alloc::boxed::Box;
use async_trait::async_trait;
use flash_image::{FlashHeader, ImageHeader};
use libsyscall_caliptra::dma::{AXIAddr, DMAMapping, DMASource, DMATransaction, DMA as DMASyscall};
use pldm_common::message::firmware_update::apply_complete::ApplyResult;
use pldm_common::message::firmware_update::get_fw_params::FirmwareParameters;
use pldm_common::message::firmware_update::get_status::ProgressPercent;
use pldm_common::message::firmware_update::transfer_complete::TransferResult;
use pldm_common::message::firmware_update::verify_complete::VerifyResult;
use pldm_common::protocol::firmware_update::{
    ComponentResponseCode, Descriptor, PLDM_FWUP_BASELINE_TRANSFER_SIZE,
};
use pldm_common::util::fw_component::FirmwareComponent;
use pldm_lib::firmware_device::fd_ops::{ComponentOperation, FdOps, FdOpsError};
const MAX_PLDM_TRANSFER_SIZE: usize = 196; // This should be smaller than I3C MAX_READ_WRITE_SIZE

pub struct StreamingFdOps<'a, D: DMAMapping> {
    descriptors: &'a [Descriptor],
    fw_params: &'a FirmwareParameters,
    dma_mapping: &'a D,
}

impl<'a, D: DMAMapping> StreamingFdOps<'a, D> {
    /// Creates a new instance of the StreamingFdOps.
    pub const fn new(
        descriptors: &'a [Descriptor],
        fw_params: &'a FirmwareParameters,
        dma_mapping: &'a D,
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
        dma_mapping: &impl DMAMapping,
    ) -> Result<(), FdOpsError> {
        let dma_syscall: DMASyscall = DMASyscall::new();
        let source_address = dma_mapping
            .mcu_sram_to_mcu_axi(data.as_ptr() as u32)
            .map_err(|_| FdOpsError::FwDownloadError)?;

        let transaction = DMATransaction {
            byte_count: data.len(),
            source: DMASource::Address(source_address),
            dest_addr: load_address + offset as u64,
        };
        dma_syscall.xfer(&transaction).await.unwrap();

        Ok(())
    }

    async fn copy_data_to_buffer(&self, _offset: usize, data: &[u8]) -> Result<(), FdOpsError> {
        let state = PLDM_STATE.lock(|state| *state.borrow());
        let dma_params = DOWNLOAD_CTX.lock(|ctx| {
            let mut ctx = ctx.borrow_mut();
            ctx.total_downloaded += data.len();
            let start = ctx.current_offset - ctx.initial_offset;

            if state == State::DownloadingHeader {
                let end = (start + data.len()).min(ctx.header.len());
                ctx.header[start..end].copy_from_slice(&data[..end - start]);
            } else if state == State::DownloadingToc {
                let end = (start + data.len()).min(ctx.image_info.len());
                ctx.image_info[start..end].copy_from_slice(&data[..end - start]);
            } else if state == State::DownloadingImage {
                return Some((ctx.load_address, start));
            }

            None
        });
        if let Some(dma_params) = dma_params {
            return self
                .copy_buffer_to_load_address(dma_params.0, dma_params.1, data, self.dma_mapping)
                .await;
        }
        Ok(())
    }
}

#[async_trait(?Send)]
impl<D: DMAMapping> FdOps for StreamingFdOps<'_, D> {
    fn get_device_identifiers(
        &self,
        device_identifiers: &mut [Descriptor],
    ) -> Result<usize, FdOpsError> {
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

    fn get_firmware_parms(
        &self,
        firmware_params: &mut FirmwareParameters,
    ) -> Result<(), FdOpsError> {
        *firmware_params = (*self.fw_params).clone();
        Ok(())
    }

    async fn get_xfer_size(&self, ua_transfer_size: usize) -> Result<usize, FdOpsError> {
        // Return the minimum of requested and baseline transfer size
        let size = core::cmp::min(ua_transfer_size, PLDM_FWUP_BASELINE_TRANSFER_SIZE);
        Ok(size)
    }

    fn handle_component(
        &self,
        component: &FirmwareComponent,
        fw_params: &FirmwareParameters,
        _op: ComponentOperation,
    ) -> Result<ComponentResponseCode, FdOpsError> {
        if let Some(size) = component.comp_image_size {
            if size
                < (core::mem::size_of::<ImageHeader>() + core::mem::size_of::<FlashHeader>()) as u32
            {
                // Image size is too small
                // Return Ok with response code here to allow PLDM lib to pass it to UA
                // Returning an Err is considered fatal and will cause PLDM lib to halt PLDM process
                return Ok(ComponentResponseCode::CompPrerequisitesNotMet);
            }
        }

        Ok(component.evaluate_update_eligibility(fw_params))
    }

    async fn query_download_offset_and_length(
        &self,
        _component: &FirmwareComponent,
    ) -> Result<(usize, usize), FdOpsError> {
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
                remaining.clamp(PLDM_FWUP_BASELINE_TRANSFER_SIZE, MAX_PLDM_TRANSFER_SIZE)
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
    ) -> Result<TransferResult, FdOpsError> {
        self.copy_data_to_buffer(offset, data).await?;
        // update self.download_ctx
        let should_yield = DOWNLOAD_CTX.lock(|ctx| {
            let mut ctx = ctx.borrow_mut();
            if ctx.total_downloaded >= ctx.total_length {
                PLDM_STATE.lock(|state| {
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
                })
            } else {
                ctx.current_offset += data.len();
                false
            }
        });

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
    ) -> Result<(), FdOpsError> {
        *progress_percent = ProgressPercent::default();
        Ok(())
    }

    async fn verify(
        &self,
        _component: &FirmwareComponent,
        progress_percent: &mut ProgressPercent,
    ) -> Result<VerifyResult, FdOpsError> {
        // For streaming boot, the firmware images are verified during DOWNLOAD state.
        // This verify function is called when the device is in the VERIFY PLDM state (after DOWNLOAD state).
        // Therefore, since images have already been verified, at this stage, we return 100% progress.
        *progress_percent = ProgressPercent::new(100).unwrap();
        let verify_result = DOWNLOAD_CTX.lock(|ctx| ctx.borrow().verify_result);
        Ok(verify_result)
    }

    async fn apply(
        &self,
        _component: &FirmwareComponent,
        progress_percent: &mut ProgressPercent,
    ) -> Result<ApplyResult, FdOpsError> {
        // For streaming boot, apply is not applicable, so we return 100% progress.
        *progress_percent = ProgressPercent::new(100).unwrap();
        Ok(ApplyResult::ApplySuccess)
    }

    fn cancel_update_component(&self, _component: &FirmwareComponent) -> Result<(), FdOpsError> {
        // TODO: Implement cancel update component logic if needed
        Ok(())
    }

    fn activate(
        &self,
        _self_contained_activation: u8,
        estimated_time: &mut u16,
    ) -> Result<u8, FdOpsError> {
        *estimated_time = 0;
        // Activate is not applicable for streaming boot, so we return success.
        Ok(0) // PLDM completion code for success
    }
}
