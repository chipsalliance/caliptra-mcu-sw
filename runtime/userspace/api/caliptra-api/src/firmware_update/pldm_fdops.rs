// Licensed under the Apache-2.0 license

extern crate alloc;

use super::pldm_client::{FW_UPDATE_TASK_YIELD, PLDM_DAEMON_TASK_YIELD};
use super::pldm_context::{State, DOWNLOAD_CTX, PLDM_STATE};
use alloc::boxed::Box;
use async_trait::async_trait;
use flash_image::{FlashHeader, ImageHeader};
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
const ESTIMATED_ACTIVATION_TIME_SECS: u16 = 300; // 5 minutes estimated activation time including reset

pub struct UpdateFdOps {}

impl UpdateFdOps {
    /// Creates a new instance of the UpdateFdOps.
    pub fn new() -> Self {
        Self {}
    }

    async fn copy_data_to_buffer(&self, _offset: usize, data: &[u8]) -> Result<(), FdOpsError> {
        let state = PLDM_STATE.lock(|state| *state.borrow());
        if state != State::DownloadingImage {
            return Err(FdOpsError::FwDownloadError);
        }
        let write_offset = DOWNLOAD_CTX.lock(|ctx| {
            let mut ctx = ctx.borrow_mut();
            ctx.total_downloaded += data.len();
            ctx.current_offset - ctx.initial_offset
        });
        let staging_memory = DOWNLOAD_CTX.lock(|ctx| ctx.borrow().staging_memory);
        if let Some(staging_area) = staging_memory {
            return staging_area
                .write(write_offset, data)
                .await
                .map_err(|_| FdOpsError::FwDownloadError);
        }
        Err(FdOpsError::FwDownloadError)
    }
}

#[async_trait(?Send)]
impl FdOps for UpdateFdOps {
    fn get_device_identifiers(
        &self,
        device_identifiers: &mut [Descriptor],
    ) -> Result<usize, FdOpsError> {
        let descriptors = DOWNLOAD_CTX.lock(|ctx| ctx.borrow().descriptors);
        if let Some(descriptors) = descriptors {
            descriptors.iter().enumerate().for_each(|(i, descriptor)| {
                if i < device_identifiers.len() {
                    device_identifiers[i] = *descriptor;
                }
            });
            Ok(descriptors.len())
        } else {
            Err(FdOpsError::DeviceIdentifiersError)
        }
    }

    fn get_firmware_parms(
        &self,
        firmware_params: &mut FirmwareParameters,
    ) -> Result<(), FdOpsError> {
        let fw_params = DOWNLOAD_CTX.lock(|ctx| ctx.borrow().fw_params);
        if let Some(fw_params) = fw_params {
            // Clone the firmware parameters to avoid borrowing issues
            *firmware_params = fw_params.clone();
            Ok(())
        } else {
            Err(FdOpsError::FirmwareParametersError)
        }
    }

    async fn get_xfer_size(&self, _ua_transfer_size: usize) -> Result<usize, FdOpsError> {
        // Return the minimum of requested and baseline transfer size
        let size = MAX_PLDM_TRANSFER_SIZE;
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
        let staging_memory = DOWNLOAD_CTX.lock(|ctx| ctx.borrow().staging_memory);
        if let Some(staging_area) = staging_memory {
            if staging_area.size() < component.comp_image_size.unwrap_or(0) as usize {
                // Staging area is not large enough for the component
                return Ok(ComponentResponseCode::CompPrerequisitesNotMet);
            }
        } else {
            return Ok(ComponentResponseCode::CompPrerequisitesNotMet);
        }

        DOWNLOAD_CTX.lock(|ctx| {
            let mut ctx = ctx.borrow_mut();
            ctx.total_length = component.comp_image_size.unwrap_or(0) as usize;
        });

        Ok(component.evaluate_update_eligibility(fw_params))
    }

    async fn query_download_offset_and_length(
        &self,
        _component: &FirmwareComponent,
    ) -> Result<(usize, usize), FdOpsError> {
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
        DOWNLOAD_CTX.lock(|ctx| {
            let mut ctx = ctx.borrow_mut();
            if ctx.total_downloaded >= ctx.total_length {
                PLDM_STATE.lock(|state| {
                    let mut state = state.borrow_mut();
                    if *state == State::DownloadingImage {
                        *state = State::ImageDownloadComplete;
                    }
                })
            } else {
                ctx.current_offset += data.len();
            }
        });

        Ok(TransferResult::TransferSuccess)
    }

    fn is_download_complete(&self, _component: &FirmwareComponent) -> bool {
        PLDM_STATE.lock(|state| *state.borrow() == State::ImageDownloadComplete)
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
        // Transition to Verify state
        PLDM_STATE.lock(|state| {
            let mut state = state.borrow_mut();
            *state = State::Verifying;
        });
        // Pass control to firmware update task
        FW_UPDATE_TASK_YIELD.signal(());

        // Wait for the firmware update task to complete verification
        PLDM_DAEMON_TASK_YIELD.wait().await;

        *progress_percent = ProgressPercent::new(100).unwrap();
        let verify_result = DOWNLOAD_CTX.lock(|ctx| ctx.borrow().verify_result);
        Ok(verify_result)
    }

    async fn apply(
        &self,
        _component: &FirmwareComponent,
        progress_percent: &mut ProgressPercent,
    ) -> Result<ApplyResult, FdOpsError> {
        // Transition to Verify state
        PLDM_STATE.lock(|state| {
            let mut state = state.borrow_mut();
            *state = State::Apply;
        });
        // Pass control to firmware update task
        FW_UPDATE_TASK_YIELD.signal(());

        // Wait for the firmware update task to complete verification
        PLDM_DAEMON_TASK_YIELD.wait().await;

        *progress_percent = ProgressPercent::new(100).unwrap();
        let apply_result = DOWNLOAD_CTX.lock(|ctx| ctx.borrow().apply_result);
        Ok(apply_result)
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
        *estimated_time = ESTIMATED_ACTIVATION_TIME_SECS;
        PLDM_STATE.lock(|state| {
            let mut state = state.borrow_mut();
            *state = State::Activate;
        });
        FW_UPDATE_TASK_YIELD.signal(());
        Ok(0) // PLDM completion code for success
    }
}
