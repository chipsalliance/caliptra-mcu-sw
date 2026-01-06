// Licensed under the Apache-2.0 license

extern crate alloc;
use alloc::boxed::Box;
use async_trait::async_trait;
use libsyscall_caliptra::DefaultSyscalls;
use pldm_common::message::firmware_update::apply_complete::ApplyResult;
use pldm_common::message::firmware_update::get_status::ProgressPercent;
use pldm_common::message::firmware_update::request_cancel::{
    NonFunctioningComponentBitmap, NonFunctioningComponentIndication,
};
use pldm_common::message::firmware_update::transfer_complete::TransferResult;
use pldm_common::message::firmware_update::verify_complete::VerifyResult;
use pldm_common::util::fw_component::FirmwareComponent;
use pldm_common::{
    message::firmware_update::get_fw_params::FirmwareParameters,
    protocol::firmware_update::{ComponentResponseCode, Descriptor, PldmFdTime},
};

use crate::timer::AsyncAlarm;

#[derive(Debug)]
pub enum FdOpsError {
    DeviceIdentifiersError,
    FirmwareParametersError,
    TransferSizeError,
    ComponentError,
    FwDownloadError,
    VerifyError,
    ApplyError,
    ActivateError,
    CancelUpdateError,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ComponentOperation {
    PassComponent,
    UpdateComponent,
}

/// Trait for firmware device-specific operations.
///
/// This trait defines asynchronous methods for performing various firmware device operations,
/// including retrieving device identifiers, firmware parameters, and transfer sizes. It also
/// provides methods for handling firmware components, managing firmware data downloads, verifying
/// and applying firmware, activating new firmware, and obtaining the current timestamp.
#[async_trait(?Send)]
pub trait FdOps {
    /// Asynchronously retrieves device identifiers.
    ///
    /// # Arguments
    ///
    /// * `device_identifiers` - A mutable slice of `Descriptor` to store the retrieved device identifiers.
    ///
    /// # Returns
    ///
    /// * `Result<usize, FdOpsError>` - On success, returns the number of device identifiers retrieved.
    ///   On failure, returns an `FdOpsError`.
    fn get_device_identifiers(
        &self,
        device_identifiers: &mut [Descriptor],
    ) -> Result<usize, FdOpsError>;

    /// Asynchronously retrieves firmware parameters.
    ///
    /// # Arguments
    ///
    /// * `firmware_params` - A mutable reference to `FirmwareParameters` to store the retrieved firmware parameters.
    ///
    /// # Returns
    ///
    /// * `Result<(), FdOpsError>` - On success, returns `Ok(())`. On failure, returns an `FdOpsError`.
    fn get_firmware_parms(
        &self,
        firmware_params: &mut FirmwareParameters,
    ) -> Result<(), FdOpsError>;

    /// Retrieves the transfer size for the firmware update operation.
    ///
    /// # Arguments
    ///
    /// * `ua_transfer_size` - The requested transfer size in bytes.
    ///
    /// # Returns
    ///
    /// * `Result<usize, FdOpsError>` - On success, returns the transfer size in bytes.
    ///   On failure, returns an `FdOpsError`.
    async fn get_xfer_size(&self, ua_transfer_size: usize) -> Result<usize, FdOpsError>;

    /// Handles firmware component operations such as passing or updating components.
    ///
    /// # Arguments
    ///
    /// * `component` - A reference to the `FirmwareComponent` to be processed.
    /// * `fw_params` - A reference to the `FirmwareParameters` associated with the operation.
    /// * `op` - The `ComponentOperation` to be performed (e.g., pass or update).
    ///
    /// # Returns
    ///
    /// * `Result<ComponentResponseCode, FdOpsError>` - On success, returns a `ComponentResponseCode`.
    ///   On failure, returns an `FdOpsError`.
    fn handle_component(
        &self,
        component: &FirmwareComponent,
        fw_params: &FirmwareParameters,
        op: ComponentOperation,
    ) -> Result<ComponentResponseCode, FdOpsError>;

    /// Queries the download offset and length for a given firmware component.
    ///
    /// # Arguments
    ///
    /// * `component` - A reference to the `FirmwareComponent` for which the download offset and length are queried.
    ///
    /// # Returns
    ///
    /// * `Result<(usize, usize), FdOpsError>` - On success, returns a tuple containing the offset and length in bytes.
    ///   On failure, returns an `FdOpsError`.
    async fn query_download_offset_and_length(
        &self,
        component: &FirmwareComponent,
    ) -> Result<(usize, usize), FdOpsError>;

    /// Handles firmware data downloading operations.
    ///
    /// # Arguments
    ///
    /// * `offset` - The offset in bytes where the firmware data should be written or processed.
    /// * `data` - A slice of bytes representing the firmware data to be handled.
    /// * `component` - A reference to the `FirmwareComponent` associated with the firmware data.
    ///
    /// # Returns
    ///
    /// * `Result<TransferResult, FdOpsError>` - On success, returns a `TransferResult` indicating the outcome of the operation.
    ///   On failure, returns an `FdOpsError`.
    async fn download_fw_data(
        &self,
        offset: usize,
        data: &[u8],
        component: &FirmwareComponent,
    ) -> Result<TransferResult, FdOpsError>;

    /// Checks if the firmware download for a given component is complete.
    ///
    /// # Arguments
    ///
    /// * `component` - A reference to the `FirmwareComponent` for which the download completion status is checked.
    ///
    /// # Returns
    ///
    /// * `bool` - Returns `true` if the download is complete, otherwise `false`.
    fn is_download_complete(&self, component: &FirmwareComponent) -> bool;

    /// Queries the download progress for a given firmware component.
    ///
    /// # Arguments
    ///
    /// * `component` - A reference to the `FirmwareComponent` for which the download progress is queried.
    /// * `progress_percent` - A mutable reference to `ProgressPercent` to track the download progress.
    ///
    /// # Returns
    ///
    /// * `Result<(), FdOpsError>` - On success, returns `Ok(())`. On failure, returns an `FdOpsError`.
    fn query_download_progress(
        &self,
        component: &FirmwareComponent,
        progress_percent: &mut ProgressPercent,
    ) -> Result<(), FdOpsError>;

    /// Verifies the firmware component.
    ///
    /// # Arguments
    ///
    /// * `component` - A reference to the `FirmwareComponent` to be verified.
    /// * `progress_percent` - A mutable reference to `ProgressPercent` to track the verification progress.
    ///
    /// # Returns
    ///
    /// * `Result<VerifyResult, FdOpsError>` - On success, returns a `VerifyResult` indicating the outcome of the verification.
    /// *   On failure, returns an `FdOpsError`.
    async fn verify(
        &self,
        component: &FirmwareComponent,
        progress_percent: &mut ProgressPercent,
    ) -> Result<VerifyResult, FdOpsError>;

    /// Applies the firmware component.
    ///
    /// # Arguments
    ///
    /// * `component` - A reference to the `FirmwareComponent` to be applied.
    /// * `progress_percent` - A mutable reference to `ProgressPercent` to track the application progress.
    ///
    /// # Returns
    ///
    /// * `Result<ApplyResult, FdOpsError>` - On success, returns an `ApplyResult` indicating the outcome of the application.
    /// *   On failure, returns an `FdOpsError`.
    async fn apply(
        &self,
        component: &FirmwareComponent,
        progress_percent: &mut ProgressPercent,
    ) -> Result<ApplyResult, FdOpsError>;

    /// Activates new firmware.
    ///
    /// # Arguments
    ///
    /// * `self_contained_activation` - Indicates if self-contained activation is requested.
    /// * `estimated_time` - A mutable reference to store the estimated time (in seconds)
    ///   required to perform self-activation. This may be left as `None` if not needed.
    ///
    /// # Returns
    ///
    /// * `Result<u8, FdOpsError>` - On success, returns a PLDM completion code.
    ///   On failure, returns an `FdOpsError`.
    ///
    /// The device implementation is responsible for verifying that the expected components
    /// have been updated. If not, it should return `PLDM_FWUP_INCOMPLETE_UPDATE`.
    fn activate(
        &self,
        self_contained_activation: u8,
        estimated_time: &mut u16,
    ) -> Result<u8, FdOpsError>;

    /// Cancels the update operation for a specific firmware component.
    ///
    /// # Arguments
    ///
    /// * `component` - A reference to the `FirmwareComponent` for which the update operation should be canceled.
    ///
    /// # Returns
    ///
    /// * `Result<(), FdOpsError>` - On success, returns `Ok(())`. On failure, returns an `FdOpsError`.
    fn cancel_update_component(&self, component: &FirmwareComponent) -> Result<(), FdOpsError>;

    /// Indicates which components will be in a non-functioning state upon exiting update mode
    /// due to cancel update request from UA.
    ///
    /// # Returns
    ///
    /// * `Result<(NonFunctioningComponentIndication, NonFunctioningComponentBitmap), FdOpsError>` -
    ///   On success, returns a tuple containing:
    ///     - `NonFunctioningComponentIndication`: Indicates whether components are functioning or not.
    ///     - `NonFunctioningComponentBitmap`: A bitmap representing non-functioning components.
    ///   On failure, returns an `FdOpsError`.
    async fn get_non_functional_component_info(
        &self,
    ) -> Result<
        (
            NonFunctioningComponentIndication,
            NonFunctioningComponentBitmap,
        ),
        FdOpsError,
    > {
        Ok((
            NonFunctioningComponentIndication::ComponentsFunctioning,
            NonFunctioningComponentBitmap::new(0),
        ))
    }

    /// Retrieves the current timestamp in milliseconds.
    ///
    /// # Returns
    ///
    /// * `PldmFdTime` - The current timestamp in milliseconds.
    fn now(&self) -> PldmFdTime {
        AsyncAlarm::<DefaultSyscalls>::get_milliseconds().unwrap()
    }
}
