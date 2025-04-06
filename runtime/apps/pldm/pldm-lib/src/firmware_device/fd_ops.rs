// Licensed under the Apache-2.0 license

extern crate alloc;
use alloc::boxed::Box;
use async_trait::async_trait;
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_sync::mutex::Mutex;
use libapi_caliptra::mailbox::Mailbox;
use libtock_platform::Syscalls;
use pldm_common::util::fw_component::FirmwareComponent;
use pldm_common::{
    message::firmware_update::get_fw_params::FirmwareParameters,
    protocol::firmware_update::{
        ComponentResponseCode, Descriptor, PldmFdTime, PLDM_FWUP_BASELINE_TRANSFER_SIZE,
    },
};

#[derive(Debug)]
pub enum FdOpsError {
    DeviceIdentifiersError,
    FirmwareParametersError,
    TransferSizeError,
    ComponentError,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ComponentOperation {
    PassComponent,
    UpdateComponent,
}

/// Thread-safe object for firmware device operations (FdOps).
pub struct FdOpsObject<S: Syscalls> {
    inner: Mutex<NoopRawMutex, FdOpsInner<S>>,
}

/// A structure representing the operations for firmware device (FdOps).
///
/// This structure encapsulates the necessary components for performing
/// firmware device operations, including a mailbox and an image loader.
///
/// # Type Parameters
/// - `S`: A type that implements the `Syscalls` trait, which provides
///   the necessary system call interfaces.
///
/// # Fields
/// - `mailbox`: An instance of `Mailbox<S>`, used for communication.
#[allow(dead_code)]
struct FdOpsInner<S: Syscalls> {
    mailbox: Mailbox<S>,
    // Add more fields or APIs as needed
}

impl<S: Syscalls> Default for FdOpsObject<S> {
    fn default() -> Self {
        Self::new()
    }
}

impl<S: Syscalls> FdOpsObject<S> {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(FdOpsInner {
                mailbox: Mailbox::new(),
            }),
        }
    }
}

/// Trait representing firmware device specific operations that can be performed by interacting with mailbox API etc.
#[async_trait(?Send)]
/// A trait defining operations for firmware devices.
///
/// This trait provides asynchronous methods for interacting with firmware devices,
/// including retrieving device identifiers, firmware parameters, transfer sizes,
/// handling firmware components, and obtaining the current timestamp.
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
    async fn get_device_identifiers(
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
    async fn get_firmware_parms(
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
    async fn handle_component(
        &self,
        component: &FirmwareComponent,
        fw_params: &FirmwareParameters,
        op: ComponentOperation,
    ) -> Result<ComponentResponseCode, FdOpsError>;

    /// Retrieves the current timestamp in milliseconds.
    ///
    /// # Returns
    ///
    /// * `PldmFdTime` - The current timestamp in milliseconds.
    async fn now(&self) -> PldmFdTime;
}

#[async_trait(?Send)]
impl<S: Syscalls> FdOps for FdOpsObject<S> {
    async fn get_device_identifiers(
        &self,
        device_identifiers: &mut [Descriptor],
    ) -> Result<usize, FdOpsError> {
        let _guard = self.inner.lock().await;
        if cfg!(feature = "pldm-lib-use-static-config") {
            let dev_id = crate::config::DESCRIPTORS.get();
            if device_identifiers.len() < dev_id.len() {
                return Err(FdOpsError::DeviceIdentifiersError);
            }
            device_identifiers[..dev_id.len()].copy_from_slice(dev_id);
            return Ok(dev_id.len());
        }

        // TODO: Implement the actual device identifiers retrieval logic
        todo!()
    }

    async fn get_firmware_parms(
        &self,
        firmware_params: &mut FirmwareParameters,
    ) -> Result<(), FdOpsError> {
        let _guard = self.inner.lock().await;
        if cfg!(feature = "pldm-lib-use-static-config") {
            let fw_params = crate::config::FIRMWARE_PARAMS.get();
            *firmware_params = (*fw_params).clone();
            return Ok(());
        }

        // TODO: Implement the actual firmware parameters retrieval via mailbox commands
        todo!()
    }

    async fn get_xfer_size(&self, ua_transfer_size: usize) -> Result<usize, FdOpsError> {
        let _guard = self.inner.lock().await;
        if cfg!(feature = "pldm-lib-use-static-config") {
            return Ok(PLDM_FWUP_BASELINE_TRANSFER_SIZE
                .max(ua_transfer_size.min(crate::config::FD_MAX_XFER_SIZE)));
        }

        // TODO: Implement the actual transfer size retrieval logic
        todo!()
    }

    async fn handle_component(
        &self,
        component: &FirmwareComponent,
        fw_params: &FirmwareParameters,
        op: ComponentOperation,
    ) -> Result<ComponentResponseCode, FdOpsError> {
        let _guard = self.inner.lock().await;
        let comp_resp_code = component.evaluate_update_eligibility(fw_params);
        if op == ComponentOperation::PassComponent
            || comp_resp_code != ComponentResponseCode::CompCanBeUpdated
        {
            return Ok(comp_resp_code);
        }

        // For the `UpdateComponent` operation, additional device-specific logic can be implemented here.
        // Currently, the method simply returns `comp_resp_code` as `CompCanBeUpdated` if the component passes the evaluation.
        if cfg!(feature = "pldm-lib-use-static-config") {
            return Ok(comp_resp_code);
        }

        // For `UpdateComponent` operation, device specific logic might be extended from here.
        todo!()
    }

    async fn now(&self) -> PldmFdTime {
        let _guard = self.inner.lock().await;
        if cfg!(feature = "pldm-lib-use-static-config") {
            let current_time = crate::config::get_test_fw_update_timestamp();
            crate::config::update_test_fw_update_timestamp();
            return current_time;
        }

        // TODO: Implement the actual logic to return the platform timestamp.
        todo!()
    }
}
