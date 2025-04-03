// Licensed under the Apache-2.0 license

extern crate alloc;
use alloc::boxed::Box;
use async_trait::async_trait;
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_sync::mutex::Mutex;
use libapi_caliptra::image_loading::ImageLoaderAPI;
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
    UpdateComponentError,
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

/// Trait representing firmware device specific operations that can be performed by interacting with mailbox API, image loader API etc.
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
    /// * `Result<usize, FdOpsError>` - On success, returns the number of device identifiers retrieved. On failure, returns an `FdOpsError`.
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

    // Get the transfer size for the firmware update operation
    async fn get_transfer_size(&self, ua_transfer_size: usize) -> Result<usize, FdOpsError>;

    // Handle pass_component and update_component operations. Update flag is used to differentiate between the two operations.
    async fn update_component(
        &self,
        component: &FirmwareComponent,
        fw_params: &FirmwareParameters,
        update: bool,
    ) -> Result<ComponentResponseCode, FdOpsError>;

    // Return the current timestamp in u64 miliseconds
    async fn now(&self) -> PldmFdTime;
}

#[async_trait(?Send)]
impl<S: Syscalls> FdOps for FdOpsObject<S> {
    async fn get_device_identifiers(
        &self,
        device_identifiers: &mut [Descriptor],
    ) -> Result<usize, FdOpsError> {
        self.inner.lock().await;
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
        self.inner.lock().await;
        if cfg!(feature = "pldm-lib-use-static-config") {
            let fw_params = crate::config::FIRMWARE_PARAMS.get();
            *firmware_params = (*fw_params).clone();
            return Ok(());
        }

        // TODO: Implement the actual firmware parameters retrieval via mailbox commands
        todo!()
    }

    async fn get_transfer_size(&self, ua_transfer_size: usize) -> Result<usize, FdOpsError> {
        self.inner.lock().await;

        if cfg!(feature = "pldm-lib-use-static-config") {
            return Ok(PLDM_FWUP_BASELINE_TRANSFER_SIZE
                .max(ua_transfer_size.min(crate::config::FD_MAX_TRANSFER_SIZE)));
        }

        // TODO: Implement the actual transfer size retrieval logic
        todo!()
    }

    async fn update_component(
        &self,
        component: &FirmwareComponent,
        fw_params: &FirmwareParameters,
        update: bool,
    ) -> Result<ComponentResponseCode, FdOpsError> {
        //let ops = self.inner.lock().await;
        let comp_resp_code = component.evaluate_update_eligibility(fw_params);
        if !update || comp_resp_code != ComponentResponseCode::CompCanBeUpdated {
            return Ok(comp_resp_code);
        }

        if cfg!(feature = "pldm-lib-use-static-config") {
            // Just return success for now
            return Ok(comp_resp_code);
        }

        // TODO: device specific component update logic is extended from here
        todo!()
    }

    async fn now(&self) -> PldmFdTime {
        if cfg!(feature = "pldm-lib-use-static-config") {
            // Just return success for now
            return PldmFdTime::default();
        } else {
            // TODO: Implement the actual timestamp retrieval logic
            todo!()
        }
    }
}
