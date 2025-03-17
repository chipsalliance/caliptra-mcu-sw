// Licensed under the Apache-2.0 license

extern crate alloc;
use alloc::boxed::Box;
use async_trait::async_trait;
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_sync::mutex::Mutex;
use libapi_caliptra::image_loading::ImageLoaderAPI;
use libapi_caliptra::mailbox::Mailbox;
use libtock_platform::Syscalls;
use pldm_common::{
    message::firmware_update::get_fw_params::FirmwareParameters,
    protocol::firmware_update::Descriptor,
};

#[derive(Debug)]
pub enum FdOpsError {
    DeviceIdentifiersError,
    FirmwareParametersError,
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
/// - `image_loader`: An instance of `ImageLoaderAPI<S>`, used for loading
///   firmware images.
#[allow(dead_code)]
struct FdOpsInner<S: Syscalls> {
    mailbox: Mailbox<S>,
    image_loader: ImageLoaderAPI<S>,
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
                image_loader: ImageLoaderAPI::new(),
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
}
