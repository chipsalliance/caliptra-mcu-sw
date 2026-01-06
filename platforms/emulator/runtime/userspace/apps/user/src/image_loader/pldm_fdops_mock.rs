// Licensed under the Apache-2.0 license

extern crate alloc;

use alloc::boxed::Box;
use async_trait::async_trait;
use core::cell::RefCell;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::lazy_lock::LazyLock;
use embassy_sync::signal::Signal;
use pldm_common::message::firmware_update::apply_complete::ApplyResult;
use pldm_common::message::firmware_update::get_fw_params::FirmwareParameters;
use pldm_common::message::firmware_update::get_status::ProgressPercent;
use pldm_common::message::firmware_update::transfer_complete::TransferResult;
use pldm_common::message::firmware_update::verify_complete::VerifyResult;
use pldm_common::protocol::firmware_update::{
    ComponentActivationMethods, ComponentClassification, ComponentParameterEntry,
    ComponentResponseCode, Descriptor, DescriptorType, FirmwareDeviceCapability,
    PldmFirmwareString, PldmFirmwareVersion, PLDM_FWUP_BASELINE_TRANSFER_SIZE,
    PLDM_FWUP_MAX_PADDING_SIZE,
};
use pldm_common::util::fw_component::FirmwareComponent;
use pldm_lib::firmware_device::fd_ops::{ComponentOperation, FdOps, FdOpsError};

const FD_DESCRIPTORS_COUNT: usize = 1;
const FD_FW_COMPONENTS_COUNT: usize = 1;

// This is a dummy UUID for development. The actual UUID is assigned by the vendor.
const UUID: [u8; 16] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
];

static DESCRIPTORS: LazyLock<[Descriptor; FD_DESCRIPTORS_COUNT]> =
    LazyLock::new(|| [Descriptor::new(DescriptorType::Uuid, &UUID).unwrap()]);

// This is dummy firmware parameter for development. The actual firmware parameters are
// retrieved from the SoC manifest via mailbox commands.
static FIRMWARE_PARAMS: LazyLock<FirmwareParameters> = LazyLock::new(|| {
    let active_firmware_string = PldmFirmwareString::new("UTF-8", "soc-fw-1.0").unwrap();
    let active_firmware_version =
        PldmFirmwareVersion::new(0x12345678, &active_firmware_string, Some("20250210"));
    let pending_firmware_string = PldmFirmwareString::new("UTF-8", "soc-fw-1.1").unwrap();
    let pending_firmware_version =
        PldmFirmwareVersion::new(0x87654321, &pending_firmware_string, Some("20250213"));
    let comp_activation_methods = ComponentActivationMethods(0x0001);
    let capabilities_during_update = FirmwareDeviceCapability(0x0010);
    let component_parameter_entry = ComponentParameterEntry::new(
        ComponentClassification::Firmware,
        0x0001,
        0,
        &active_firmware_version,
        &pending_firmware_version,
        comp_activation_methods,
        capabilities_during_update,
    );
    FirmwareParameters::new(
        capabilities_during_update,
        FD_FW_COMPONENTS_COUNT as u16,
        &active_firmware_string,
        &pending_firmware_string,
        &[component_parameter_entry],
    )
});

static PLDM_DONE_SIGNAL: Signal<CriticalSectionRawMutex, ()> = Signal::new();

// This is the maximum time in seconds that UA will wait for self-activation. It is a test value for development.
static TEST_SELF_ACTIVATION_MAX_TIME_IN_SECONDS: u16 = 20;

pub struct FdOpsObject {
    download_ctx: RefCell<DownloadCtx>,
    verify_ctx: RefCell<ProgressPercent>,
    apply_ctx: RefCell<ProgressPercent>,
}

pub struct DownloadCtx {
    pub offset: usize,
    pub length: usize,
}

impl Default for FdOpsObject {
    fn default() -> Self {
        Self::new()
    }
}

impl FdOpsObject {
    pub fn new() -> Self {
        Self {
            download_ctx: RefCell::new(DownloadCtx {
                offset: 0,
                length: 0,
            }),
            verify_ctx: RefCell::new(ProgressPercent::default()),
            apply_ctx: RefCell::new(ProgressPercent::default()),
        }
    }
    pub async fn wait_for_pldm_done() {
        PLDM_DONE_SIGNAL.wait().await;
    }
}

#[async_trait(?Send)]
impl FdOps for FdOpsObject {
    fn get_device_identifiers(
        &self,
        device_identifiers: &mut [Descriptor],
    ) -> Result<usize, FdOpsError> {
        let dev_id = DESCRIPTORS.get();
        if device_identifiers.len() < dev_id.len() {
            Err(FdOpsError::DeviceIdentifiersError)
        } else {
            device_identifiers[..dev_id.len()].copy_from_slice(dev_id);
            Ok(dev_id.len())
        }
    }

    fn get_firmware_parms(
        &self,
        firmware_params: &mut FirmwareParameters,
    ) -> Result<(), FdOpsError> {
        let fw_params = FIRMWARE_PARAMS.get();
        *firmware_params = (*fw_params).clone();
        Ok(())
    }

    async fn get_xfer_size(&self, ua_transfer_size: usize) -> Result<usize, FdOpsError> {
        Ok(PLDM_FWUP_BASELINE_TRANSFER_SIZE
            .max(ua_transfer_size.min(pldm_lib::config::FD_MAX_XFER_SIZE)))
    }

    fn handle_component(
        &self,
        component: &FirmwareComponent,
        fw_params: &FirmwareParameters,
        op: ComponentOperation,
    ) -> Result<ComponentResponseCode, FdOpsError> {
        let comp_resp_code = component.evaluate_update_eligibility(fw_params);

        // If it is update component operation, reset download context
        if op == ComponentOperation::UpdateComponent {
            let mut download_ctx = self.download_ctx.borrow_mut();
            download_ctx.offset = 0;
            download_ctx.length = 0;
        }

        Ok(comp_resp_code)
    }

    async fn query_download_offset_and_length(
        &self,
        component: &FirmwareComponent,
    ) -> Result<(usize, usize), FdOpsError> {
        let download_ctx = self.download_ctx.borrow();
        match component.comp_image_size {
            Some(image_size) => {
                let offset = download_ctx.offset;
                let length = (image_size as usize - offset).min(64);
                Ok((offset, length))
            }
            None => Err(FdOpsError::ComponentError),
        }
    }

    async fn download_fw_data(
        &self,
        offset: usize,
        data: &[u8],
        component: &FirmwareComponent,
    ) -> Result<TransferResult, FdOpsError> {
        let component_image_size = component
            .comp_image_size
            .ok_or(FdOpsError::FwDownloadError)? as usize;

        let max_allowed_size = component_image_size + PLDM_FWUP_MAX_PADDING_SIZE;
        let mut download_ctx = self.download_ctx.borrow_mut();

        if offset != download_ctx.offset || offset + data.len() > max_allowed_size {
            // reset download context if offset is not as expected
            download_ctx.offset = 0;
            download_ctx.length = 0;
            return Err(FdOpsError::FwDownloadError);
        }

        download_ctx.offset += data.len();
        download_ctx.length += data.len();

        Ok(TransferResult::TransferSuccess)
    }

    fn is_download_complete(&self, component: &FirmwareComponent) -> bool {
        let download_ctx = self.download_ctx.borrow();
        if let Some(image_size) = component.comp_image_size {
            download_ctx.length >= image_size as usize
        } else {
            false
        }
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
        let mut verify_ctx = self.verify_ctx.borrow_mut();
        // Increment the verification progress by 30% on each call. Reset to 0 once it reaches 100%.
        if verify_ctx.value() < 100 {
            let new_value = verify_ctx.value() + 30;
            verify_ctx.set_value(new_value.min(100)).ok();
        } else {
            verify_ctx.set_value(0).ok();
        }

        progress_percent.set_value(verify_ctx.value()).ok();
        Ok(VerifyResult::VerifySuccess)
    }

    async fn apply(
        &self,
        _component: &FirmwareComponent,
        progress_percent: &mut ProgressPercent,
    ) -> Result<ApplyResult, FdOpsError> {
        let mut apply_ctx = self.apply_ctx.borrow_mut();
        // Increment the apply progress by 30% on each call. Reset to 0 once it reaches 100% for next test.
        if apply_ctx.value() < 100 {
            let new_value = apply_ctx.value() + 30;
            apply_ctx.set_value(new_value.min(100)).ok();
        } else {
            apply_ctx.set_value(0).ok();
        }
        progress_percent.set_value(apply_ctx.value()).ok();
        Ok(ApplyResult::ApplySuccess)
    }

    fn activate(
        &self,
        self_contained_activation: u8,
        estimated_time: &mut u16,
    ) -> Result<u8, FdOpsError> {
        if self_contained_activation == 1 {
            *estimated_time = TEST_SELF_ACTIVATION_MAX_TIME_IN_SECONDS;
        }
        PLDM_DONE_SIGNAL.signal(());
        Ok(0) // PLDM completion code for success
    }

    fn cancel_update_component(&self, _component: &FirmwareComponent) -> Result<(), FdOpsError> {
        // Clean up download, verify, and apply contexts
        let mut download_ctx = self.download_ctx.borrow_mut();
        download_ctx.offset = 0;
        download_ctx.length = 0;
        let mut verify_ctx = self.verify_ctx.borrow_mut();
        verify_ctx.set_value(0).ok();
        let mut apply_ctx = self.apply_ctx.borrow_mut();
        apply_ctx.set_value(0).ok();

        Ok(())
    }
}
