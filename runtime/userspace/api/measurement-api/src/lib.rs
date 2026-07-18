// Licensed under the Apache-2.0 license

#![no_std]

mod api;
pub mod attestation_manifest;
pub mod errors;
pub mod image_metadata;

use api::MeasurementApi;
use caliptra_mcu_libsyscall_caliptra::DefaultSyscalls;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::mutex::Mutex;
use errors::{MeasurementApiError, MeasurementApiResult};
pub use image_metadata::{
    ImageMetadata, ImageMetadataFlags, MeasurementOperation, IMAGE_MEASUREMENT_DIGEST_SIZE,
};
pub use mcu_caliptra_api_lite::ImageHashSource;
use mcu_caliptra_api_lite::{ApiAlloc, DPE_LABEL_LEN};

static MEASUREMENT_API: Mutex<
    CriticalSectionRawMutex,
    Option<MeasurementApi<'static, DefaultSyscalls>>,
> = Mutex::new(None);

pub const ATTESTATION_P384_DIGEST_SIZE: usize = 48;
pub const ATTESTATION_P384_SIGNATURE_SIZE: usize = 96;

/// Reset classification passed to `measurement_boot_init`.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum BootKind {
    /// Cold boot: persistent measurement state is stale and must be
    /// reinitialized.
    ColdBoot,
    /// MCU hitless update: preserved measurement state must be validated
    /// against the authenticated attestation policy.
    HitlessUpdate,
}

/// Attestation availability state owned by the Measurement API.
///
/// Later Measurement API entry points gate evidence generation and component
/// measurement-state mutation on this state.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum AttestationState {
    /// Boot initialization has not completed yet.
    Uninitialized,
    /// Measurement state is valid; attestation flows may run.
    Active,
    /// Measurement state is invalid; normal attestation flows are blocked
    /// until cold boot reinitializes measurement state.
    Error,
}

/// Initialize the global Measurement API instance.
///
/// The caller provides the authenticated Attestation Manifest bytes and the
/// reset classification. After this succeeds, cert/sign/evidence paths use the
/// global Measurement API surface below so DPE Handle Storage updates remain
/// serialized.
pub async fn init<A: ApiAlloc>(
    manifest_bytes: &'static [u8],
    soc_image_load_fw_ids: &'static [u32],
    boot_kind: BootKind,
    alloc: &A,
) -> MeasurementApiResult {
    let mut api = MeasurementApi::<DefaultSyscalls>::new(manifest_bytes, soc_image_load_fw_ids)?;
    let result = api.measurement_boot_init(boot_kind, alloc).await;
    let mut guard = MEASUREMENT_API.lock().await;
    guard.replace(api);
    result
}

/// Return the DPE leaf certificate length for the configured attestation target.
pub async fn leaf_cert_size<A: ApiAlloc>(
    alloc: &A,
    key_label: &[u8; DPE_LABEL_LEN],
) -> MeasurementApiResult<usize> {
    let mut guard = MEASUREMENT_API.lock().await;
    let api = guard
        .as_mut()
        .ok_or(MeasurementApiError::AttestationDisabled)?;
    api.leaf_cert_size(alloc, key_label).await
}

/// Authorize one MCU-managed initial-load component.
pub async fn authorize_and_stash<A: ApiAlloc>(
    alloc: &A,
    fw_id: u32,
    metadata: ImageMetadata,
) -> MeasurementApiResult {
    let mut guard = MEASUREMENT_API.lock().await;
    let api = guard
        .as_mut()
        .ok_or(MeasurementApiError::AttestationDisabled)?;
    api.authorize_and_stash(alloc, fw_id, metadata).await
}

/// Fetch a DPE leaf certificate slice for the configured attestation target.
pub async fn leaf_cert_slice<A: ApiAlloc>(
    alloc: &A,
    key_label: &[u8; DPE_LABEL_LEN],
    cert_offset: u32,
    dst: &mut [u8],
) -> MeasurementApiResult<usize> {
    let mut guard = MEASUREMENT_API.lock().await;
    let api = guard
        .as_mut()
        .ok_or(MeasurementApiError::AttestationDisabled)?;
    api.leaf_cert_slice(alloc, key_label, cert_offset, dst)
        .await
}

/// Compute the COSE `kid` for the configured attestation target.
pub async fn leaf_kid<A: ApiAlloc>(
    alloc: &A,
    key_label: &[u8; DPE_LABEL_LEN],
    kid: &mut [u8; ATTESTATION_P384_DIGEST_SIZE],
) -> MeasurementApiResult {
    let mut guard = MEASUREMENT_API.lock().await;
    let api = guard
        .as_mut()
        .ok_or(MeasurementApiError::AttestationDisabled)?;
    api.leaf_kid(alloc, key_label, kid).await
}

/// Sign `digest` with the configured attestation target.
pub async fn sign<A: ApiAlloc>(
    alloc: &A,
    key_label: &[u8; DPE_LABEL_LEN],
    digest: &[u8],
    signature: &mut [u8],
) -> MeasurementApiResult<usize> {
    let mut guard = MEASUREMENT_API.lock().await;
    let api = guard
        .as_mut()
        .ok_or(MeasurementApiError::AttestationDisabled)?;
    api.sign(alloc, key_label, digest, signature).await
}
