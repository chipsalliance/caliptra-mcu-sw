// Licensed under the Apache-2.0 license

#![no_std]
#![allow(async_fn_in_trait)]

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
use mcu_error::McuResult;

static MEASUREMENT_API: Mutex<
    CriticalSectionRawMutex,
    Option<MeasurementApi<'static, DefaultSyscalls>>,
> = Mutex::new(None);

pub const ATTESTATION_P384_DIGEST_SIZE: usize = 48;
pub const ATTESTATION_P384_SIGNATURE_SIZE: usize = 96;
pub const EXPORTED_CDI_SIZE: usize = 32;

/// Builds evidence token buffers and the to-be-signed digest while Measurement
/// API keeps measurement state locked.
///
/// Implementations must not call back into Measurement API, because
/// [`measure_and_sign_evidence`] holds the global Measurement API lock while
/// invoking this hook.
pub trait EvidenceBuilder<A: ApiAlloc> {
    /// Return the final token `kid` slot.
    fn kid_buffer_mut(&mut self) -> McuResult<&mut [u8; ATTESTATION_P384_DIGEST_SIZE]>;

    /// Return the final concise-evidence slot.
    fn concise_evidence_buffer_mut(&mut self) -> McuResult<&mut [u8]>;

    /// Build the evidence payload from the concise evidence already written,
    /// write the signature digest into `digest`, and return the payload length.
    async fn digest_for_signature(
        &mut self,
        alloc: &A,
        concise_evidence_len: usize,
        digest: &mut [u8; ATTESTATION_P384_DIGEST_SIZE],
    ) -> McuResult<usize>;

    /// Finalize the evidence layout for `payload_len` and return the final
    /// token length plus the final signature slot.
    fn signature_buffer_mut(
        &mut self,
        payload_len: usize,
    ) -> McuResult<(usize, &mut [u8; ATTESTATION_P384_SIGNATURE_SIZE])>;
}

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

/// Generate a selected-AK `kid`, encode concise evidence, build the evidence
/// digest, and sign it as one serialized Measurement API operation.
///
/// This prevents component-update measurement mutation from interleaving between
/// the `kid`/evidence read and final signature. The caller supplies
/// `digest_builder` for the transport-neutral payload shape, but that builder
/// must not call Measurement API while this function holds the lock.
pub async fn measure_and_sign_evidence<A, B>(
    alloc: &A,
    key_label: &[u8; DPE_LABEL_LEN],
    evidence_builder: &mut B,
) -> McuResult<usize>
where
    A: ApiAlloc,
    B: EvidenceBuilder<A>,
{
    let mut guard = MEASUREMENT_API.lock().await;
    let api = guard
        .as_mut()
        .ok_or(MeasurementApiError::AttestationDisabled)?;

    {
        let kid = evidence_builder.kid_buffer_mut()?;
        api.leaf_kid(alloc, key_label, kid).await?;
    }
    let concise_evidence_len = {
        let concise_evidence = evidence_builder.concise_evidence_buffer_mut()?;
        api.encode_measurement_evidence(alloc, concise_evidence)
            .await?
    };

    let mut sig_digest_buf = alloc.alloc(ATTESTATION_P384_DIGEST_SIZE)?;
    let sig_digest = sig_digest_buf
        .get_mut(..ATTESTATION_P384_DIGEST_SIZE)
        .and_then(|buf| buf.first_chunk_mut::<ATTESTATION_P384_DIGEST_SIZE>())
        .ok_or(mcu_error::codes::INTERNAL_BUG)?;
    let payload_len = evidence_builder
        .digest_for_signature(alloc, concise_evidence_len, sig_digest)
        .await?;
    let (evidence_len, signature) = evidence_builder.signature_buffer_mut(payload_len)?;
    let sig_len = api.sign(alloc, key_label, sig_digest, signature).await?;
    if sig_len != signature.len() {
        return Err(mcu_error::codes::INTERNAL_BUG);
    }
    Ok(evidence_len)
}

/// Encode concise measurement evidence for all eligible manifest entries.
pub async fn encode_measurement_evidence<A: ApiAlloc>(
    alloc: &A,
    buffer: &mut [u8],
) -> MeasurementApiResult<usize> {
    let mut guard = MEASUREMENT_API.lock().await;
    let api = guard
        .as_mut()
        .ok_or(MeasurementApiError::AttestationDisabled)?;
    api.encode_measurement_evidence(alloc, buffer).await
}

/// Derive an exported CDI context from the configured attestation target, persist the
/// 32-byte exported CDI handle in DPE handle storage, update the rotated target handle,
/// and write the emitted leaf certificate into `cert_out`.
pub async fn export_cdi_and_stash<A: ApiAlloc>(
    alloc: &A,
    cert_out: &mut [u8],
) -> MeasurementApiResult<usize> {
    let mut guard = MEASUREMENT_API.lock().await;
    let api = guard
        .as_mut()
        .ok_or(MeasurementApiError::AttestationDisabled)?;
    api.export_cdi_and_stash(alloc, cert_out).await
}

/// Retrieve the stashed 32-byte exported CDI handle via an outparam.
pub async fn read_exported_cdi(cdi_out: &mut [u8; EXPORTED_CDI_SIZE]) -> MeasurementApiResult {
    let guard = MEASUREMENT_API.lock().await;
    let api = guard
        .as_ref()
        .ok_or(MeasurementApiError::AttestationDisabled)?;
    api.read_exported_cdi(cdi_out)
}
