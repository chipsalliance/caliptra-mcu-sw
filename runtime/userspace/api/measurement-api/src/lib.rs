// Licensed under the Apache-2.0 license

#![no_std]
#![allow(async_fn_in_trait)]

mod api;
pub mod attestation_manifest;
pub mod errors;
pub mod image_metadata;

pub use attestation_manifest::{
    parse_and_validate_owner, parse_and_validate_owner_fw_load_list,
    parse_and_validate_owner_measurement_policy, OwnerFwLoadList, OwnerMeasurementPolicy,
    OWNER_MEASUREMENT_POLICY_IDENTIFIER, O_AUTH_KEY_ID, V_AUTH_KEY_ID,
};

use api::MeasurementApi;
use caliptra_mcu_libsyscall_caliptra::DefaultSyscalls;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::mutex::Mutex;
use errors::{MeasurementApiError, MeasurementApiResult};
pub use image_metadata::{
    ImageMetadata, ImageMetadataFlags, MeasurementOperation, IMAGE_MEASUREMENT_DIGEST_SIZE,
};
use mcu_caliptra_api::{ApiAlloc, DPE_LABEL_LEN};
pub use mcu_caliptra_api::{DpeProfile, ImageHashSource, SigningInput};
use mcu_error::McuResult;

static MEASUREMENT_API: Mutex<
    CriticalSectionRawMutex,
    Option<MeasurementApi<'static, DefaultSyscalls>>,
> = Mutex::new(None);

pub const ATTESTATION_KID_SIZE: usize = 48;
pub const ATTESTATION_P384_DIGEST_SIZE: usize = ATTESTATION_KID_SIZE;
pub const ATTESTATION_P384_SIGNATURE_SIZE: usize = 96;
pub const ATTESTATION_MLDSA87_SIGNATURE_SIZE: usize = mcu_caliptra_api::DPE_MLDSA87_SIGNATURE_SIZE;
pub const EXPORTED_CDI_SIZE: usize = 32;

/// Target algorithm for measurement evidence signing.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum MeasurementSigningAlgo {
    EccP384,
    MlDsa87,
}

/// Builds evidence token buffers and the to-be-signed digest while Measurement
/// API keeps measurement state locked.
///
/// Implementations must not call back into Measurement API, because
/// [`measure_and_sign_evidence`] holds the global Measurement API lock while
/// invoking this hook.
pub trait EvidenceBuilder<A: ApiAlloc> {
    /// Return the target signing algorithm.
    fn signing_algo(&self) -> MeasurementSigningAlgo {
        MeasurementSigningAlgo::EccP384
    }

    /// Return the final token `kid` slot.
    fn kid_buffer_mut(&mut self) -> McuResult<&mut [u8; ATTESTATION_KID_SIZE]>;

    /// Pass the ML-DSA-87 public-key hash `tr` to the builder.
    /// Only called when `signing_algo() == MeasurementSigningAlgo::MlDsa87`.
    fn set_mldsa87_tr(&mut self, _tr: &[u8; mcu_caliptra_api::MLDSA87_TR_SIZE]) -> McuResult<()> {
        Ok(())
    }

    /// Return the final concise-evidence slot.
    fn concise_evidence_buffer_mut(&mut self) -> McuResult<&mut [u8]>;

    /// Build the evidence payload and signature digest/mu from concise evidence.
    /// Writes the SHA-384 digest (48 bytes) for EccP384 or the external `mu`
    /// (64 bytes) for MlDsa87 into `signing_input`.
    async fn prepare_signing_input(
        &mut self,
        alloc: &A,
        concise_evidence_len: usize,
        signing_input: &mut [u8],
    ) -> McuResult<usize>;

    /// Finalize the evidence layout for `payload_len` and return the final
    /// token length plus the final signature slot.
    fn signature_buffer_mut(&mut self, payload_len: usize) -> McuResult<(usize, &mut [u8])>;
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

/// Policy for when evidence generation becomes available after boot init.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum EvidenceReadinessPolicy {
    /// Evidence can be emitted immediately after Measurement API boot init.
    ReadyAfterBootInit,
    /// Evidence is blocked until all initial SoC image measurements are stashed.
    RequireInitialSocLoadComplete,
}

/// Attestation availability state owned by the Measurement API.
///
/// Later Measurement API entry points gate evidence generation and component
/// measurement-state mutation on this state.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum AttestationState {
    /// Boot initialization has not completed yet.
    Uninitialized,
    /// Boot policy/root state is initialized, but initial SoC image
    /// measurements are not yet complete.
    InitialMeasurementsPending,
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
    readiness_policy: EvidenceReadinessPolicy,
    alloc: &A,
) -> MeasurementApiResult {
    let mut api = MeasurementApi::<DefaultSyscalls>::new(manifest_bytes, soc_image_load_fw_ids)?;
    let result = api
        .measurement_boot_init(boot_kind, readiness_policy, alloc)
        .await;
    let mut guard = MEASUREMENT_API.lock().await;
    guard.replace(api);
    result
}

/// Return the DPE leaf certificate length for the configured attestation target.
pub async fn leaf_cert_size<A: ApiAlloc>(
    alloc: &A,
    profile: DpeProfile,
    key_label: &[u8; DPE_LABEL_LEN],
) -> MeasurementApiResult<usize> {
    let mut guard = MEASUREMENT_API.lock().await;
    let api = guard
        .as_mut()
        .ok_or(MeasurementApiError::AttestationDisabled)?;
    api.leaf_cert_size(alloc, profile, key_label).await
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

/// Mark initial SoC image measurements complete after regular image loading.
pub async fn mark_initial_soc_load_complete() -> MeasurementApiResult {
    let mut guard = MEASUREMENT_API.lock().await;
    let api = guard
        .as_mut()
        .ok_or(MeasurementApiError::AttestationDisabled)?;
    api.mark_initial_soc_load_complete()
}

/// Fetch a DPE leaf certificate slice for the configured attestation target.
pub async fn leaf_cert_slice<A: ApiAlloc>(
    alloc: &A,
    profile: DpeProfile,
    key_label: &[u8; DPE_LABEL_LEN],
    cert_offset: u32,
    dst: &mut [u8],
) -> MeasurementApiResult<usize> {
    let mut guard = MEASUREMENT_API.lock().await;
    let api = guard
        .as_mut()
        .ok_or(MeasurementApiError::AttestationDisabled)?;
    api.leaf_cert_slice(alloc, profile, key_label, cert_offset, dst)
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

/// Sign a typed input with the configured attestation target.
pub async fn sign<A: ApiAlloc>(
    alloc: &A,
    key_label: &[u8; DPE_LABEL_LEN],
    signing_input: SigningInput<'_>,
    signature: &mut [u8],
) -> MeasurementApiResult<usize> {
    let mut guard = MEASUREMENT_API.lock().await;
    let api = guard
        .as_mut()
        .ok_or(MeasurementApiError::AttestationDisabled)?;
    api.sign(alloc, key_label, signing_input, signature).await
}

/// Generate a selected-AK `kid`, encode concise evidence, build the evidence
/// digest, and sign it as one serialized Measurement API operation.
///
/// This prevents component-update measurement mutation from interleaving between
/// the `kid`/evidence read and final signature. The caller supplies
/// `digest_builder` for the transport-neutral payload shape, but that builder
/// must not call Measurement API while this function holds the lock.
///
/// `pki_entity_slot` selects the endorsement hierarchy for the signing key.
/// TODO: it is unused while every slot signs with the same DPE leaf key; pass
/// it to the cert store once signing is slot-aware.
#[inline(never)]
pub async fn measure_and_sign_evidence<A, B>(
    alloc: &A,
    key_label: &[u8; DPE_LABEL_LEN],
    _pki_entity_slot: u8,
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

    let algo = evidence_builder.signing_algo();
    match algo {
        MeasurementSigningAlgo::EccP384 => {
            let kid = evidence_builder.kid_buffer_mut()?;
            api.leaf_kid(alloc, key_label, kid).await?;
        }
        MeasurementSigningAlgo::MlDsa87 => {
            let kid = evidence_builder.kid_buffer_mut()?;
            let mut tr = [0u8; mcu_caliptra_api::MLDSA87_TR_SIZE];
            api.leaf_kid_and_tr(alloc, key_label, kid, &mut tr).await?;
            evidence_builder.set_mldsa87_tr(&tr)?;
        }
    }
    let concise_evidence_len = {
        let concise_evidence = evidence_builder.concise_evidence_buffer_mut()?;
        api.encode_measurement_evidence(alloc, concise_evidence)
            .await?
    };

    let mut sig_buf = [0u8; mcu_caliptra_api::DPE_MLDSA87_MU_SIZE];
    let payload_len = evidence_builder
        .prepare_signing_input(alloc, concise_evidence_len, &mut sig_buf)
        .await?;
    let (evidence_len, signature) = evidence_builder.signature_buffer_mut(payload_len)?;

    let (signing_input, expected_sig_len) = match algo {
        MeasurementSigningAlgo::EccP384 => {
            let digest = sig_buf
                .get(..ATTESTATION_P384_DIGEST_SIZE)
                .and_then(|s| s.first_chunk::<ATTESTATION_P384_DIGEST_SIZE>())
                .ok_or(mcu_error::codes::INTERNAL_BUG)?;
            (
                SigningInput::EccP384Digest(digest),
                ATTESTATION_P384_SIGNATURE_SIZE,
            )
        }
        MeasurementSigningAlgo::MlDsa87 => (
            SigningInput::Mldsa87Mu(&sig_buf),
            ATTESTATION_MLDSA87_SIGNATURE_SIZE,
        ),
    };

    let sig_len = api.sign(alloc, key_label, signing_input, signature).await?;
    if sig_len != expected_sig_len {
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
    profile: DpeProfile,
    cert_out: &mut [u8],
) -> MeasurementApiResult<usize> {
    let mut guard = MEASUREMENT_API.lock().await;
    let api = guard
        .as_mut()
        .ok_or(MeasurementApiError::AttestationDisabled)?;
    api.export_cdi_and_stash(alloc, profile, cert_out).await
}

/// Retrieve the stashed 32-byte exported CDI handle via an outparam.
pub async fn read_exported_cdi(cdi_out: &mut [u8; EXPORTED_CDI_SIZE]) -> MeasurementApiResult {
    let guard = MEASUREMENT_API.lock().await;
    let api = guard
        .as_ref()
        .ok_or(MeasurementApiError::AttestationDisabled)?;
    api.read_exported_cdi(cdi_out)
}
