// Licensed under the Apache-2.0 license

//! The `MeasurementApi` instance.
//!
//! It owns the parsed attestation manifest view and the attestation boot/error
//! state. The DPE Handle Storage and Software PCR Storage clients are stateless
//! syscall handles, so they are instantiated on demand inside each operation
//! rather than stored. Boot initialization is performed by
//! `measurement_boot_init`.

use caliptra_mcu_libsyscall_caliptra::dpe_handle_store::{
    DpeHandleRecord, DpeHandleStore, DPE_HANDLE_STORE_DRIVER_NUM, POLICY_DIGEST_SIZE,
};
use caliptra_mcu_libsyscall_caliptra::soft_pcr_store::{
    SoftwarePcrStore, SOFT_PCR_STORE_DRIVER_NUM,
};
use caliptra_mcu_libsyscall_caliptra::DefaultSyscalls;
use caliptra_mcu_libtock_platform::Syscalls;
use core::marker::PhantomData;
use mcu_caliptra_api_lite::{
    dpe_rotate_context_default, dpe_tag_tci, sha_finish, sha_init, ApiAlloc, HashAlgo,
    SHA_CONTEXT_SIZE,
};

use crate::attestation_manifest::{parse_and_validate, AttestationManifest, MCU_RT_FW_ID};
use crate::errors::{MeasurementApiError, MeasurementApiResult};
use crate::{AttestationState, BootKind};

/// Owns the attestation configuration and attestation boot/error state.
///
/// The user app constructs one instance from the authenticated attestation
/// manifest bytes and drives boot initialization before any measurement
/// consumer runs. All later access to the static attestation configuration
/// goes through this instance. The store clients are cheap syscall handles
/// created on demand inside each operation.
pub struct MeasurementApi<'a, S: Syscalls = DefaultSyscalls> {
    manifest: AttestationManifest<'a>,
    state: AttestationState,
    _syscalls: PhantomData<S>,
}

impl<'a, S: Syscalls> MeasurementApi<'a, S> {
    /// Parse and validate the integrator attestation manifest and construct the
    /// Measurement API instance, which owns the parsed manifest view.
    ///
    /// A malformed manifest is reported as
    /// [`MeasurementApiError::InvalidManifest`].
    pub fn new(manifest_bytes: &'a [u8]) -> MeasurementApiResult<Self> {
        let manifest = parse_and_validate(manifest_bytes)?;
        Ok(Self {
            manifest,
            state: AttestationState::Uninitialized,
            _syscalls: PhantomData,
        })
    }

    /// Compute `attestation_policy_digest = SHA384(canonical manifest bytes)`
    /// using the Caliptra SHA mailbox, writing it into `digest_out`.
    ///
    /// The digest is taken over the exact canonical manifest bytes, i.e. the
    /// authenticated integrator static attestation configuration. Any mailbox
    /// failure is reported as [`MeasurementApiError::DigestFailed`].
    async fn attestation_policy_digest<A: ApiAlloc>(
        &self,
        alloc: &A,
        digest_out: &mut [u8; POLICY_DIGEST_SIZE],
    ) -> MeasurementApiResult {
        let ctx = alloc
            .alloc(SHA_CONTEXT_SIZE)
            .map_err(|_| MeasurementApiError::DigestFailed)?;
        let mut state = sha_init(alloc, ctx, HashAlgo::Sha384, self.manifest.bytes())
            .await
            .map_err(|_| MeasurementApiError::DigestFailed)?;
        sha_finish(alloc, &mut state, digest_out)
            .await
            .map_err(|_| MeasurementApiError::DigestFailed)?;
        Ok(())
    }

    /// Initialize measurement state after reset.
    ///
    /// Cold boot creates fresh measurement state and writes the MCU Runtime
    /// root DPE record. Hitless update validates the preserved measurement
    /// state against the authenticated attestation policy without clearing it.
    /// On any failure the API is left in [`AttestationState::Error`] so later
    /// measurement flows fail closed; on success it becomes
    /// [`AttestationState::Active`].
    pub async fn measurement_boot_init<A: ApiAlloc>(
        &mut self,
        boot: BootKind,
        alloc: &A,
    ) -> MeasurementApiResult {
        let result = match boot {
            BootKind::ColdBoot => self.cold_boot_init(alloc).await,
            BootKind::HitlessUpdate => self.hitless_update_init(alloc).await,
        };
        self.state = if result.is_ok() {
            AttestationState::Active
        } else {
            AttestationState::Error
        };
        result
    }

    /// Cold-boot sequence: compute the policy digest, initialize both stores,
    /// rotate and tag the MCU Runtime DPE context, write the MCU Runtime root
    /// record, and mark it as the initial attestation target.
    async fn cold_boot_init<A: ApiAlloc>(&self, alloc: &A) -> MeasurementApiResult {
        let dpe_store = DpeHandleStore::<S>::new(DPE_HANDLE_STORE_DRIVER_NUM);
        let pcr_store = SoftwarePcrStore::<S>::new(SOFT_PCR_STORE_DRIVER_NUM);

        let mut digest = [0u8; POLICY_DIGEST_SIZE];
        self.attestation_policy_digest(alloc, &mut digest).await?;

        dpe_store
            .initialize_store(&digest)
            .map_err(|_| MeasurementApiError::StoreFailed)?;
        pcr_store
            .initialize_store()
            .map_err(|_| MeasurementApiError::StoreFailed)?;

        let handle = dpe_rotate_context_default(alloc)
            .await
            .map_err(|_| MeasurementApiError::DpeMailboxFailed)?;
        dpe_tag_tci(alloc, &handle, MCU_RT_FW_ID)
            .await
            .map_err(|_| MeasurementApiError::DpeMailboxFailed)?;

        let record = DpeHandleRecord {
            fw_id: MCU_RT_FW_ID,
            parent_fw_id: None,
            context_handle: handle,
            tci_tag: MCU_RT_FW_ID,
            ..Default::default()
        };
        dpe_store
            .write_record(MCU_RT_FW_ID, &record)
            .map_err(|_| MeasurementApiError::StoreFailed)?;
        dpe_store
            .mark_attestation_target(MCU_RT_FW_ID)
            .map_err(|_| MeasurementApiError::StoreFailed)?;
        Ok(())
    }

    /// Hitless-update sequence: recompute the policy digest, validate both
    /// preserved stores against it, and validate the preserved MCU Runtime
    /// root record.
    ///
    /// The preserved reserved SRAM is never cleared or reinitialized. A digest
    /// mismatch, a missing required record, or invalid root-record semantics
    /// fails closed so measurement state is not silently reinitialized under a
    /// new lineage.
    async fn hitless_update_init<A: ApiAlloc>(&self, alloc: &A) -> MeasurementApiResult {
        let dpe_store = DpeHandleStore::<S>::new(DPE_HANDLE_STORE_DRIVER_NUM);
        let pcr_store = SoftwarePcrStore::<S>::new(SOFT_PCR_STORE_DRIVER_NUM);

        let mut digest = [0u8; POLICY_DIGEST_SIZE];
        self.attestation_policy_digest(alloc, &mut digest).await?;

        // Validate both preserved stores against the policy digest before use;
        // a mismatch means the preserved state belongs to a different policy.
        dpe_store
            .validate_store(&digest)
            .map_err(|_| MeasurementApiError::InvalidPreservedState)?;
        pcr_store
            .validate_store()
            .map_err(|_| MeasurementApiError::InvalidPreservedState)?;

        // The preserved MCU Runtime root record must exist and be well-formed.
        let mut root = DpeHandleRecord::default();
        dpe_store
            .read_record(MCU_RT_FW_ID, &mut root)
            .map_err(|_| MeasurementApiError::InvalidPreservedState)?;
        if !is_mcu_root_record(&root) {
            return Err(MeasurementApiError::InvalidPreservedState);
        }

        // The active DPE leaf must be readable. Its record semantics are not
        // checked: once downstream SoC TCB components are recorded, the active
        // leaf is legitimately one of those rather than the MCU Runtime root.
        let mut leaf = DpeHandleRecord::default();
        dpe_store
            .read_leaf_record(&mut leaf)
            .map_err(|_| MeasurementApiError::InvalidPreservedState)?;

        // The attestation target must be readable and, until downstream target
        // re-marking exists, still the MCU Runtime root.
        let mut target = DpeHandleRecord::default();
        dpe_store
            .read_attestation_target(&mut target)
            .map_err(|_| MeasurementApiError::InvalidPreservedState)?;
        if target.fw_id != MCU_RT_FW_ID {
            return Err(MeasurementApiError::InvalidPreservedState);
        }

        Ok(())
    }

    /// Current attestation availability state.
    pub fn attestation_state(&self) -> AttestationState {
        self.state
    }
}

/// True if `record` has MCU Runtime root DPE record semantics: the
/// `MCU_RT_FW_ID` root context (no parent), tagged with `MCU_RT_FW_ID`, and a
/// non-default (non-zero) context handle.
fn is_mcu_root_record(record: &DpeHandleRecord) -> bool {
    record.fw_id == MCU_RT_FW_ID
        && record.parent_fw_id.is_none()
        && record.tci_tag == MCU_RT_FW_ID
        && record.context_handle != [0u8; 16]
}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::vec::Vec;

    use super::*;
    use crate::attestation_manifest::{
        ATTESTATION_MANIFEST_FIXED_HEADER_SIZE, ATTESTATION_MANIFEST_MARKER,
        ATTESTATION_MANIFEST_VERSION, MCU_RT_FW_ID,
    };

    /// Build a minimal valid manifest: no component entries, empty
    /// vendor/model platform-information strings.
    fn valid_empty_manifest() -> Vec<u8> {
        let header_size = ATTESTATION_MANIFEST_FIXED_HEADER_SIZE;
        let mut out = Vec::new();
        out.extend_from_slice(&ATTESTATION_MANIFEST_MARKER.to_le_bytes());
        out.extend_from_slice(&(header_size as u32).to_le_bytes()); // size
        out.extend_from_slice(&ATTESTATION_MANIFEST_VERSION.to_le_bytes());
        out.extend_from_slice(&(header_size as u32).to_le_bytes()); // header_size
        out.extend_from_slice(&0u32.to_le_bytes()); // entry_count
        out.extend_from_slice(&0u32.to_le_bytes()); // tcb_entry_count
        out.extend_from_slice(&0u16.to_le_bytes()); // vendor_len
        out.extend_from_slice(&0u16.to_le_bytes()); // model_len
        out.resize(header_size, 0); // zero vendor[100] + model[100]
        out
    }

    #[test]
    fn new_accepts_valid_manifest_and_starts_uninitialized() {
        let bytes = valid_empty_manifest();
        let api = MeasurementApi::<DefaultSyscalls>::new(&bytes).unwrap();
        assert_eq!(api.attestation_state(), AttestationState::Uninitialized);
        assert_eq!(api.manifest.attestation_target_fw_id(), MCU_RT_FW_ID);
    }

    #[test]
    fn new_rejects_malformed_manifest() {
        assert!(matches!(
            MeasurementApi::<DefaultSyscalls>::new(&[0u8; 4]),
            Err(MeasurementApiError::InvalidManifest)
        ));
    }

    #[test]
    fn policy_digest_input_is_exact_canonical_manifest_bytes() {
        use sha2::{Digest, Sha384};

        let bytes = valid_empty_manifest();
        let api = MeasurementApi::<DefaultSyscalls>::new(&bytes).unwrap();

        // The digest is computed over the exact canonical manifest bytes.
        assert_eq!(api.manifest.bytes(), &bytes[..]);

        // Reference SHA-384 that the mailbox digest path must reproduce.
        let reference = Sha384::digest(&bytes);
        assert_eq!(reference.len(), POLICY_DIGEST_SIZE);
        assert_eq!(&Sha384::digest(api.manifest.bytes())[..], &reference[..]);
    }

    #[test]
    fn mcu_root_record_semantics() {
        let valid = DpeHandleRecord {
            fw_id: MCU_RT_FW_ID,
            parent_fw_id: None,
            tci_tag: MCU_RT_FW_ID,
            context_handle: [1u8; 16],
            ..Default::default()
        };
        assert!(is_mcu_root_record(&valid));
        // Wrong fw_id, a parent, wrong tag, or a default (zero) handle each fail.
        assert!(!is_mcu_root_record(&DpeHandleRecord {
            fw_id: MCU_RT_FW_ID + 1,
            ..valid
        }));
        assert!(!is_mcu_root_record(&DpeHandleRecord {
            parent_fw_id: Some(1),
            ..valid
        }));
        assert!(!is_mcu_root_record(&DpeHandleRecord {
            tci_tag: 0,
            ..valid
        }));
        assert!(!is_mcu_root_record(&DpeHandleRecord {
            context_handle: [0u8; 16],
            ..valid
        }));
    }
}
