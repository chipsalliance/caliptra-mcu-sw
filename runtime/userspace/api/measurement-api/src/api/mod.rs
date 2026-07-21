// Licensed under the Apache-2.0 license

//! The `MeasurementApi` instance.
//!
//! It owns the parsed attestation manifest view and the attestation boot/error
//! state. The DPE Handle Storage and Software PCR Storage clients are stateless
//! syscall handles, so they are instantiated on demand inside each operation
//! rather than stored. Boot initialization is performed by
//! `measurement_boot_init`.

mod component_update;
mod initial_load;

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
    dpe_certify_key_cert_size, dpe_certify_key_cert_slice, dpe_certify_key_pubkey,
    dpe_rotate_context_default, dpe_sign_ecc_p384, dpe_tag_tci, sha_finish, sha_init, sha_update,
    ApiAlloc, AuthorizeAndStashFlags, AuthorizeAndStashParams, DpeContextHandle, HashAlgo,
    DPE_LABEL_LEN, SHA_CONTEXT_SIZE,
};

use crate::attestation_manifest::{parse_and_validate, AttestationManifest, MCU_RT_FW_ID};
use crate::errors::{MeasurementApiError, MeasurementApiResult};
use crate::{AttestationState, BootKind, ImageMetadata, MeasurementOperation};

/// Owns the attestation configuration and attestation boot/error state.
///
/// The user app constructs one instance from the authenticated attestation
/// manifest bytes and drives boot initialization before any measurement
/// consumer runs. All later access to the static attestation configuration
/// goes through this instance. The store clients are cheap syscall handles
/// created on demand inside each operation.
pub(crate) struct MeasurementApi<'a, S: Syscalls = DefaultSyscalls> {
    manifest: AttestationManifest<'a>,
    soc_image_load_fw_ids: &'a [u32],
    state: AttestationState,
    _syscalls: PhantomData<S>,
}

impl<'a, S: Syscalls> MeasurementApi<'a, S> {
    /// Parse and validate the integrator attestation manifest and construct the
    /// Measurement API instance, which owns the parsed manifest view.
    ///
    /// A malformed manifest is reported as
    /// [`MeasurementApiError::InvalidManifest`].
    pub fn new(
        manifest_bytes: &'a [u8],
        soc_image_load_fw_ids: &'a [u32],
    ) -> MeasurementApiResult<Self> {
        let manifest = parse_and_validate(manifest_bytes)?;
        validate_soc_image_load_fw_ids(&manifest, soc_image_load_fw_ids)?;
        Ok(Self {
            manifest,
            soc_image_load_fw_ids,
            state: AttestationState::Uninitialized,
            _syscalls: PhantomData,
        })
    }

    /// Compute `measurement_policy_digest = SHA384(canonical manifest bytes ||
    /// ordered SOC_IMAGE_LOAD_LIST bytes)`
    ///
    /// The digest binds the authenticated integrator static attestation
    /// configuration and the cold-boot SoC load topology. Any mailbox failure
    /// is reported as [`MeasurementApiError::DigestFailed`].
    async fn measurement_policy_digest<A: ApiAlloc>(
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
        for fw_id in self.soc_image_load_fw_ids {
            sha_update(alloc, &mut state, &fw_id.to_le_bytes())
                .await
                .map_err(|_| MeasurementApiError::DigestFailed)?;
        }
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
        self.measurement_policy_digest(alloc, &mut digest).await?;

        dpe_store
            .initialize_store(&digest)
            .map_err(|_| MeasurementApiError::StoreFailed)?;
        pcr_store
            .initialize_store()
            .map_err(|_| MeasurementApiError::StoreFailed)?;

        let handle = dpe_rotate_context_default(alloc)
            .await
            .map_err(|_| MeasurementApiError::DpeCommandFailed)?;
        dpe_tag_tci(alloc, &handle, MCU_RT_FW_ID)
            .await
            .map_err(|_| MeasurementApiError::DpeCommandFailed)?;

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
        self.measurement_policy_digest(alloc, &mut digest).await?;

        // Validate both preserved stores against the policy digest before use;
        // a mismatch means the preserved state belongs to a different policy.
        dpe_store
            .validate_store(&digest)
            .map_err(|_| MeasurementApiError::InvalidDpeHandleStoreState)?;
        pcr_store
            .validate_store()
            .map_err(|_| MeasurementApiError::StoreFailed)?;

        // The preserved MCU Runtime root record must exist and be well-formed.
        let mut root = DpeHandleRecord::default();
        dpe_store
            .read_record(MCU_RT_FW_ID, &mut root)
            .map_err(|_| MeasurementApiError::InvalidDpeHandleStoreState)?;
        if !is_mcu_root_record(&root) {
            return Err(MeasurementApiError::InvalidDpeHandleStoreState);
        }

        // The active DPE leaf must be readable. Its record semantics are not
        // checked: once downstream SoC TCB components are recorded, the active
        // leaf is legitimately one of those rather than the MCU Runtime root.
        let mut leaf = DpeHandleRecord::default();
        dpe_store
            .read_leaf_record(&mut leaf)
            .map_err(|_| MeasurementApiError::InvalidDpeHandleStoreState)?;

        // The attestation target must be readable and, until downstream target
        // re-marking exists, still the MCU Runtime root.
        let mut target = DpeHandleRecord::default();
        dpe_store
            .read_attestation_target(&mut target)
            .map_err(|_| MeasurementApiError::InvalidDpeHandleStoreState)?;
        if target.fw_id != MCU_RT_FW_ID {
            return Err(MeasurementApiError::InvalidDpeHandleStoreState);
        }

        Ok(())
    }

    /// Authorize one MCU-managed component through Caliptra.
    ///
    /// Validates Measurement API state and Attestation Manifest membership,
    /// then uses public `AUTHORIZE_AND_STASH` with `SKIP_STASH=true` for
    /// authorization only. Initial-load and component-update callers then
    /// dispatch to operation-specific Measurement API state updates.
    pub async fn authorize_and_stash<A: ApiAlloc>(
        &mut self,
        alloc: &A,
        fw_id: u32,
        metadata: ImageMetadata,
    ) -> MeasurementApiResult {
        match metadata.operation {
            MeasurementOperation::InitialLoad => {
                initial_load::authorize_and_stash(self, alloc, fw_id, metadata).await
            }
            MeasurementOperation::ComponentUpdate => {
                component_update::authorize_and_stash(self, alloc, fw_id, metadata).await
            }
        }
    }

    /// Return the DPE leaf certificate length for the configured attestation
    /// target and persist the rotated target handle returned by DPE.
    pub async fn leaf_cert_size<A: ApiAlloc>(
        &mut self,
        alloc: &A,
        key_label: &[u8; DPE_LABEL_LEN],
    ) -> MeasurementApiResult<usize> {
        let target = self.read_attestation_target_record()?;
        let (next_handle, cert_size) =
            dpe_certify_key_cert_size(alloc, Some(&target.context_handle), key_label)
                .await
                .map_err(|_| MeasurementApiError::DpeCommandFailed)?;
        self.write_attestation_target_handle(target, next_handle)?;
        Ok(cert_size)
    }

    /// Fetch a DPE leaf certificate slice for the configured attestation target
    /// and persist the rotated target handle returned by DPE.
    pub async fn leaf_cert_slice<A: ApiAlloc>(
        &mut self,
        alloc: &A,
        key_label: &[u8; DPE_LABEL_LEN],
        cert_offset: u32,
        dst: &mut [u8],
    ) -> MeasurementApiResult<usize> {
        let target = self.read_attestation_target_record()?;
        let (next_handle, bytes_written) = dpe_certify_key_cert_slice(
            alloc,
            Some(&target.context_handle),
            key_label,
            cert_offset,
            dst,
        )
        .await
        .map_err(|_| MeasurementApiError::DpeCommandFailed)?;
        self.write_attestation_target_handle(target, next_handle)?;
        Ok(bytes_written)
    }

    async fn leaf_pubkey<A: ApiAlloc>(
        &mut self,
        alloc: &A,
        key_label: &[u8; DPE_LABEL_LEN],
        pubkey_x: &mut [u8; 48],
        pubkey_y: &mut [u8; 48],
    ) -> MeasurementApiResult {
        let target = self.read_attestation_target_record()?;
        let next_handle = dpe_certify_key_pubkey(
            alloc,
            Some(&target.context_handle),
            key_label,
            pubkey_x,
            pubkey_y,
        )
        .await
        .map_err(|_| MeasurementApiError::DpeCommandFailed)?;
        self.write_attestation_target_handle(target, next_handle)
    }

    /// Compute the COSE `kid` for the configured attestation target and
    /// persist the rotated target handle returned by DPE.
    pub async fn leaf_kid<A: ApiAlloc>(
        &mut self,
        alloc: &A,
        key_label: &[u8; DPE_LABEL_LEN],
        kid: &mut [u8; crate::ATTESTATION_P384_DIGEST_SIZE],
    ) -> MeasurementApiResult {
        let mut pubkey_x = [0u8; crate::ATTESTATION_P384_DIGEST_SIZE];
        let mut pubkey_y = [0u8; crate::ATTESTATION_P384_DIGEST_SIZE];
        self.leaf_pubkey(alloc, key_label, &mut pubkey_x, &mut pubkey_y)
            .await?;
        let ctx = alloc
            .alloc(SHA_CONTEXT_SIZE)
            .map_err(|_| MeasurementApiError::DigestFailed)?;
        let mut state = sha_init(alloc, ctx, HashAlgo::Sha384, &pubkey_x)
            .await
            .map_err(|_| MeasurementApiError::DigestFailed)?;
        sha_update(alloc, &mut state, &pubkey_y)
            .await
            .map_err(|_| MeasurementApiError::DigestFailed)?;
        sha_finish(alloc, &mut state, kid)
            .await
            .map_err(|_| MeasurementApiError::DigestFailed)
    }

    /// Sign a digest with the configured attestation target and persist the
    /// rotated target handle returned by DPE.
    pub async fn sign<A: ApiAlloc>(
        &mut self,
        alloc: &A,
        key_label: &[u8; DPE_LABEL_LEN],
        digest: &[u8],
        signature: &mut [u8],
    ) -> MeasurementApiResult<usize> {
        let target = self.read_attestation_target_record()?;
        let (next_handle, signature_len) = dpe_sign_ecc_p384(
            alloc,
            Some(&target.context_handle),
            key_label,
            digest,
            signature,
        )
        .await
        .map_err(|_| MeasurementApiError::DpeCommandFailed)?;
        self.write_attestation_target_handle(target, next_handle)?;
        Ok(signature_len)
    }

    /// Current attestation availability state.
    #[cfg(test)]
    pub fn attestation_state(&self) -> AttestationState {
        self.state
    }

    fn attestation_state_active(&self) -> MeasurementApiResult {
        if self.state == AttestationState::Active {
            Ok(())
        } else {
            Err(MeasurementApiError::AttestationDisabled)
        }
    }

    fn read_attestation_target_record(&self) -> MeasurementApiResult<DpeHandleRecord> {
        self.attestation_state_active()?;
        let dpe_store = DpeHandleStore::<S>::new(DPE_HANDLE_STORE_DRIVER_NUM);
        let mut target = DpeHandleRecord::default();
        dpe_store
            .read_attestation_target(&mut target)
            .map_err(|_| MeasurementApiError::InvalidDpeHandleStoreState)?;
        Ok(target)
    }

    fn write_attestation_target_handle(
        &mut self,
        mut target: DpeHandleRecord,
        next_handle: DpeContextHandle,
    ) -> MeasurementApiResult {
        target.context_handle = next_handle;
        let dpe_store = DpeHandleStore::<S>::new(DPE_HANDLE_STORE_DRIVER_NUM);
        dpe_store.write_record(target.fw_id, &target).map_err(|_| {
            self.state = AttestationState::Error;
            MeasurementApiError::StoreFailed
        })
    }

    fn enter_error_state(&mut self, error: MeasurementApiError) -> MeasurementApiError {
        self.state = AttestationState::Error;
        error
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

fn validate_soc_image_load_fw_ids(
    manifest: &AttestationManifest<'_>,
    soc_image_load_fw_ids: &[u32],
) -> MeasurementApiResult {
    if soc_image_load_fw_ids.len() != manifest.entries().count() {
        return Err(MeasurementApiError::InvalidSocImageLoadList);
    }

    for (index, fw_id) in soc_image_load_fw_ids.iter().copied().enumerate() {
        if soc_image_load_fw_ids
            .iter()
            .take(index)
            .any(|existing| *existing == fw_id)
        {
            return Err(MeasurementApiError::InvalidSocImageLoadList);
        }
        manifest
            .lookup(fw_id)
            .map_err(|_| MeasurementApiError::InvalidSocImageLoadList)?;
    }

    Ok(())
}

fn caliptra_authorize_params(fw_id: u32, metadata: ImageMetadata) -> AuthorizeAndStashParams {
    AuthorizeAndStashParams {
        fw_id,
        measurement: metadata.measurement,
        context: [0u8; 48],
        svn: metadata.svn,
        flags: AuthorizeAndStashFlags::SKIP_STASH,
        source: metadata.source,
        image_size: metadata.image_size,
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::vec::Vec;

    use super::*;
    use crate::attestation_manifest::{
        ATTESTATION_FLAG_SOC_TCB_DPE, ATTESTATION_MANIFEST_ENTRY_SIZE,
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

    fn valid_manifest_with_entries(entries: &[(u32, u32)]) -> Vec<u8> {
        let header_size = ATTESTATION_MANIFEST_FIXED_HEADER_SIZE;
        let size = header_size + entries.len() * ATTESTATION_MANIFEST_ENTRY_SIZE;
        let tcb_entry_count = entries
            .iter()
            .filter(|(_, flags)| flags & ATTESTATION_FLAG_SOC_TCB_DPE != 0)
            .count();
        let mut out = Vec::new();
        out.extend_from_slice(&ATTESTATION_MANIFEST_MARKER.to_le_bytes());
        out.extend_from_slice(&(size as u32).to_le_bytes());
        out.extend_from_slice(&ATTESTATION_MANIFEST_VERSION.to_le_bytes());
        out.extend_from_slice(&(header_size as u32).to_le_bytes());
        out.extend_from_slice(&(entries.len() as u32).to_le_bytes());
        out.extend_from_slice(&(tcb_entry_count as u32).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.resize(header_size, 0);
        for (fw_id, flags) in entries {
            out.extend_from_slice(&fw_id.to_le_bytes());
            out.extend_from_slice(&flags.to_le_bytes());
        }
        out
    }

    #[test]
    fn new_accepts_valid_manifest_and_starts_uninitialized() {
        let bytes = valid_empty_manifest();
        let api = MeasurementApi::<DefaultSyscalls>::new(&bytes, &[]).unwrap();
        assert_eq!(api.attestation_state(), AttestationState::Uninitialized);
        assert_eq!(api.manifest.attestation_target_fw_id(), MCU_RT_FW_ID);
    }

    #[test]
    fn new_rejects_malformed_manifest() {
        assert!(matches!(
            MeasurementApi::<DefaultSyscalls>::new(&[0u8; 4], &[]),
            Err(MeasurementApiError::InvalidManifest)
        ));
    }

    #[test]
    fn new_accepts_load_list_in_different_order_than_manifest() {
        let bytes =
            valid_manifest_with_entries(&[(0x1000, ATTESTATION_FLAG_SOC_TCB_DPE), (0x2000, 0)]);

        let api = MeasurementApi::<DefaultSyscalls>::new(&bytes, &[0x2000, 0x1000]).unwrap();

        assert_eq!(api.attestation_state(), AttestationState::Uninitialized);
    }

    #[test]
    fn new_rejects_duplicate_load_fw_id() {
        let bytes = valid_manifest_with_entries(&[(0x1000, 0), (0x2000, 0)]);

        assert!(matches!(
            MeasurementApi::<DefaultSyscalls>::new(&bytes, &[0x1000, 0x1000]),
            Err(MeasurementApiError::InvalidSocImageLoadList)
        ));
    }

    #[test]
    fn new_rejects_load_fw_id_missing_from_manifest() {
        let bytes = valid_manifest_with_entries(&[(0x1000, 0), (0x2000, 0)]);

        assert!(matches!(
            MeasurementApi::<DefaultSyscalls>::new(&bytes, &[0x1000, 0x3000]),
            Err(MeasurementApiError::InvalidSocImageLoadList)
        ));
    }

    #[test]
    fn new_rejects_load_list_len_mismatch() {
        let bytes = valid_manifest_with_entries(&[(0x1000, 0), (0x2000, 0)]);

        assert!(matches!(
            MeasurementApi::<DefaultSyscalls>::new(&bytes, &[0x1000]),
            Err(MeasurementApiError::InvalidSocImageLoadList)
        ));
    }

    fn reference_measurement_policy_digest(
        manifest_bytes: &[u8],
        soc_image_load_fw_ids: &[u32],
    ) -> [u8; POLICY_DIGEST_SIZE] {
        use sha2::{Digest, Sha384};

        let mut hasher = Sha384::new();
        hasher.update(manifest_bytes);
        for fw_id in soc_image_load_fw_ids {
            hasher.update(fw_id.to_le_bytes());
        }
        hasher.finalize().into()
    }

    #[test]
    fn policy_digest_reference_binds_manifest_and_ordered_load_list() {
        let bytes = valid_manifest_with_entries(&[(0x1000, 0), (0x2000, 0)]);
        let api = MeasurementApi::<DefaultSyscalls>::new(&bytes, &[0x1000, 0x2000]).unwrap();

        assert_eq!(api.manifest.bytes(), &bytes[..]);

        let reference =
            reference_measurement_policy_digest(api.manifest.bytes(), api.soc_image_load_fw_ids);
        assert_eq!(reference.len(), POLICY_DIGEST_SIZE);

        let mut changed_manifest = bytes.clone();
        changed_manifest[4] ^= 0x01;
        assert_ne!(
            reference,
            reference_measurement_policy_digest(&changed_manifest, &[0x1000, 0x2000])
        );
        assert_ne!(
            reference,
            reference_measurement_policy_digest(&bytes, &[0x2000, 0x1000])
        );
        assert_ne!(
            reference,
            reference_measurement_policy_digest(&bytes, &[0x1000])
        );
        assert_ne!(
            reference,
            reference_measurement_policy_digest(&bytes, &[0x1000, 0x2000, 0x3000])
        );
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
