// Licensed under the Apache-2.0 license

//! The `MeasurementApi` instance.
//!
//! It owns the parsed attestation manifest view and the attestation boot/error
//! state. The DPE Handle Storage and Software PCR Storage clients are stateless
//! syscall handles, so they are instantiated on demand inside each operation
//! rather than stored. Boot initialization is performed by
//! `measurement_boot_init`.

mod component_update;
#[allow(dead_code)]
mod evidence;
mod initial_load;
#[allow(dead_code)]
pub(crate) mod read;

use caliptra_mcu_libsyscall_caliptra::dpe_handle_store::{
    DpeHandleRecord, DpeHandleStore, DPE_HANDLE_STORE_DRIVER_NUM, EXPORTED_CDI_SIZE,
    POLICY_DIGEST_SIZE,
};
use caliptra_mcu_libsyscall_caliptra::soft_pcr_store::{
    SoftwarePcrStore, SOFT_PCR_STORE_DRIVER_NUM,
};
use caliptra_mcu_libsyscall_caliptra::DefaultSyscalls;
use caliptra_mcu_libtock_platform::Syscalls;
use core::marker::PhantomData;
use mcu_caliptra_api::{
    authorize_and_stash as caliptra_authorize, dpe_certify_key_cert_size,
    dpe_certify_key_cert_slice, dpe_certify_key_mldsa87_tr, dpe_certify_key_pubkey,
    dpe_derive_context_exported_cdi, dpe_rotate_context_default, dpe_sign, dpe_tag_tci, sha_finish,
    sha_init, sha_update, AuthManifestSource, AuthorizeAndStashFlags, AuthorizeAndStashParams,
    DpeContextHandle, DpeDeriveContextFlags, DpeDeriveContextParams, DpeProfile, HashAlgo,
    ScratchAlloc, SigningInput, DPE_CONTEXT_HANDLE_SIZE, DPE_LABEL_LEN, DPE_TCI_MEASUREMENT_SIZE,
    MLDSA87_TR_SIZE, SHA_CONTEXT_SIZE,
};

use crate::attestation_manifest::{
    parse_and_validate, parse_and_validate_owner_measurement_policy, AttestationManifest,
    AttestationManifestEntry, OwnerMeasurementPolicy, ATTESTATION_FLAG_SOC_TCB_DPE, MCU_RT_FW_ID,
    OWNER_MEASUREMENT_POLICY_IDENTIFIER, OWSM_FW_ID, O_AUTH_KEY_ID, V_AUTH_KEY_ID,
};
use crate::errors::{MeasurementApiError, MeasurementApiResult};
use crate::{
    AttestationState, BootKind, EvidenceReadinessPolicy, ImageMetadata, MeasurementOperation,
};

// OWSM is a measured control component, not an authorization manifest entry.
const OWSM_ENTRY: AttestationManifestEntry = AttestationManifestEntry {
    fw_id: OWSM_FW_ID,
    attestation_flags: ATTESTATION_FLAG_SOC_TCB_DPE,
};

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
    owner_policy: Option<OwnerMeasurementPolicy<'a>>,
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
            owner_policy: None,
            state: AttestationState::Uninitialized,
            _syscalls: PhantomData,
        })
    }

    /// Validate and set authenticated Owner Measurement Policy (Component 0x0000_0005).
    pub fn validate_and_set_owner_policy(
        &mut self,
        owner_policy_bytes: &'a [u8],
    ) -> MeasurementApiResult {
        let policy = parse_and_validate_owner_measurement_policy(owner_policy_bytes)
            .map_err(|_| MeasurementApiError::InvalidManifest)?;
        self.owner_policy = Some(policy);
        Ok(())
    }

    /// Return the currently attached Owner Measurement Policy, if any.
    #[allow(dead_code)]
    pub fn owner_policy(&self) -> Option<&OwnerMeasurementPolicy<'a>> {
        self.owner_policy.as_ref()
    }

    /// Lookup a component across the Base Attestation Manifest and Owner Attestation Manifest.
    ///
    /// Also returns the Caliptra auth manifest source that authorizes the component:
    /// `VendorOwner` for Base Attestation Manifest entries and `Owner` for entries
    /// resolved only through the Owner Attestation Manifest.
    pub(crate) fn manifest_lookup(
        &self,
        fw_id: u32,
    ) -> Result<(AttestationManifestEntry, AuthManifestSource), MeasurementApiError> {
        if let Ok(entry) = self.manifest.lookup(fw_id) {
            return Ok((entry, AuthManifestSource::VendorOwner));
        }
        if let Some(owner) = &self.owner_policy {
            if let Ok(entry) = owner.manifest().lookup(fw_id) {
                return Ok((entry, AuthManifestSource::Owner));
            }
        }
        Err(MeasurementApiError::UnknownFwId)
    }

    /// Compute `measurement_policy_digest = SHA384(canonical manifest bytes ||
    /// ordered SOC_IMAGE_LOAD_LIST bytes)`
    ///
    /// The digest binds the authenticated integrator static attestation
    /// configuration and the cold-boot SoC load topology. Any mailbox failure
    /// is reported as [`MeasurementApiError::DigestFailed`].
    async fn measurement_policy_digest<A: ScratchAlloc>(
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
    pub async fn measurement_boot_init<A: ScratchAlloc>(
        &mut self,
        boot: BootKind,
        readiness_policy: EvidenceReadinessPolicy,
        alloc: &A,
    ) -> MeasurementApiResult {
        let result = match boot {
            BootKind::ColdBoot => self.cold_boot_init(alloc).await,
            BootKind::HitlessUpdate => self.hitless_update_init(alloc).await,
        };
        self.state = if result.is_ok() {
            match readiness_policy {
                EvidenceReadinessPolicy::RequireInitialSocLoadComplete => {
                    AttestationState::InitialMeasurementsPending
                }
                EvidenceReadinessPolicy::ReadyAfterBootInit => AttestationState::Active,
            }
        } else {
            AttestationState::Error
        };
        result
    }

    /// Cold-boot sequence: compute the policy digest, initialize both stores,
    /// rotate and tag the MCU Runtime DPE context, write the MCU Runtime root
    /// record, and mark it as the initial attestation target.
    async fn cold_boot_init<A: ScratchAlloc>(&self, alloc: &A) -> MeasurementApiResult {
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
    async fn hitless_update_init<A: ScratchAlloc>(&self, alloc: &A) -> MeasurementApiResult {
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
    pub async fn authorize_and_stash<A: ScratchAlloc>(
        &mut self,
        alloc: &A,
        fw_id: u32,
        metadata: ImageMetadata,
    ) -> MeasurementApiResult {
        self.initial_load_measurement_state_ready()?;
        let (entry, manifest_source) = self
            .manifest_lookup(fw_id)
            .map_err(|_| MeasurementApiError::UnknownFwId)?;

        let params = caliptra_authorize_params(fw_id, metadata, manifest_source);
        caliptra_authorize(alloc, &params)
            .await
            .map_err(|_| MeasurementApiError::ImageAuthorizationFailed)?;

        match metadata.operation {
            MeasurementOperation::InitialLoad => {
                initial_load::record_authorized_image(self, alloc, entry, metadata).await
            }
            MeasurementOperation::ComponentUpdate => {
                component_update::record_authorized_image(self, alloc, entry, metadata).await
            }
        }
    }

    /// Measure or sync the Vendor Authorization Key (`0x0000_0004`) under the `MCU_RT` DPE context.
    ///
    /// On cold boot, derives and tags a new DPE context and extends PCR31.
    /// On hitless update, checks if the key matches the preserved DPE measurement;
    /// if unchanged, retains the context without re-extending PCR31; if changed, updates
    /// the context measurement and extends PCR31 once.
    pub async fn measure_vendor_auth_key<A: ScratchAlloc>(
        &mut self,
        alloc: &A,
        vendor_auth_key_digest: &[u8; crate::IMAGE_MEASUREMENT_DIGEST_SIZE],
        boot: BootKind,
    ) -> MeasurementApiResult {
        self.manifest
            .lookup(V_AUTH_KEY_ID)
            .map_err(|_| MeasurementApiError::InvalidManifest)?;
        match boot {
            BootKind::ColdBoot => {
                initial_load::create_dpe_context(
                    self,
                    alloc,
                    V_AUTH_KEY_ID,
                    vendor_auth_key_digest,
                    0,
                    false,
                )
                .await
            }
            BootKind::HitlessUpdate => {
                component_update::update_dpe_context(
                    self,
                    alloc,
                    V_AUTH_KEY_ID,
                    vendor_auth_key_digest,
                    component_update::DpeUpdateMode::UpdateIfChanged,
                )
                .await
            }
        }
    }

    /// Measure or sync the Owner Authorization Manifest preamble (`0x0000_0003`) under the Vendor Auth Key DPE context.
    pub async fn measure_owsm<A: ScratchAlloc>(
        &mut self,
        alloc: &A,
        preamble_digest: &[u8; crate::IMAGE_MEASUREMENT_DIGEST_SIZE],
        svn: u32,
        boot: BootKind,
    ) -> MeasurementApiResult {
        match boot {
            BootKind::ColdBoot => {
                initial_load::create_dpe_context(
                    self,
                    alloc,
                    OWSM_FW_ID,
                    preamble_digest,
                    svn,
                    false,
                )
                .await
            }
            BootKind::HitlessUpdate => {
                component_update::update_dpe_context(
                    self,
                    alloc,
                    OWSM_FW_ID,
                    preamble_digest,
                    component_update::DpeUpdateMode::UpdateIfChanged,
                )
                .await
            }
        }
    }

    /// Measure or sync the Owner Measurement Policy (`0x0000_0005`) under the OWSM DPE context.
    pub async fn measure_owner_measurement_policy<A: ScratchAlloc>(
        &mut self,
        alloc: &A,
        policy_digest: &[u8; crate::IMAGE_MEASUREMENT_DIGEST_SIZE],
        boot: BootKind,
    ) -> MeasurementApiResult {
        match boot {
            BootKind::ColdBoot => {
                initial_load::create_dpe_context(
                    self,
                    alloc,
                    OWNER_MEASUREMENT_POLICY_IDENTIFIER,
                    policy_digest,
                    0,
                    false,
                )
                .await
            }
            BootKind::HitlessUpdate => {
                component_update::update_dpe_context(
                    self,
                    alloc,
                    OWNER_MEASUREMENT_POLICY_IDENTIFIER,
                    policy_digest,
                    component_update::DpeUpdateMode::VerifyUnchanged,
                )
                .await
            }
        }
    }

    /// Measure or sync the Owner Authorization Key (`0x0000_0006`) under the Owner Policy DPE context.
    pub async fn measure_owner_auth_key<A: ScratchAlloc>(
        &mut self,
        alloc: &A,
        owner_auth_key_digest: &[u8; crate::IMAGE_MEASUREMENT_DIGEST_SIZE],
        boot: BootKind,
    ) -> MeasurementApiResult {
        match boot {
            BootKind::ColdBoot => {
                initial_load::create_dpe_context(
                    self,
                    alloc,
                    O_AUTH_KEY_ID,
                    owner_auth_key_digest,
                    0,
                    false,
                )
                .await
            }
            BootKind::HitlessUpdate => {
                component_update::update_dpe_context(
                    self,
                    alloc,
                    O_AUTH_KEY_ID,
                    owner_auth_key_digest,
                    component_update::DpeUpdateMode::UpdateIfChanged,
                )
                .await
            }
        }
    }

    /// Return the DPE leaf certificate length for the configured attestation
    /// target and persist the rotated target handle returned by DPE.
    pub async fn leaf_cert_size<A: ScratchAlloc>(
        &mut self,
        alloc: &A,
        profile: DpeProfile,
        key_label: &[u8; DPE_LABEL_LEN],
    ) -> MeasurementApiResult<usize> {
        let target = self.read_attestation_target_record()?;
        let (next_handle, cert_size) =
            dpe_certify_key_cert_size(alloc, profile, Some(&target.context_handle), key_label)
                .await
                .map_err(|_| MeasurementApiError::DpeCommandFailed)?;
        self.write_attestation_target_handle(target, next_handle)?;
        Ok(cert_size)
    }

    /// Fetch a DPE leaf certificate slice for the configured attestation target
    /// and persist the rotated target handle returned by DPE.
    pub async fn leaf_cert_slice<A: ScratchAlloc>(
        &mut self,
        alloc: &A,
        profile: DpeProfile,
        key_label: &[u8; DPE_LABEL_LEN],
        cert_offset: u32,
        dst: &mut [u8],
    ) -> MeasurementApiResult<usize> {
        let target = self.read_attestation_target_record()?;
        let (next_handle, bytes_written) = dpe_certify_key_cert_slice(
            alloc,
            profile,
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

    async fn leaf_pubkey<A: ScratchAlloc>(
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
    pub async fn leaf_kid<A: ScratchAlloc>(
        &mut self,
        alloc: &A,
        key_label: &[u8; DPE_LABEL_LEN],
        kid: &mut [u8; crate::ATTESTATION_P384_DIGEST_SIZE],
    ) -> MeasurementApiResult {
        let mut pubkey_y_buf = alloc
            .alloc(crate::ATTESTATION_P384_DIGEST_SIZE)
            .map_err(|_| MeasurementApiError::DpeCommandFailed)?;
        let pubkey_y = pubkey_y_buf
            .get_mut(..crate::ATTESTATION_P384_DIGEST_SIZE)
            .and_then(|buf| buf.first_chunk_mut::<{ crate::ATTESTATION_P384_DIGEST_SIZE }>())
            .ok_or(MeasurementApiError::DpeCommandFailed)?;

        self.leaf_pubkey(alloc, key_label, kid, pubkey_y).await?;
        let ctx = alloc
            .alloc(SHA_CONTEXT_SIZE)
            .map_err(|_| MeasurementApiError::DigestFailed)?;
        let mut state = sha_init(alloc, ctx, HashAlgo::Sha384, kid)
            .await
            .map_err(|_| MeasurementApiError::DigestFailed)?;
        sha_update(alloc, &mut state, pubkey_y)
            .await
            .map_err(|_| MeasurementApiError::DigestFailed)?;
        sha_finish(alloc, &mut state, kid)
            .await
            .map_err(|_| MeasurementApiError::DigestFailed)
    }

    /// Compute the COSE `kid` and ML-DSA-87 public-key hash `tr` for the
    /// configured attestation target and persist the rotated target handle
    /// returned by DPE.
    pub async fn leaf_kid_and_tr<A: ScratchAlloc>(
        &mut self,
        alloc: &A,
        key_label: &[u8; DPE_LABEL_LEN],
        kid: &mut [u8; crate::ATTESTATION_KID_SIZE],
        tr: &mut [u8; MLDSA87_TR_SIZE],
    ) -> MeasurementApiResult {
        let target = self.read_attestation_target_record()?;
        let next_handle =
            dpe_certify_key_mldsa87_tr(alloc, Some(&target.context_handle), key_label, tr)
                .await
                .map_err(|_| MeasurementApiError::DpeCommandFailed)?;

        let kid_bytes = tr
            .get(..crate::ATTESTATION_KID_SIZE)
            .ok_or(MeasurementApiError::DigestFailed)?;
        if kid.len() != kid_bytes.len() {
            return Err(MeasurementApiError::DigestFailed);
        }
        kid.copy_from_slice(kid_bytes);
        self.write_attestation_target_handle(target, next_handle)
    }

    /// Sign a typed input with the configured attestation target and persist
    /// the rotated target handle returned by DPE.
    pub async fn sign<A: ScratchAlloc>(
        &mut self,
        alloc: &A,
        key_label: &[u8; DPE_LABEL_LEN],
        signing_input: SigningInput<'_>,
        signature: &mut [u8],
    ) -> MeasurementApiResult<usize> {
        let target = self.read_attestation_target_record()?;
        let (next_handle, signature_len) = dpe_sign(
            alloc,
            Some(&target.context_handle),
            key_label,
            signing_input,
            signature,
        )
        .await
        .map_err(|_| self.enter_error_state(MeasurementApiError::DpeCommandFailed))?;
        self.write_attestation_target_handle(target, next_handle)?;
        Ok(signature_len)
    }

    /// Derive an exported CDI context from the active attestation target, persist the
    /// 32-byte exported CDI handle in DPE handle storage, persist the rotated target handle
    /// returned by DPE, and write the emitted leaf certificate into `cert_out`.
    pub async fn export_cdi_and_stash<A: ScratchAlloc>(
        &mut self,
        alloc: &A,
        profile: DpeProfile,
        cert_out: &mut [u8],
    ) -> MeasurementApiResult<usize> {
        self.attestation_state_active()?;

        let dpe_store = DpeHandleStore::<S>::new(DPE_HANDLE_STORE_DRIVER_NUM);
        let mut existing_cdi = [0u8; EXPORTED_CDI_SIZE];
        if dpe_store.read_exported_cdi(&mut existing_cdi).is_ok()
            && existing_cdi != [0u8; EXPORTED_CDI_SIZE]
        {
            return Err(MeasurementApiError::ExportedCdiAlreadyDerived);
        }

        let target = self.read_attestation_target_record()?;
        let params = DpeDeriveContextParams {
            parent_handle: target.context_handle,
            measurement: [0u8; DPE_TCI_MEASUREMENT_SIZE],
            flags: DpeDeriveContextFlags::EXPORT_CDI
                | DpeDeriveContextFlags::CREATE_CERTIFICATE
                | DpeDeriveContextFlags::RETAIN_PARENT_CONTEXT,
            tci_type: 0,
            target_locality: 0,
            svn: 0,
        };
        let derived = dpe_derive_context_exported_cdi(alloc, &params, profile, cert_out)
            .await
            .map_err(|_| MeasurementApiError::DpeCommandFailed)?;

        dpe_store
            .write_exported_cdi(&derived.exported_cdi)
            .map_err(|_| self.enter_error_state(MeasurementApiError::StoreFailed))?;

        self.write_attestation_target_handle(target, derived.parent_handle)?;
        Ok(derived.cert_size)
    }

    /// Read the stored 32-byte exported CDI handle from DPE handle storage into `cdi_out`.
    pub fn read_exported_cdi(&self, cdi_out: &mut [u8; EXPORTED_CDI_SIZE]) -> MeasurementApiResult {
        self.attestation_state_active()?;
        let dpe_store = DpeHandleStore::<S>::new(DPE_HANDLE_STORE_DRIVER_NUM);
        dpe_store
            .read_exported_cdi(cdi_out)
            .map_err(|_| MeasurementApiError::StoreFailed)?;
        if *cdi_out == [0u8; EXPORTED_CDI_SIZE] {
            return Err(MeasurementApiError::ExportedCdiNotDerived);
        }
        Ok(())
    }

    /// Read stored measurement state for one manifest `fw_id`.
    ///
    /// This is an internal Measurement API primitive for evidence generation and
    /// diagnostics. Transport code should not iterate policy or call it directly.
    #[allow(dead_code)]
    pub(crate) async fn read_measurement<A: ScratchAlloc>(
        &self,
        alloc: &A,
        fw_id: u32,
    ) -> MeasurementApiResult<read::MeasurementValue> {
        read::read_measurement(self, alloc, fw_id).await
    }

    /// Return whether a TCB measurement should be included for the selected AK.
    ///
    /// TCB records on the selected AK lineage are omitted because they are
    /// already represented by the selected DPE context; sibling TCBs remain
    /// eligible for evidence.
    #[allow(dead_code)]
    pub(crate) fn should_include_tcb_measurement(&self, fw_id: u32) -> MeasurementApiResult<bool> {
        read::should_include_tcb_measurement(self, fw_id)
    }

    /// Encode concise measurement evidence for all eligible manifest entries.
    ///
    /// Measurement API owns manifest iteration and selected-AK lineage policy;
    /// callers provide only the output buffer. On success the returned length is
    /// the complete encoded evidence size. A too-small buffer returns
    /// [`MeasurementApiError::EvidenceBufferTooSmall`] without returning a
    /// partial length.
    pub async fn encode_measurement_evidence<A: ScratchAlloc>(
        &self,
        alloc: &A,
        buffer: &mut [u8],
    ) -> MeasurementApiResult<usize> {
        self.attestation_state_active()?;
        let measurement_count = self.evidence_measurement_count()?;
        let mut encoder = evidence::MeasurementEvidenceEncoder::new(
            buffer,
            self.manifest.vendor(),
            self.manifest.model(),
            measurement_count,
        )?;
        for entry in self.evidence_entries() {
            if !evidence::inventory_evidence_eligible(entry) {
                continue;
            }
            if entry.is_tcb() && !self.should_include_tcb_measurement(entry.fw_id)? {
                continue;
            }
            let measurement = self.read_measurement(alloc, entry.fw_id).await?;
            encoder.encode_measurement(&measurement)?;
        }
        encoder.finish()
    }

    /// Mark initial SoC image measurement state complete.
    pub fn mark_initial_soc_load_complete(&mut self) -> MeasurementApiResult {
        match self.state {
            AttestationState::InitialMeasurementsPending | AttestationState::Active => {}
            AttestationState::Uninitialized | AttestationState::Error => {
                return Err(MeasurementApiError::AttestationDisabled);
            }
        }

        for fw_id in self.soc_image_load_fw_ids {
            let entry = self
                .manifest
                .lookup(*fw_id)
                .map_err(|_| MeasurementApiError::UnknownFwId)?;
            validate_loaded_record::<S>(entry)?;
        }
        if let Some(owner) = &self.owner_policy {
            let owner_manifest = owner.manifest();
            for fw_id in owner.load_list().entries() {
                let entry = owner_manifest
                    .lookup(fw_id)
                    .map_err(|_| MeasurementApiError::UnknownFwId)?;
                validate_loaded_record::<S>(entry)?;
            }
        }
        self.state = AttestationState::Active;
        Ok(())
    }

    /// Permanently transition to error state.
    pub fn disable_attestation(&mut self) {
        self.state = AttestationState::Error;
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

    fn initial_load_measurement_state_ready(&self) -> MeasurementApiResult {
        match self.state {
            AttestationState::InitialMeasurementsPending | AttestationState::Active => Ok(()),
            AttestationState::Uninitialized | AttestationState::Error => {
                Err(MeasurementApiError::AttestationDisabled)
            }
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

    fn evidence_entries(&self) -> impl Iterator<Item = AttestationManifestEntry> + '_ {
        self.manifest
            .entries()
            .chain(self.owner_policy.as_ref().map(|_| OWSM_ENTRY))
            .chain(
                self.owner_policy
                    .iter()
                    .flat_map(|owner| owner.manifest().entries()),
            )
    }

    fn evidence_measurement_count(&self) -> MeasurementApiResult<usize> {
        let mut count = 0usize;
        for entry in self.evidence_entries() {
            if !evidence::inventory_evidence_eligible(entry) {
                continue;
            }
            if entry.is_tcb() && !self.should_include_tcb_measurement(entry.fw_id)? {
                continue;
            }
            count = count
                .checked_add(1)
                .ok_or(MeasurementApiError::InvalidManifest)?;
        }
        Ok(count)
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

fn validate_loaded_record<S: Syscalls>(entry: AttestationManifestEntry) -> MeasurementApiResult {
    if entry.is_tcb() {
        validate_loaded_tcb_record::<S>(entry.fw_id)
    } else {
        validate_loaded_non_tcb_record::<S>(entry.fw_id)
    }
}

fn validate_loaded_tcb_record<S: Syscalls>(fw_id: u32) -> MeasurementApiResult {
    let dpe_store = DpeHandleStore::<S>::new(DPE_HANDLE_STORE_DRIVER_NUM);
    let mut record = DpeHandleRecord::default();
    dpe_store
        .read_record(fw_id, &mut record)
        .map_err(|_| MeasurementApiError::InvalidDpeHandleStoreState)?;
    if record.fw_id != fw_id {
        return Err(MeasurementApiError::InvalidDpeHandleStoreState);
    }
    if record.fw_id == MCU_RT_FW_ID {
        if is_mcu_root_record(&record) {
            return Ok(());
        }
        return Err(MeasurementApiError::InvalidDpeHandleStoreState);
    }
    if record.parent_fw_id.is_none()
        || record.tci_tag != fw_id
        || record.context_handle == [0u8; DPE_CONTEXT_HANDLE_SIZE]
    {
        return Err(MeasurementApiError::InvalidDpeHandleStoreState);
    }
    Ok(())
}

fn validate_loaded_non_tcb_record<S: Syscalls>(fw_id: u32) -> MeasurementApiResult {
    let pcr_store = SoftwarePcrStore::<S>::new(SOFT_PCR_STORE_DRIVER_NUM);
    let mut record = caliptra_mcu_libsyscall_caliptra::soft_pcr_store::MeasurementRecord::default();
    pcr_store
        .read_measurement(fw_id, &mut record)
        .map_err(|_| MeasurementApiError::InvalidSoftwarePcrStoreState)?;
    if record.fw_id == fw_id {
        Ok(())
    } else {
        Err(MeasurementApiError::InvalidSoftwarePcrStoreState)
    }
}

fn validate_soc_image_load_fw_ids(
    manifest: &AttestationManifest<'_>,
    soc_image_load_fw_ids: &[u32],
) -> MeasurementApiResult {
    let expected_count = manifest
        .entries()
        .filter(|entry| entry.fw_id != V_AUTH_KEY_ID)
        .count();
    if soc_image_load_fw_ids.len() != expected_count {
        return Err(MeasurementApiError::InvalidSocImageLoadList);
    }

    for (index, fw_id) in soc_image_load_fw_ids.iter().copied().enumerate() {
        if fw_id == V_AUTH_KEY_ID {
            return Err(MeasurementApiError::InvalidSocImageLoadList);
        }
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

fn caliptra_authorize_params(
    fw_id: u32,
    metadata: ImageMetadata,
    manifest_source: AuthManifestSource,
) -> AuthorizeAndStashParams {
    AuthorizeAndStashParams {
        fw_id,
        measurement: metadata.measurement,
        context: [0u8; 48],
        svn: metadata.svn,
        flags: AuthorizeAndStashFlags::SKIP_STASH,
        source: metadata.source,
        image_size: metadata.image_size,
        manifest_source,
    }
}

pub(super) async fn software_pcr_extend_digest<A: ScratchAlloc>(
    alloc: &A,
    previous_digest: &[u8; crate::IMAGE_MEASUREMENT_DIGEST_SIZE],
    measurement: &[u8; crate::IMAGE_MEASUREMENT_DIGEST_SIZE],
    digest: &mut [u8; crate::IMAGE_MEASUREMENT_DIGEST_SIZE],
) -> MeasurementApiResult {
    let ctx = alloc
        .alloc(SHA_CONTEXT_SIZE)
        .map_err(|_| MeasurementApiError::DigestFailed)?;
    let mut state = sha_init(alloc, ctx, HashAlgo::Sha384, previous_digest)
        .await
        .map_err(|_| MeasurementApiError::DigestFailed)?;
    sha_update(alloc, &mut state, measurement)
        .await
        .map_err(|_| MeasurementApiError::DigestFailed)?;
    sha_finish(alloc, &mut state, digest)
        .await
        .map_err(|_| MeasurementApiError::DigestFailed)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use core::cell::RefCell;
    use core::future::Future;
    use core::task::{Context, Poll, Waker};
    use std::rc::Rc;
    use std::sync::Mutex;
    use std::vec::Vec;

    use super::*;
    use crate::attestation_manifest::{
        ATTESTATION_FLAG_AK_TARGET, ATTESTATION_FLAG_SOC_TCB_DPE, ATTESTATION_MANIFEST_ENTRY_SIZE,
        ATTESTATION_MANIFEST_FIXED_HEADER_SIZE, ATTESTATION_MANIFEST_MARKER,
        ATTESTATION_MANIFEST_VERSION, MCU_RT_FW_ID, OWNER_ATTESTATION_MANIFEST_FIXED_HEADER_SIZE,
        OWNER_ATTESTATION_MANIFEST_MARKER, OWNER_FW_LOAD_LIST_FIXED_HEADER_SIZE,
        OWNER_FW_LOAD_LIST_MARKER, OWNER_FW_LOAD_LIST_VERSION,
    };
    use caliptra_mcu_attestation_evidence::ocp_eat::{
        CONCISE_EVIDENCE_MAX_SIZE, CONCISE_EVIDENCE_MEASUREMENT_COUNT,
    };
    use caliptra_mcu_libsyscall_caliptra::mailbox::MAILBOX_DRIVER_NUM;
    use caliptra_mcu_libsyscall_caliptra::soft_pcr_store::MeasurementRecord;
    use caliptra_mcu_libtock_platform::{CommandReturn, ErrorCode};
    use caliptra_mcu_libtock_unittest::{command_return, fake, DriverInfo, RwAllowBuffer};

    static EVIDENCE_TEST_LOCK: Mutex<()> = Mutex::new(());

    struct TestAlloc;

    impl ScratchAlloc for TestAlloc {
        type Buf<'a> = Vec<u8>;

        fn alloc(&self, len: usize) -> mcu_error::McuResult<Self::Buf<'_>> {
            Ok(std::vec![0; len])
        }
    }

    struct TestMeasurementStore {
        driver_num: u32,
        target_fw_id: u32,
        records: RefCell<Vec<(u32, Vec<u8>)>>,
        output: RefCell<RwAllowBuffer>,
    }

    impl fake::SyscallDriver for TestMeasurementStore {
        fn info(&self) -> DriverInfo {
            DriverInfo::new(self.driver_num)
        }

        fn command(&self, command: u32, fw_id: u32, _: u32) -> CommandReturn {
            let fw_id = match command {
                1 => fw_id,
                6 if self.driver_num == DPE_HANDLE_STORE_DRIVER_NUM => self.target_fw_id,
                _ => return command_return::failure(ErrorCode::NoSupport),
            };
            let records = self.records.borrow();
            let Some((_, record)) = records.iter().find(|(id, _)| *id == fw_id) else {
                return command_return::failure(ErrorCode::Fail);
            };
            self.output.borrow_mut().copy_from_slice(record);
            command_return::success()
        }

        fn allow_readwrite(
            &self,
            buffer_num: u32,
            buffer: RwAllowBuffer,
        ) -> Result<RwAllowBuffer, (RwAllowBuffer, ErrorCode)> {
            if buffer_num == 0 {
                Ok(self.output.replace(buffer))
            } else {
                Err((buffer, ErrorCode::Invalid))
            }
        }
    }

    fn run<T>(future: impl Future<Output = T>) -> T {
        let mut future = core::pin::pin!(future);
        let mut context = Context::from_waker(Waker::noop());
        for _ in 0..32 {
            if let Poll::Ready(value) = future.as_mut().poll(&mut context) {
                return value;
            }
            DefaultSyscalls::yield_no_wait();
            // The fake mailbox retains completed-command buffers.
            DefaultSyscalls::unallow_ro(MAILBOX_DRIVER_NUM, 0);
            DefaultSyscalls::unallow_rw(MAILBOX_DRIVER_NUM, 0);
        }
        panic!("Measurement evidence did not complete");
    }

    fn owner_evidence_policy() -> Vec<u8> {
        let entries = [
            (
                OWNER_MEASUREMENT_POLICY_IDENTIFIER,
                ATTESTATION_FLAG_SOC_TCB_DPE,
            ),
            (O_AUTH_KEY_ID, ATTESTATION_FLAG_SOC_TCB_DPE),
            (0x10000, ATTESTATION_FLAG_SOC_TCB_DPE),
            (0x10001, 0),
        ];
        let header_size = OWNER_ATTESTATION_MANIFEST_FIXED_HEADER_SIZE;
        let size = header_size + entries.len() * ATTESTATION_MANIFEST_ENTRY_SIZE;
        let mut bytes = Vec::new();
        for value in [
            OWNER_ATTESTATION_MANIFEST_MARKER,
            size as u32,
            ATTESTATION_MANIFEST_VERSION,
            header_size as u32,
            entries.len() as u32,
            3,
        ] {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        bytes.extend_from_slice(&[0; 4]);
        for (fw_id, flags) in entries {
            bytes.extend_from_slice(&fw_id.to_le_bytes());
            bytes.extend_from_slice(&flags.to_le_bytes());
        }
        for value in [
            OWNER_FW_LOAD_LIST_MARKER,
            (OWNER_FW_LOAD_LIST_FIXED_HEADER_SIZE + 8) as u32,
            OWNER_FW_LOAD_LIST_VERSION,
            2,
            0x10000,
            0x10001,
        ] {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        bytes
    }

    fn evidence_measurements() -> Vec<read::MeasurementValue> {
        [
            V_AUTH_KEY_ID,
            0x1000,
            0x2000,
            OWSM_FW_ID,
            OWNER_MEASUREMENT_POLICY_IDENTIFIER,
            O_AUTH_KEY_ID,
            0x10000,
            0x10001,
        ]
        .into_iter()
        .enumerate()
        .map(|(index, fw_id)| read::MeasurementValue {
            target_env_id: fw_id,
            current_digest: [index as u8 + 1; DPE_TCI_MEASUREMENT_SIZE],
            journey_digest: [index as u8 + 0x81; DPE_TCI_MEASUREMENT_SIZE],
            svn: match fw_id {
                0x2000 | 0x10001 => u64::from(u32::MAX),
                _ => 0,
            },
        })
        .collect()
    }

    fn evidence_stores(
        kernel: &fake::Kernel,
        target_fw_id: u32,
        measurements: &[read::MeasurementValue],
    ) -> (Rc<TestMeasurementStore>, Rc<TestMeasurementStore>) {
        let chain = [
            MCU_RT_FW_ID,
            V_AUTH_KEY_ID,
            OWSM_FW_ID,
            OWNER_MEASUREMENT_POLICY_IDENTIFIER,
            O_AUTH_KEY_ID,
            0x1000,
            0x10000,
        ];
        let dpe_store = Rc::new(TestMeasurementStore {
            driver_num: DPE_HANDLE_STORE_DRIVER_NUM,
            target_fw_id,
            records: RefCell::new(
                chain
                    .iter()
                    .enumerate()
                    .map(|(index, fw_id)| {
                        let record = DpeHandleRecord {
                            fw_id: *fw_id,
                            parent_fw_id: index.checked_sub(1).map(|parent| chain[parent]),
                            context_handle: [index as u8 + 1; DPE_CONTEXT_HANDLE_SIZE],
                            tci_tag: *fw_id,
                            ..Default::default()
                        };
                        (*fw_id, record.to_bytes().to_vec())
                    })
                    .collect(),
            ),
            output: RefCell::default(),
        });
        let pcr_store = Rc::new(TestMeasurementStore {
            driver_num: SOFT_PCR_STORE_DRIVER_NUM,
            target_fw_id,
            records: RefCell::new(
                evidence_measurements()
                    .iter()
                    .filter(|value| matches!(value.target_env_id, 0x2000 | 0x10001))
                    .map(|value| {
                        let record = MeasurementRecord {
                            fw_id: value.target_env_id,
                            current_digest: value.current_digest,
                            journey_digest: value.journey_digest,
                            svn: value.svn as u32,
                            ..Default::default()
                        };
                        (record.fw_id, record.serialize().to_vec())
                    })
                    .collect(),
            ),
            output: RefCell::default(),
        });
        let dpe_bytes = 104
            + dpe_store
                .records
                .borrow()
                .iter()
                .map(|(_, record)| record.len())
                .sum::<usize>();
        let pcr_bytes = 16
            + pcr_store
                .records
                .borrow()
                .iter()
                .map(|(_, record)| record.len())
                .sum::<usize>();
        // Reference boards split the 4 KiB measurement-store SRAM into 1 KiB / 3 KiB.
        assert!(dpe_bytes <= 0x400, "DPE fixture exceeds reference SRAM");
        assert!(pcr_bytes <= 0xc00, "PCR fixture exceeds reference SRAM");
        let mailbox = Rc::new(fake::FakeMailboxDriver::new());
        for value in measurements
            .iter()
            .filter(|value| !matches!(value.target_env_id, 0x2000 | 0x10001))
        {
            let mut response = std::vec![0; 8];
            response.extend_from_slice(&value.journey_digest);
            response.extend_from_slice(&value.current_digest);
            let checksum = mcu_caliptra_api::raw::mailbox_checksum(0, &response);
            response[..4].copy_from_slice(&checksum.to_le_bytes());
            mailbox.add_ready_response(u32::from_be_bytes(*b"GTGD"), &response);
        }
        kernel.add_driver(&dpe_store);
        kernel.add_driver(&pcr_store);
        kernel.add_driver(&mailbox);
        (dpe_store, pcr_store)
    }

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

    #[test]
    fn pending_initial_measurements_allow_initial_load_but_not_evidence() {
        let bytes = valid_empty_manifest();
        let mut api = MeasurementApi::<DefaultSyscalls>::new(&bytes, &[]).unwrap();

        api.state = AttestationState::InitialMeasurementsPending;

        assert_eq!(api.initial_load_measurement_state_ready(), Ok(()));
        assert_eq!(
            api.attestation_state_active(),
            Err(MeasurementApiError::AttestationDisabled)
        );
    }

    #[test]
    fn disable_attestation_permanently_blocks_evidence() {
        let bytes = valid_empty_manifest();
        let mut api = MeasurementApi::<DefaultSyscalls>::new(&bytes, &[]).unwrap();
        api.state = AttestationState::Active;

        api.disable_attestation();
        assert_eq!(api.attestation_state(), AttestationState::Error);
        assert_eq!(
            api.attestation_state_active(),
            Err(MeasurementApiError::AttestationDisabled)
        );
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

    #[test]
    fn read_exported_cdi_fails_when_uninitialized() {
        let bytes = valid_manifest_with_entries(&[(0x1000, 0)]);
        let api = MeasurementApi::<DefaultSyscalls>::new(&bytes, &[0x1000]).unwrap();
        let mut cdi = [0u8; EXPORTED_CDI_SIZE];
        assert_eq!(
            api.read_exported_cdi(&mut cdi),
            Err(MeasurementApiError::AttestationDisabled)
        );
    }

    #[test]
    fn attach_owner_policy_enables_dual_manifest_lookup() {
        use crate::attestation_manifest::{
            OWNER_ATTESTATION_MANIFEST_FIXED_HEADER_SIZE, OWNER_ATTESTATION_MANIFEST_MARKER,
            OWNER_FW_LOAD_LIST_FIXED_HEADER_SIZE, OWNER_FW_LOAD_LIST_MARKER,
            OWNER_FW_LOAD_LIST_VERSION, OWNER_MEASUREMENT_POLICY_IDENTIFIER, O_AUTH_KEY_ID,
        };

        let base_bytes = valid_manifest_with_entries(&[(0x1000, ATTESTATION_FLAG_SOC_TCB_DPE)]);
        let mut api = MeasurementApi::<DefaultSyscalls>::new(&base_bytes, &[0x1000]).unwrap();

        assert!(api.owner_policy().is_none());
        assert_eq!(api.manifest_lookup(0x1000).unwrap().0.fw_id, 0x1000);
        assert!(api.manifest_lookup(0x10000).is_err());

        // Construct valid Owner Measurement Policy container
        let mut policy_bytes = Vec::new();
        let header_size = OWNER_ATTESTATION_MANIFEST_FIXED_HEADER_SIZE;
        let entries = [
            (
                OWNER_MEASUREMENT_POLICY_IDENTIFIER,
                ATTESTATION_FLAG_SOC_TCB_DPE,
            ),
            (O_AUTH_KEY_ID, ATTESTATION_FLAG_SOC_TCB_DPE),
            (0x10000, ATTESTATION_FLAG_SOC_TCB_DPE),
        ];
        let size = header_size + entries.len() * ATTESTATION_MANIFEST_ENTRY_SIZE;
        policy_bytes.extend_from_slice(&OWNER_ATTESTATION_MANIFEST_MARKER.to_le_bytes());
        policy_bytes.extend_from_slice(&(size as u32).to_le_bytes());
        policy_bytes.extend_from_slice(&ATTESTATION_MANIFEST_VERSION.to_le_bytes());
        policy_bytes.extend_from_slice(&(header_size as u32).to_le_bytes());
        policy_bytes.extend_from_slice(&(entries.len() as u32).to_le_bytes());
        policy_bytes.extend_from_slice(&3u32.to_le_bytes()); // 3 TCB entries
        policy_bytes.extend_from_slice(&0u16.to_le_bytes());
        policy_bytes.extend_from_slice(&0u16.to_le_bytes());
        for (fw_id, flags) in entries {
            policy_bytes.extend_from_slice(&fw_id.to_le_bytes());
            policy_bytes.extend_from_slice(&flags.to_le_bytes());
        }

        let load_list_header_size = OWNER_FW_LOAD_LIST_FIXED_HEADER_SIZE;
        let load_list_size = load_list_header_size + 4;
        policy_bytes.extend_from_slice(&OWNER_FW_LOAD_LIST_MARKER.to_le_bytes());
        policy_bytes.extend_from_slice(&(load_list_size as u32).to_le_bytes());
        policy_bytes.extend_from_slice(&OWNER_FW_LOAD_LIST_VERSION.to_le_bytes());
        policy_bytes.extend_from_slice(&1u32.to_le_bytes()); // 1 load list entry
        policy_bytes.extend_from_slice(&0x10000u32.to_le_bytes());

        api.validate_and_set_owner_policy(&policy_bytes).unwrap();
        assert!(api.owner_policy().is_some());

        // Base component lookup succeeds and is authorized by the vendor/owner manifest
        let (entry, source) = api.manifest_lookup(0x1000).unwrap();
        assert_eq!(entry.fw_id, 0x1000);
        assert_eq!(source, AuthManifestSource::VendorOwner);
        // Owner components lookup succeeds and is authorized by the owner manifest
        for fw_id in [OWNER_MEASUREMENT_POLICY_IDENTIFIER, O_AUTH_KEY_ID, 0x10000] {
            let (entry, source) = api.manifest_lookup(fw_id).unwrap();
            assert_eq!(entry.fw_id, fw_id);
            assert_eq!(source, AuthManifestSource::Owner);
        }
        // Unknown component fails
        assert!(api.manifest_lookup(0x9999).is_err());
    }

    #[test]
    fn evidence_inventory_covers_base_and_owner_for_selected_ak() {
        let _guard = EVIDENCE_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let vendor = "V".repeat(100);
        let model = "M".repeat(100);
        for (with_owner, target_fw_id) in
            [(false, MCU_RT_FW_ID), (true, MCU_RT_FW_ID), (true, 0x1000)]
        {
            let kernel = fake::Kernel::new();
            let mut base = valid_manifest_with_entries(&[
                (V_AUTH_KEY_ID, ATTESTATION_FLAG_SOC_TCB_DPE),
                (
                    0x1000,
                    ATTESTATION_FLAG_SOC_TCB_DPE
                        | if target_fw_id == 0x1000 {
                            ATTESTATION_FLAG_AK_TARGET
                        } else {
                            0
                        },
                ),
                (0x2000, 0),
            ]);
            base[24..26].copy_from_slice(&(vendor.len() as u16).to_le_bytes());
            base[26..28].copy_from_slice(&(model.len() as u16).to_le_bytes());
            base[28..128].copy_from_slice(vendor.as_bytes());
            base[128..228].copy_from_slice(model.as_bytes());
            let policy = owner_evidence_policy();
            let mut api = MeasurementApi::<DefaultSyscalls>::new(&base, &[0x1000, 0x2000]).unwrap();
            if with_owner {
                api.validate_and_set_owner_policy(&policy).unwrap();
            }
            api.state = AttestationState::Active;
            let expected: Vec<_> = evidence_measurements()
                .into_iter()
                .filter(|value| {
                    if !with_owner {
                        matches!(value.target_env_id, V_AUTH_KEY_ID | 0x1000 | 0x2000)
                    } else if target_fw_id != MCU_RT_FW_ID {
                        matches!(value.target_env_id, 0x2000 | 0x10000 | 0x10001)
                    } else {
                        true
                    }
                })
                .collect();
            let _stores = evidence_stores(&kernel, target_fw_id, &expected);

            assert!(api.manifest_lookup(OWSM_FW_ID).is_err());
            if !with_owner {
                assert_eq!(
                    run(api.read_measurement(&TestAlloc, OWSM_FW_ID)),
                    Err(MeasurementApiError::UnknownFwId)
                );
            }
            assert_eq!(api.evidence_measurement_count().unwrap(), expected.len());
            let mut reference = std::vec![0; CONCISE_EVIDENCE_MAX_SIZE];
            let reference_result = (|| {
                let mut encoder = evidence::MeasurementEvidenceEncoder::new(
                    &mut reference,
                    &vendor,
                    &model,
                    expected.len(),
                )?;
                for value in &expected {
                    encoder.encode_measurement(value)?;
                }
                encoder.finish()
            })();
            let mut actual = std::vec![0; CONCISE_EVIDENCE_MAX_SIZE];
            let actual_result = run(api.encode_measurement_evidence(&TestAlloc, &mut actual));
            let reference_len = match reference_result {
                Ok(len) => len,
                Err(error) => {
                    assert_eq!(error, MeasurementApiError::EvidenceBufferTooSmall);
                    assert!(expected.len() > CONCISE_EVIDENCE_MEASUREMENT_COUNT);
                    assert_eq!(actual_result, Err(error));
                    continue;
                }
            };
            let actual_len = actual_result.unwrap();
            assert_eq!(&actual[..actual_len], &reference[..reference_len]);
            corim_rs::coev::TaggedConciseEvidence::from_cbor(&actual[..actual_len]).unwrap();
        }
    }

    #[test]
    fn owner_evidence_rejects_missing_or_invalid_measurement_records() {
        let _guard = EVIDENCE_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        for fw_id in [
            OWSM_FW_ID,
            OWNER_MEASUREMENT_POLICY_IDENTIFIER,
            O_AUTH_KEY_ID,
            0x10000,
            0x10001,
        ] {
            for corrupt in [false, true] {
                let kernel = fake::Kernel::new();
                let base = valid_manifest_with_entries(&[]);
                let policy = owner_evidence_policy();
                let mut api = MeasurementApi::<DefaultSyscalls>::new(&base, &[]).unwrap();
                api.validate_and_set_owner_policy(&policy).unwrap();
                api.state = AttestationState::Active;
                let expected: Vec<_> = evidence_measurements().into_iter().skip(3).collect();
                let (dpe_store, pcr_store) = evidence_stores(&kernel, MCU_RT_FW_ID, &expected);
                let store = if fw_id == 0x10001 {
                    &pcr_store
                } else {
                    &dpe_store
                };
                let mut records = store.records.borrow_mut();
                if corrupt {
                    let (_, record) = records.iter_mut().find(|(id, _)| *id == fw_id).unwrap();
                    let offset = if fw_id == 0x10001 { 0 } else { 24 };
                    record[offset..offset + 4].copy_from_slice(&(fw_id + 1).to_le_bytes());
                } else {
                    records.retain(|(id, _)| *id != fw_id);
                }
                drop(records);
                let mut buffer = std::vec![0; CONCISE_EVIDENCE_MAX_SIZE];
                assert_eq!(
                    run(api.encode_measurement_evidence(&TestAlloc, &mut buffer)),
                    Err(if fw_id == 0x10001 {
                        MeasurementApiError::InvalidSoftwarePcrStoreState
                    } else {
                        MeasurementApiError::InvalidDpeHandleStoreState
                    })
                );
            }
        }
    }

    #[test]
    fn owner_evidence_rejects_small_buffers_and_inactive_state() {
        let _guard = EVIDENCE_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let kernel = fake::Kernel::new();
        let base = valid_manifest_with_entries(&[(0x2000, 0)]);
        let policy = owner_evidence_policy();
        let mut api = MeasurementApi::<DefaultSyscalls>::new(&base, &[0x2000]).unwrap();
        api.validate_and_set_owner_policy(&policy).unwrap();
        let expected: Vec<_> = evidence_measurements().into_iter().skip(2).collect();
        let _stores = evidence_stores(&kernel, MCU_RT_FW_ID, &expected);
        let mut buffer = [0; 256];
        assert_eq!(
            run(api.encode_measurement_evidence(&TestAlloc, &mut buffer)),
            Err(MeasurementApiError::AttestationDisabled)
        );
        api.state = AttestationState::Active;
        assert_eq!(
            run(api.encode_measurement_evidence(&TestAlloc, &mut buffer)),
            Err(MeasurementApiError::EvidenceBufferTooSmall)
        );
    }
}
