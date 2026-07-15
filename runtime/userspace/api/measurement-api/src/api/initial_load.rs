// Licensed under the Apache-2.0 license

//! Initial-load `authorize_and_stash` implementation details.

use caliptra_mcu_libsyscall_caliptra::dpe_handle_store::{
    DpeHandleRecord, DpeHandleStore, DPE_HANDLE_STORE_DRIVER_NUM,
};
use caliptra_mcu_libsyscall_caliptra::soft_pcr_store::{
    MeasurementRecord, SoftwarePcrStore, SOFT_PCR_STORE_DRIVER_NUM,
};
use caliptra_mcu_libtock_platform::Syscalls;
use mcu_caliptra_api_lite::{
    authorize_and_stash as caliptra_authorize, dpe_derive_context, dpe_tag_tci, extend_pcr31,
    sha_finish, sha_init, sha_update, ApiAlloc, AuthorizeAndStashFlags, AuthorizeAndStashParams,
    DpeContextHandle, DpeDeriveContextFlags, DpeDeriveContextParams, HashAlgo, SHA_CONTEXT_SIZE,
};

use super::MeasurementApi;
use crate::attestation_manifest::AttestationManifestEntry;
use crate::errors::{MeasurementApiError, MeasurementApiResult};
use crate::ImageMetadata;

pub(super) async fn authorize_and_stash<S: Syscalls, A: ApiAlloc>(
    api: &mut MeasurementApi<'_, S>,
    alloc: &A,
    fw_id: u32,
    metadata: ImageMetadata,
) -> MeasurementApiResult {
    api.attestation_state_active()?;
    let entry = api
        .manifest
        .lookup(fw_id)
        .map_err(|_| MeasurementApiError::UnknownFwId)?;

    let params = caliptra_authorize_params(fw_id, metadata);
    caliptra_authorize(alloc, &params)
        .await
        .map_err(|_| MeasurementApiError::ImageAuthorizationFailed)?;

    if entry.is_tcb() {
        create_dpe_context(api, alloc, entry, metadata).await?;
    } else {
        create_software_pcr_record(api, alloc, entry, metadata).await?;
    }
    // DPE and Software PCR stores are persistent state with no safe rollback
    // primitive after a successful mutation. If the final PCR31 extend fails,
    // fail closed so later measurement/evidence operations are blocked until
    // cold boot reinitializes measurement state.
    extend_pcr31(&metadata.measurement)
        .await
        .map_err(|_| api.enter_error_state(MeasurementApiError::PcrExtendFailed))
}

async fn create_dpe_context<S: Syscalls, A: ApiAlloc>(
    api: &mut MeasurementApi<'_, S>,
    alloc: &A,
    entry: AttestationManifestEntry,
    metadata: ImageMetadata,
) -> MeasurementApiResult {
    let dpe_store = DpeHandleStore::<S>::new(DPE_HANDLE_STORE_DRIVER_NUM);
    reject_existing_tcb_record(&dpe_store, entry.fw_id)?;

    let mut parent = DpeHandleRecord::default();
    dpe_store
        .read_leaf_record(&mut parent)
        .map_err(|_| MeasurementApiError::InvalidDpeHandleStoreState)?;

    let derived = dpe_derive_context(
        alloc,
        &DpeDeriveContextParams {
            parent_handle: parent.context_handle,
            measurement: metadata.measurement,
            flags: DpeDeriveContextFlags::RETAIN_PARENT_CONTEXT,
            tci_type: entry.fw_id,
            target_locality: 0,
            svn: metadata.svn,
        },
    )
    .await
    .map_err(|_| MeasurementApiError::DpeCommandFailed)?;

    parent.context_handle = derived.parent_handle;
    dpe_store
        .write_record(parent.fw_id, &parent)
        .map_err(|_| api.enter_error_state(MeasurementApiError::StoreFailed))?;

    let child = tcb_child_record(entry.fw_id, parent.fw_id, derived.child_handle);
    dpe_store
        .write_record(entry.fw_id, &child)
        .map_err(|_| api.enter_error_state(MeasurementApiError::StoreFailed))?;
    dpe_tag_tci(alloc, &child.context_handle, entry.fw_id)
        .await
        .map_err(|_| api.enter_error_state(MeasurementApiError::DpeCommandFailed))?;
    if entry.is_ak_target() {
        dpe_store
            .mark_attestation_target(entry.fw_id)
            .map_err(|_| api.enter_error_state(MeasurementApiError::StoreFailed))?;
    }
    Ok(())
}

async fn create_software_pcr_record<S: Syscalls, A: ApiAlloc>(
    api: &mut MeasurementApi<'_, S>,
    alloc: &A,
    entry: AttestationManifestEntry,
    metadata: ImageMetadata,
) -> MeasurementApiResult {
    let pcr_store = SoftwarePcrStore::<S>::new(SOFT_PCR_STORE_DRIVER_NUM);
    reject_existing_measurement_record(&pcr_store, entry.fw_id)?;

    let digest = initial_software_pcr_digest(alloc, &metadata.measurement).await?;
    let record = software_pcr_initial_load_record(entry.fw_id, digest, metadata);
    pcr_store
        .create_measurement(entry.fw_id, &record)
        .map_err(|_| api.enter_error_state(MeasurementApiError::StoreFailed))
}

fn reject_existing_tcb_record<S: Syscalls>(
    dpe_store: &DpeHandleStore<S>,
    fw_id: u32,
) -> MeasurementApiResult {
    let mut existing = DpeHandleRecord::default();
    // The capsule returns `FAIL` when the record is absent; success means the
    // fw_id is already recorded and `WRITE_RECORD` would update it in place.
    if dpe_store.read_record(fw_id, &mut existing).is_ok() {
        return Err(MeasurementApiError::DuplicateMeasurementRecord);
    }
    Ok(())
}

fn reject_existing_measurement_record<S: Syscalls>(
    pcr_store: &SoftwarePcrStore<S>,
    fw_id: u32,
) -> MeasurementApiResult {
    let mut existing = MeasurementRecord::default();
    if pcr_store.read_measurement(fw_id, &mut existing).is_ok() {
        return Err(MeasurementApiError::DuplicateMeasurementRecord);
    }
    Ok(())
}

async fn initial_software_pcr_digest<A: ApiAlloc>(
    alloc: &A,
    measurement: &[u8; crate::IMAGE_MEASUREMENT_DIGEST_SIZE],
) -> MeasurementApiResult<[u8; crate::IMAGE_MEASUREMENT_DIGEST_SIZE]> {
    let zero_digest = [0u8; crate::IMAGE_MEASUREMENT_DIGEST_SIZE];
    let mut digest = [0u8; crate::IMAGE_MEASUREMENT_DIGEST_SIZE];
    let ctx = alloc
        .alloc(SHA_CONTEXT_SIZE)
        .map_err(|_| MeasurementApiError::DigestFailed)?;
    let mut state = sha_init(alloc, ctx, HashAlgo::Sha384, &zero_digest)
        .await
        .map_err(|_| MeasurementApiError::DigestFailed)?;
    sha_update(alloc, &mut state, measurement)
        .await
        .map_err(|_| MeasurementApiError::DigestFailed)?;
    sha_finish(alloc, &mut state, &mut digest)
        .await
        .map_err(|_| MeasurementApiError::DigestFailed)?;
    Ok(digest)
}

fn software_pcr_initial_load_record(
    fw_id: u32,
    digest: [u8; crate::IMAGE_MEASUREMENT_DIGEST_SIZE],
    metadata: ImageMetadata,
) -> MeasurementRecord {
    MeasurementRecord {
        fw_id,
        current_digest: digest,
        journey_digest: digest,
        svn: metadata.svn,
        version: metadata.version,
        reserved: [0u8; 4],
    }
}

fn tcb_child_record(
    fw_id: u32,
    parent_fw_id: u32,
    context_handle: DpeContextHandle,
) -> DpeHandleRecord {
    DpeHandleRecord {
        fw_id,
        parent_fw_id: Some(parent_fw_id),
        context_handle,
        tci_tag: fw_id,
        ..Default::default()
    }
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

    use super::*;
    use crate::attestation_manifest::MCU_RT_FW_ID;

    #[test]
    fn caliptra_authorize_params_force_skip_stash_for_initial_load() {
        let measurement = [0xa5; crate::IMAGE_MEASUREMENT_DIGEST_SIZE];
        let metadata = ImageMetadata::initial_load_from_load_address(0x1234, measurement);

        let params = caliptra_authorize_params(0x1000, metadata);

        assert_eq!(params.fw_id, 0x1000);
        assert_eq!(params.measurement, measurement);
        assert_eq!(params.context, [0u8; 48]);
        assert_eq!(params.svn, 0);
        assert_eq!(params.flags, AuthorizeAndStashFlags::SKIP_STASH);
        assert_eq!(params.source, crate::ImageHashSource::LoadAddress);
        assert_eq!(params.image_size, 0x1234);
    }

    #[test]
    fn tcb_child_record_uses_load_topology_parent_and_fw_id_tag() {
        let child = tcb_child_record(0x1000, MCU_RT_FW_ID, [0xa5; 16]);

        assert_eq!(child.parent_fw_id, Some(MCU_RT_FW_ID));
        assert_eq!(child.tci_tag, child.fw_id);
        assert_eq!(child.context_handle, [0xa5; 16]);
    }

    #[test]
    fn software_pcr_initial_load_record_uses_current_and_journey_digest() {
        let digest = [0x5a; crate::IMAGE_MEASUREMENT_DIGEST_SIZE];
        let metadata = ImageMetadata {
            svn: 7,
            version: 9,
            ..ImageMetadata::initial_load_from_load_address(0x1234, [0xa5; 48])
        };

        let record = software_pcr_initial_load_record(0x1000, digest, metadata);

        assert_eq!(record.fw_id, 0x1000);
        assert_eq!(record.current_digest, digest);
        assert_eq!(record.journey_digest, digest);
        assert_eq!(record.svn, 7);
        assert_eq!(record.version, 9);
        assert_eq!(record.reserved, [0u8; 4]);
    }
}
