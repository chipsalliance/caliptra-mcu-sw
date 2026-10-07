// Licensed under the Apache-2.0 license

//! Initial-load `authorize_and_stash` implementation details.

use caliptra_mcu_libsyscall_caliptra::dpe_handle_store::{
    DpeHandleRecord, DpeHandleStore, DPE_HANDLE_STORE_DRIVER_NUM,
};
use caliptra_mcu_libsyscall_caliptra::soft_pcr_store::{
    MeasurementRecord, SoftwarePcrStore, SOFT_PCR_STORE_DRIVER_NUM,
};
use caliptra_mcu_libtock_platform::Syscalls;
use mcu_caliptra_api::{
    dpe_derive_context, dpe_tag_tci, extend_pcr31, DpeContextHandle, DpeDeriveContextFlags,
    DpeDeriveContextParams, ScratchAlloc,
};

use super::MeasurementApi;
use crate::attestation_manifest::AttestationManifestEntry;
use crate::errors::{MeasurementApiError, MeasurementApiResult};
use crate::ImageMetadata;

#[inline(never)]
pub(super) async fn create_dpe_context<S: Syscalls, A: ScratchAlloc>(
    api: &mut MeasurementApi<'_, S>,
    alloc: &A,
    fw_id: u32,
    measurement: &[u8; crate::IMAGE_MEASUREMENT_DIGEST_SIZE],
    svn: u32,
    is_ak_target: bool,
) -> MeasurementApiResult {
    api.initial_load_measurement_state_ready()?;
    let dpe_store = DpeHandleStore::<S>::new(DPE_HANDLE_STORE_DRIVER_NUM);
    reject_existing_tcb_record(&dpe_store, fw_id)?;

    let mut parent = DpeHandleRecord::default();
    dpe_store
        .read_leaf_record(&mut parent)
        .map_err(|_| MeasurementApiError::InvalidDpeHandleStoreState)?;

    let derived = dpe_derive_context(
        alloc,
        &DpeDeriveContextParams {
            parent_handle: parent.context_handle,
            measurement: *measurement,
            flags: DpeDeriveContextFlags::RETAIN_PARENT_CONTEXT
                | DpeDeriveContextFlags::ALLOW_NEW_CONTEXT_TO_EXPORT
                | DpeDeriveContextFlags::INPUT_ALLOW_X509,
            tci_type: fw_id,
            target_locality: 0,
            svn,
        },
    )
    .await
    .map_err(|_| MeasurementApiError::DpeCommandFailed)?;

    parent.context_handle = derived.parent_handle;
    dpe_store
        .write_record(parent.fw_id, &parent)
        .map_err(|_| api.enter_error_state(MeasurementApiError::StoreFailed))?;

    let child = tcb_child_record(fw_id, parent.fw_id, derived.child_handle);
    dpe_store
        .write_record(fw_id, &child)
        .map_err(|_| api.enter_error_state(MeasurementApiError::StoreFailed))?;
    dpe_tag_tci(alloc, &child.context_handle, fw_id)
        .await
        .map_err(|_| api.enter_error_state(MeasurementApiError::DpeCommandFailed))?;
    if is_ak_target {
        dpe_store
            .mark_attestation_target(fw_id)
            .map_err(|_| api.enter_error_state(MeasurementApiError::StoreFailed))?;
    }
    extend_pcr31(measurement)
        .await
        .map_err(|_| api.enter_error_state(MeasurementApiError::PcrExtendFailed))
}

pub(super) async fn record_authorized_image<S: Syscalls, A: ScratchAlloc>(
    api: &mut MeasurementApi<'_, S>,
    alloc: &A,
    entry: AttestationManifestEntry,
    metadata: ImageMetadata,
) -> MeasurementApiResult {
    if entry.is_tcb() {
        create_dpe_context(
            api,
            alloc,
            entry.fw_id,
            &metadata.measurement,
            metadata.svn,
            entry.is_ak_target(),
        )
        .await
    } else {
        create_software_pcr_record(api, alloc, entry, metadata).await?;
        extend_pcr31(&metadata.measurement)
            .await
            .map_err(|_| api.enter_error_state(MeasurementApiError::PcrExtendFailed))
    }
}

async fn create_software_pcr_record<S: Syscalls, A: ScratchAlloc>(
    api: &mut MeasurementApi<'_, S>,
    alloc: &A,
    entry: AttestationManifestEntry,
    metadata: ImageMetadata,
) -> MeasurementApiResult {
    let pcr_store = SoftwarePcrStore::<S>::new(SOFT_PCR_STORE_DRIVER_NUM);
    reject_existing_measurement_record(&pcr_store, entry.fw_id)?;

    let mut journey_digest = [0u8; crate::IMAGE_MEASUREMENT_DIGEST_SIZE];
    super::software_pcr_extend_digest(
        alloc,
        &[0u8; crate::IMAGE_MEASUREMENT_DIGEST_SIZE],
        &metadata.measurement,
        &mut journey_digest,
    )
    .await?;
    let record = software_pcr_initial_load_record(entry.fw_id, journey_digest, metadata);
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

fn software_pcr_initial_load_record(
    fw_id: u32,
    journey_digest: [u8; crate::IMAGE_MEASUREMENT_DIGEST_SIZE],
    metadata: ImageMetadata,
) -> MeasurementRecord {
    MeasurementRecord {
        fw_id,
        current_digest: metadata.measurement,
        journey_digest,
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

#[cfg(test)]
mod tests {
    extern crate std;

    use super::super::caliptra_authorize_params;
    use super::*;
    use crate::attestation_manifest::{
        MCU_RT_FW_ID, OWNER_MEASUREMENT_POLICY_IDENTIFIER, OWSM_FW_ID, O_AUTH_KEY_ID, V_AUTH_KEY_ID,
    };
    use mcu_caliptra_api::AuthorizeAndStashFlags;

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
    fn tcb_child_record_for_vendor_auth_key_uses_mcu_rt_parent() {
        let child = tcb_child_record(V_AUTH_KEY_ID, MCU_RT_FW_ID, [0x55; 16]);

        assert_eq!(child.fw_id, V_AUTH_KEY_ID);
        assert_eq!(child.parent_fw_id, Some(MCU_RT_FW_ID));
        assert_eq!(child.tci_tag, V_AUTH_KEY_ID);
        assert_eq!(child.context_handle, [0x55; 16]);
    }

    #[test]
    fn tcb_child_record_for_owsm_uses_vendor_key_parent() {
        let child = tcb_child_record(OWSM_FW_ID, V_AUTH_KEY_ID, [0x33; 16]);

        assert_eq!(child.fw_id, OWSM_FW_ID);
        assert_eq!(child.parent_fw_id, Some(V_AUTH_KEY_ID));
        assert_eq!(child.tci_tag, OWSM_FW_ID);
        assert_eq!(child.context_handle, [0x33; 16]);
    }

    #[test]
    fn tcb_child_record_for_owner_policy_uses_owsm_parent() {
        let child = tcb_child_record(OWNER_MEASUREMENT_POLICY_IDENTIFIER, OWSM_FW_ID, [0x55; 16]);

        assert_eq!(child.fw_id, OWNER_MEASUREMENT_POLICY_IDENTIFIER);
        assert_eq!(child.parent_fw_id, Some(OWSM_FW_ID));
        assert_eq!(child.tci_tag, OWNER_MEASUREMENT_POLICY_IDENTIFIER);
        assert_eq!(child.context_handle, [0x55; 16]);
    }

    #[test]
    fn tcb_child_record_for_owner_auth_key_uses_owner_policy_parent() {
        let child = tcb_child_record(
            O_AUTH_KEY_ID,
            OWNER_MEASUREMENT_POLICY_IDENTIFIER,
            [0x66; 16],
        );

        assert_eq!(child.fw_id, O_AUTH_KEY_ID);
        assert_eq!(
            child.parent_fw_id,
            Some(OWNER_MEASUREMENT_POLICY_IDENTIFIER)
        );
        assert_eq!(child.tci_tag, O_AUTH_KEY_ID);
        assert_eq!(child.context_handle, [0x66; 16]);
    }

    #[test]
    fn software_pcr_initial_load_record_uses_raw_current_and_journey_digest() {
        let journey_digest = [0x5a; crate::IMAGE_MEASUREMENT_DIGEST_SIZE];
        let metadata = ImageMetadata {
            svn: 7,
            version: 9,
            ..ImageMetadata::initial_load_from_load_address(0x1234, [0xa5; 48])
        };

        let record = software_pcr_initial_load_record(0x1000, journey_digest, metadata);

        assert_eq!(record.fw_id, 0x1000);
        assert_eq!(record.current_digest, metadata.measurement);
        assert_eq!(record.journey_digest, journey_digest);
        assert_ne!(record.current_digest, record.journey_digest);
        assert_eq!(record.svn, 7);
        assert_eq!(record.version, 9);
        assert_eq!(record.reserved, [0u8; 4]);
    }
}
