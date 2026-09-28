// Licensed under the Apache-2.0 license

//! Component-update `authorize_and_stash` implementation details.

use caliptra_mcu_libsyscall_caliptra::dpe_handle_store::{
    DpeHandleRecord, DpeHandleStore, DPE_HANDLE_STORE_DRIVER_NUM,
};
use caliptra_mcu_libsyscall_caliptra::soft_pcr_store::{
    MeasurementRecord, SoftwarePcrStore, SOFT_PCR_STORE_DRIVER_NUM,
};
use caliptra_mcu_libtock_platform::Syscalls;
use mcu_caliptra_api::{
    dpe_get_tagged_tci, dpe_update_context_measurement, extend_pcr31,
    DpeUpdateContextMeasurementParams, DpeUpdateContextMeasurementResult, ScratchAlloc,
};

use super::MeasurementApi;
use crate::attestation_manifest::AttestationManifestEntry;
use crate::errors::{MeasurementApiError, MeasurementApiResult};
use crate::ImageMetadata;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum DpeUpdateMode {
    AlwaysRecord,
    UpdateIfChanged,
    VerifyUnchanged,
}

pub(super) async fn record_authorized_image<S: Syscalls, A: ScratchAlloc>(
    api: &mut MeasurementApi<'_, S>,
    alloc: &A,
    entry: AttestationManifestEntry,
    metadata: ImageMetadata,
) -> MeasurementApiResult {
    if entry.is_tcb() {
        update_dpe_context(
            api,
            alloc,
            entry.fw_id,
            &metadata.measurement,
            DpeUpdateMode::AlwaysRecord,
        )
        .await
    } else {
        update_software_pcr(api, alloc, entry, metadata).await?;
        extend_pcr31(&metadata.measurement)
            .await
            .map_err(|_| api.enter_error_state(MeasurementApiError::PcrExtendFailed))
    }
}

pub(super) async fn update_dpe_context<S: Syscalls, A: ScratchAlloc>(
    api: &mut MeasurementApi<'_, S>,
    alloc: &A,
    fw_id: u32,
    measurement: &[u8; crate::IMAGE_MEASUREMENT_DIGEST_SIZE],
    mode: DpeUpdateMode,
) -> MeasurementApiResult {
    api.initial_load_measurement_state_ready()?;
    let dpe_store = DpeHandleStore::<S>::new(DPE_HANDLE_STORE_DRIVER_NUM);

    let mut component = DpeHandleRecord::default();
    dpe_store
        .read_record(fw_id, &mut component)
        .map_err(|_| MeasurementApiError::InvalidDpeHandleStoreState)?;
    if component.fw_id != fw_id {
        return Err(MeasurementApiError::InvalidDpeHandleStoreState);
    }

    if mode != DpeUpdateMode::AlwaysRecord {
        let tagged_tci = dpe_get_tagged_tci(alloc, component.tci_tag)
            .await
            .map_err(|_| MeasurementApiError::DpeCommandFailed)?;

        if &tagged_tci.tci_current == measurement {
            return Ok(());
        }

        if mode == DpeUpdateMode::VerifyUnchanged {
            return Err(MeasurementApiError::InvalidDpeHandleStoreState);
        }
    }

    dpe_update_context_and_persist(api, alloc, &dpe_store, component, measurement).await?;

    extend_pcr31(measurement)
        .await
        .map_err(|_| api.enter_error_state(MeasurementApiError::PcrExtendFailed))
}

async fn dpe_update_context_and_persist<S: Syscalls, A: ScratchAlloc>(
    api: &mut MeasurementApi<'_, S>,
    alloc: &A,
    dpe_store: &DpeHandleStore<S>,
    component: DpeHandleRecord,
    measurement: &[u8; crate::IMAGE_MEASUREMENT_DIGEST_SIZE],
) -> MeasurementApiResult {
    let parent_fw_id = component
        .parent_fw_id
        .ok_or(MeasurementApiError::InvalidDpeHandleStoreState)?;
    let mut parent = DpeHandleRecord::default();
    dpe_store
        .read_record(parent_fw_id, &mut parent)
        .map_err(|_| MeasurementApiError::InvalidDpeHandleStoreState)?;
    if parent.fw_id != parent_fw_id {
        return Err(MeasurementApiError::InvalidDpeHandleStoreState);
    }

    let updated = dpe_update_context_measurement(
        alloc,
        &DpeUpdateContextMeasurementParams {
            parent_handle: parent.context_handle,
            measurement: *measurement,
            tci_type: component.fw_id,
        },
    )
    .await
    .map_err(|_| MeasurementApiError::DpeCommandFailed)?;

    let (parent, component) = tcb_records_with_updated_handles(parent, component, updated);
    dpe_store
        .write_record(parent.fw_id, &parent)
        .map_err(|_| api.enter_error_state(MeasurementApiError::StoreFailed))?;
    dpe_store
        .write_record(component.fw_id, &component)
        .map_err(|_| api.enter_error_state(MeasurementApiError::StoreFailed))
}

async fn update_software_pcr<S: Syscalls, A: ScratchAlloc>(
    api: &mut MeasurementApi<'_, S>,
    alloc: &A,
    entry: AttestationManifestEntry,
    metadata: ImageMetadata,
) -> MeasurementApiResult {
    let pcr_store = SoftwarePcrStore::<S>::new(SOFT_PCR_STORE_DRIVER_NUM);

    let (previous_journey_digest, reserved) = {
        let mut record = MeasurementRecord::default();
        pcr_store
            .read_measurement(entry.fw_id, &mut record)
            .map_err(|_| MeasurementApiError::InvalidSoftwarePcrStoreState)?;
        if record.fw_id != entry.fw_id {
            return Err(MeasurementApiError::InvalidSoftwarePcrStoreState);
        }
        (record.journey_digest, record.reserved)
    };

    let mut journey_digest = [0u8; crate::IMAGE_MEASUREMENT_DIGEST_SIZE];
    super::software_pcr_extend_digest(
        alloc,
        &previous_journey_digest,
        &metadata.measurement,
        &mut journey_digest,
    )
    .await?;
    let record = software_pcr_update_record(
        entry.fw_id,
        reserved,
        metadata.measurement,
        journey_digest,
        metadata,
    );

    pcr_store
        .update_measurement(entry.fw_id, &record)
        .map_err(|_| api.enter_error_state(MeasurementApiError::StoreFailed))
}

fn tcb_records_with_updated_handles(
    mut parent: DpeHandleRecord,
    mut component: DpeHandleRecord,
    updated: DpeUpdateContextMeasurementResult,
) -> (DpeHandleRecord, DpeHandleRecord) {
    parent.context_handle = updated.parent_handle;
    component.context_handle = updated.component_handle;
    (parent, component)
}

fn software_pcr_update_record(
    fw_id: u32,
    reserved: [u8; 4],
    current_digest: [u8; crate::IMAGE_MEASUREMENT_DIGEST_SIZE],
    journey_digest: [u8; crate::IMAGE_MEASUREMENT_DIGEST_SIZE],
    metadata: ImageMetadata,
) -> MeasurementRecord {
    MeasurementRecord {
        fw_id,
        current_digest,
        journey_digest,
        svn: metadata.svn,
        version: metadata.version,
        reserved,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attestation_manifest::{
        MCU_RT_FW_ID, OWNER_MEASUREMENT_POLICY_IDENTIFIER, OWSM_FW_ID, O_AUTH_KEY_ID, V_AUTH_KEY_ID,
    };

    #[test]
    fn tcb_update_records_preserve_topology_and_replace_only_handles() {
        let parent = DpeHandleRecord {
            fw_id: 0x1000,
            parent_fw_id: Some(0x2),
            context_handle: [0x11; 16],
            tci_tag: 0x1000,
            flags: 0xaa,
        };
        let component = DpeHandleRecord {
            fw_id: 0x2000,
            parent_fw_id: Some(0x1000),
            context_handle: [0x22; 16],
            tci_tag: 0x2000,
            flags: 0xbb,
        };
        let updated = DpeUpdateContextMeasurementResult {
            component_handle: [0xcc; 16],
            parent_handle: [0xdd; 16],
        };

        let (updated_parent, updated_component) =
            tcb_records_with_updated_handles(parent, component, updated);

        assert_eq!(updated_parent.context_handle, updated.parent_handle);
        assert_eq!(updated_component.context_handle, updated.component_handle);
        assert_eq!(updated_parent.fw_id, parent.fw_id);
        assert_eq!(updated_parent.parent_fw_id, parent.parent_fw_id);
        assert_eq!(updated_parent.tci_tag, parent.tci_tag);
        assert_eq!(updated_parent.flags, parent.flags);
        assert_eq!(updated_component.fw_id, component.fw_id);
        assert_eq!(updated_component.parent_fw_id, component.parent_fw_id);
        assert_eq!(updated_component.tci_tag, component.tci_tag);
        assert_eq!(updated_component.flags, component.flags);
    }

    #[test]
    fn software_pcr_update_record_uses_raw_current_and_extended_journey() {
        let record = MeasurementRecord {
            fw_id: 0x3000,
            current_digest: [0x11; 48],
            journey_digest: [0x22; 48],
            svn: 3,
            version: 4,
            reserved: [0xa5; 4],
        };
        let current_digest = [0x33; 48];
        let journey_digest = [0x44; 48];
        let metadata = ImageMetadata {
            svn: 7,
            version: 9,
            ..ImageMetadata::component_update(
                crate::ImageHashSource::InRequest,
                0x1234,
                [0x55; 48],
                7,
                9,
            )
        };

        let updated = software_pcr_update_record(
            record.fw_id,
            record.reserved,
            current_digest,
            journey_digest,
            metadata,
        );

        assert_eq!(updated.fw_id, record.fw_id);
        assert_eq!(updated.current_digest, current_digest);
        assert_eq!(updated.journey_digest, journey_digest);
        assert_ne!(updated.current_digest, updated.journey_digest);
        assert_eq!(updated.svn, metadata.svn);
        assert_eq!(updated.version, metadata.version);
        assert_eq!(updated.reserved, record.reserved);
    }

    #[test]
    fn tcb_records_with_updated_handles_for_vendor_auth_key() {
        let parent = DpeHandleRecord {
            fw_id: MCU_RT_FW_ID,
            parent_fw_id: None,
            context_handle: [0x11; 16],
            tci_tag: MCU_RT_FW_ID,
            flags: 0,
        };
        let component = DpeHandleRecord {
            fw_id: V_AUTH_KEY_ID,
            parent_fw_id: Some(MCU_RT_FW_ID),
            context_handle: [0x22; 16],
            tci_tag: V_AUTH_KEY_ID,
            flags: 0,
        };
        let updated = DpeUpdateContextMeasurementResult {
            component_handle: [0x33; 16],
            parent_handle: [0x44; 16],
        };

        let (updated_parent, updated_component) =
            tcb_records_with_updated_handles(parent, component, updated);

        assert_eq!(updated_parent.context_handle, [0x44; 16]);
        assert_eq!(updated_component.context_handle, [0x33; 16]);
        assert_eq!(updated_parent.fw_id, MCU_RT_FW_ID);
        assert_eq!(updated_component.fw_id, V_AUTH_KEY_ID);
        assert_eq!(updated_component.parent_fw_id, Some(MCU_RT_FW_ID));
        assert_eq!(updated_component.tci_tag, V_AUTH_KEY_ID);
    }

    #[test]
    fn tcb_records_with_updated_handles_for_owsm() {
        let parent = DpeHandleRecord {
            fw_id: V_AUTH_KEY_ID,
            parent_fw_id: Some(MCU_RT_FW_ID),
            context_handle: [0x11; 16],
            tci_tag: V_AUTH_KEY_ID,
            flags: 0,
        };
        let component = DpeHandleRecord {
            fw_id: OWSM_FW_ID,
            parent_fw_id: Some(V_AUTH_KEY_ID),
            context_handle: [0x22; 16],
            tci_tag: OWSM_FW_ID,
            flags: 0,
        };
        let updated = DpeUpdateContextMeasurementResult {
            component_handle: [0x55; 16],
            parent_handle: [0x66; 16],
        };

        let (updated_parent, updated_component) =
            tcb_records_with_updated_handles(parent, component, updated);

        assert_eq!(updated_parent.context_handle, [0x66; 16]);
        assert_eq!(updated_component.context_handle, [0x55; 16]);
        assert_eq!(updated_parent.fw_id, V_AUTH_KEY_ID);
        assert_eq!(updated_component.fw_id, OWSM_FW_ID);
        assert_eq!(updated_component.parent_fw_id, Some(V_AUTH_KEY_ID));
        assert_eq!(updated_component.tci_tag, OWSM_FW_ID);
    }

    #[test]
    fn tcb_records_with_updated_handles_for_owner_auth_key() {
        let parent = DpeHandleRecord {
            fw_id: OWNER_MEASUREMENT_POLICY_IDENTIFIER,
            parent_fw_id: Some(OWSM_FW_ID),
            context_handle: [0x33; 16],
            tci_tag: OWNER_MEASUREMENT_POLICY_IDENTIFIER,
            flags: 0,
        };
        let component = DpeHandleRecord {
            fw_id: O_AUTH_KEY_ID,
            parent_fw_id: Some(OWNER_MEASUREMENT_POLICY_IDENTIFIER),
            context_handle: [0x44; 16],
            tci_tag: O_AUTH_KEY_ID,
            flags: 0,
        };
        let updated = DpeUpdateContextMeasurementResult {
            component_handle: [0x77; 16],
            parent_handle: [0x88; 16],
        };

        let (updated_parent, updated_component) =
            tcb_records_with_updated_handles(parent, component, updated);

        assert_eq!(updated_parent.context_handle, [0x88; 16]);
        assert_eq!(updated_component.context_handle, [0x77; 16]);
        assert_eq!(updated_parent.fw_id, OWNER_MEASUREMENT_POLICY_IDENTIFIER);
        assert_eq!(updated_component.fw_id, O_AUTH_KEY_ID);
        assert_eq!(
            updated_component.parent_fw_id,
            Some(OWNER_MEASUREMENT_POLICY_IDENTIFIER)
        );
        assert_eq!(updated_component.tci_tag, O_AUTH_KEY_ID);
    }
}
