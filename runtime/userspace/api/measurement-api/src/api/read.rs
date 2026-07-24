// Licensed under the Apache-2.0 license

//! Internal stored-measurement read helpers.

use caliptra_mcu_libsyscall_caliptra::dpe_handle_store::{
    DpeHandleRecord, DpeHandleStore, DPE_HANDLE_STORE_DRIVER_NUM,
};
use caliptra_mcu_libsyscall_caliptra::soft_pcr_store::{
    MeasurementRecord, SoftwarePcrStore, SOFT_PCR_STORE_DRIVER_NUM,
};
use caliptra_mcu_libtock_platform::Syscalls;
use mcu_caliptra_api_lite::{
    dpe_get_tagged_tci, ApiAlloc, DpeTaggedTci, DPE_CONTEXT_HANDLE_SIZE, DPE_TCI_MEASUREMENT_SIZE,
};

use super::{is_mcu_root_record, MeasurementApi};
use crate::attestation_manifest::{AttestationManifestEntry, MCU_RT_FW_ID};
use crate::errors::{MeasurementApiError, MeasurementApiResult};

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) struct MeasurementValue {
    pub target_env_id: u32,
    pub current_digest: [u8; DPE_TCI_MEASUREMENT_SIZE],
    pub journey_digest: [u8; DPE_TCI_MEASUREMENT_SIZE],
    pub svn: u64,
}

pub(super) async fn read_measurement<S: Syscalls, A: ApiAlloc>(
    api: &MeasurementApi<'_, S>,
    alloc: &A,
    fw_id: u32,
) -> MeasurementApiResult<MeasurementValue> {
    api.attestation_state_active()?;
    let entry = manifest_entry(api, fw_id)?;
    if entry.is_tcb() {
        read_tcb_measurement::<S, A>(alloc, entry).await
    } else {
        read_non_tcb_measurement::<S>(entry)
    }
}

pub(super) fn should_include_tcb_measurement<S: Syscalls>(
    api: &MeasurementApi<'_, S>,
    fw_id: u32,
) -> MeasurementApiResult<bool> {
    api.attestation_state_active()?;
    let entry = manifest_entry(api, fw_id)?;
    if !entry.is_tcb() {
        return Ok(true);
    }

    let target = api.read_attestation_target_record()?;
    let expected_target_fw_id = api.manifest.attestation_target_fw_id();
    let dpe_store = DpeHandleStore::<S>::new(DPE_HANDLE_STORE_DRIVER_NUM);
    should_include_tcb_candidate(
        target,
        expected_target_fw_id,
        fw_id,
        api.manifest.header().tcb_entry_count,
        |parent_fw_id, out| {
            dpe_store
                .read_record(parent_fw_id, out)
                .map_err(|_| MeasurementApiError::InvalidDpeHandleStoreState)
        },
    )
}

async fn read_tcb_measurement<S: Syscalls, A: ApiAlloc>(
    alloc: &A,
    entry: AttestationManifestEntry,
) -> MeasurementApiResult<MeasurementValue> {
    let dpe_store = DpeHandleStore::<S>::new(DPE_HANDLE_STORE_DRIVER_NUM);
    let mut record = DpeHandleRecord::default();
    dpe_store
        .read_record(entry.fw_id, &mut record)
        .map_err(|_| MeasurementApiError::InvalidDpeHandleStoreState)?;
    validate_tcb_handle_record(&record, entry.fw_id)?;

    let tagged_tci = dpe_get_tagged_tci(alloc, record.tci_tag)
        .await
        .map_err(|_| MeasurementApiError::DpeCommandFailed)?;
    Ok(tcb_measurement_from_record(&record, tagged_tci))
}

fn read_non_tcb_measurement<S: Syscalls>(
    entry: AttestationManifestEntry,
) -> MeasurementApiResult<MeasurementValue> {
    let pcr_store = SoftwarePcrStore::<S>::new(SOFT_PCR_STORE_DRIVER_NUM);
    let mut record = MeasurementRecord::default();
    pcr_store
        .read_measurement(entry.fw_id, &mut record)
        .map_err(|_| MeasurementApiError::InvalidSoftwarePcrStoreState)?;
    validate_software_pcr_record(&record, entry.fw_id)?;
    Ok(non_tcb_measurement_from_record(&record))
}

fn manifest_entry<S: Syscalls>(
    api: &MeasurementApi<'_, S>,
    fw_id: u32,
) -> MeasurementApiResult<AttestationManifestEntry> {
    api.manifest
        .lookup(fw_id)
        .map_err(|_| MeasurementApiError::UnknownFwId)
}

fn validate_tcb_handle_record(
    record: &DpeHandleRecord,
    expected_fw_id: u32,
) -> MeasurementApiResult {
    if record.fw_id != expected_fw_id {
        return Err(MeasurementApiError::InvalidDpeHandleStoreState);
    }
    if record.fw_id == MCU_RT_FW_ID {
        if is_mcu_root_record(record) {
            return Ok(());
        }
        return Err(MeasurementApiError::InvalidDpeHandleStoreState);
    }
    if record.parent_fw_id.is_none()
        || record.tci_tag != expected_fw_id
        || record.context_handle == [0u8; DPE_CONTEXT_HANDLE_SIZE]
    {
        return Err(MeasurementApiError::InvalidDpeHandleStoreState);
    }
    Ok(())
}

fn validate_software_pcr_record(
    record: &MeasurementRecord,
    expected_fw_id: u32,
) -> MeasurementApiResult {
    if record.fw_id != expected_fw_id {
        return Err(MeasurementApiError::InvalidSoftwarePcrStoreState);
    }
    Ok(())
}

fn validate_attestation_target_record(
    target: &DpeHandleRecord,
    expected_fw_id: u32,
) -> MeasurementApiResult {
    validate_tcb_handle_record(target, expected_fw_id)
}

fn tcb_measurement_from_record(
    record: &DpeHandleRecord,
    tagged_tci: DpeTaggedTci,
) -> MeasurementValue {
    MeasurementValue {
        target_env_id: record.fw_id,
        current_digest: tagged_tci.tci_current,
        journey_digest: tagged_tci.tci_cumulative,
        svn: 0,
    }
}

fn non_tcb_measurement_from_record(record: &MeasurementRecord) -> MeasurementValue {
    MeasurementValue {
        target_env_id: record.fw_id,
        current_digest: record.current_digest,
        journey_digest: record.journey_digest,
        svn: u64::from(record.svn),
    }
}

fn should_include_tcb_candidate<F>(
    target: DpeHandleRecord,
    expected_target_fw_id: u32,
    candidate_fw_id: u32,
    tcb_entry_count: u32,
    read_record: F,
) -> MeasurementApiResult<bool>
where
    F: FnMut(u32, &mut DpeHandleRecord) -> MeasurementApiResult,
{
    selected_ak_lineage_contains(
        target,
        expected_target_fw_id,
        candidate_fw_id,
        tcb_entry_count,
        read_record,
    )
    .map(|in_lineage| !in_lineage)
}

fn selected_ak_lineage_contains<F>(
    target: DpeHandleRecord,
    expected_target_fw_id: u32,
    candidate_fw_id: u32,
    tcb_entry_count: u32,
    mut read_record: F,
) -> MeasurementApiResult<bool>
where
    F: FnMut(u32, &mut DpeHandleRecord) -> MeasurementApiResult,
{
    validate_attestation_target_record(&target, expected_target_fw_id)?;
    if target.fw_id == candidate_fw_id {
        return Ok(true);
    }

    let mut current = target;
    for _ in 0..lineage_step_limit(tcb_entry_count)? {
        if current.fw_id == MCU_RT_FW_ID {
            if is_mcu_root_record(&current) {
                return Ok(false);
            }
            return Err(MeasurementApiError::InvalidDpeHandleStoreState);
        }

        let parent_fw_id = current
            .parent_fw_id
            .ok_or(MeasurementApiError::InvalidDpeHandleStoreState)?;
        let mut parent = DpeHandleRecord::default();
        read_record(parent_fw_id, &mut parent)?;
        validate_tcb_handle_record(&parent, parent_fw_id)?;
        if parent.fw_id == candidate_fw_id {
            return Ok(true);
        }
        current = parent;
    }

    Err(MeasurementApiError::InvalidDpeHandleStoreState)
}

fn lineage_step_limit(tcb_entry_count: u32) -> MeasurementApiResult<usize> {
    usize::try_from(tcb_entry_count)
        .map_err(|_| MeasurementApiError::InvalidManifest)?
        .checked_add(1)
        .ok_or(MeasurementApiError::InvalidManifest)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::attestation_manifest::{
        ATTESTATION_FLAG_AK_TARGET, ATTESTATION_FLAG_SOC_TCB_DPE, ATTESTATION_MANIFEST_ENTRY_SIZE,
        ATTESTATION_MANIFEST_FIXED_HEADER_SIZE, ATTESTATION_MANIFEST_MARKER,
        ATTESTATION_MANIFEST_VERSION,
    };
    use crate::AttestationState;
    use caliptra_mcu_libsyscall_caliptra::DefaultSyscalls;
    use std::vec::Vec;

    const TCB_FW_ID: u32 = 0x1000;
    const CHILD_TCB_FW_ID: u32 = 0x1001;
    const SIBLING_TCB_FW_ID: u32 = 0x1002;
    const NON_TCB_FW_ID: u32 = 0x2000;

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

    fn tcb_record(fw_id: u32, parent_fw_id: Option<u32>) -> DpeHandleRecord {
        DpeHandleRecord {
            fw_id,
            parent_fw_id,
            context_handle: [fw_id as u8 | 1; DPE_CONTEXT_HANDLE_SIZE],
            tci_tag: fw_id,
            ..Default::default()
        }
    }

    fn root_record() -> DpeHandleRecord {
        DpeHandleRecord {
            fw_id: MCU_RT_FW_ID,
            parent_fw_id: None,
            context_handle: [0x5a; DPE_CONTEXT_HANDLE_SIZE],
            tci_tag: MCU_RT_FW_ID,
            ..Default::default()
        }
    }

    fn read_record_from(
        records: &[DpeHandleRecord],
        fw_id: u32,
        out: &mut DpeHandleRecord,
    ) -> MeasurementApiResult {
        if let Some(record) = records.iter().find(|record| record.fw_id == fw_id) {
            *out = *record;
            return Ok(());
        }
        Err(MeasurementApiError::InvalidDpeHandleStoreState)
    }

    #[test]
    fn unknown_fw_id_fails_lookup() {
        let manifest = valid_manifest_with_entries(&[(TCB_FW_ID, ATTESTATION_FLAG_SOC_TCB_DPE)]);
        let mut api = MeasurementApi::<DefaultSyscalls>::new(&manifest, &[TCB_FW_ID]).unwrap();
        api.state = AttestationState::Active;

        assert_eq!(
            manifest_entry(&api, NON_TCB_FW_ID).unwrap_err(),
            MeasurementApiError::UnknownFwId
        );
    }

    #[test]
    fn tcb_record_validation_rejects_tag_mismatch() {
        let mut record = tcb_record(TCB_FW_ID, Some(MCU_RT_FW_ID));
        record.tci_tag = TCB_FW_ID + 1;

        assert_eq!(
            validate_tcb_handle_record(&record, TCB_FW_ID).unwrap_err(),
            MeasurementApiError::InvalidDpeHandleStoreState
        );
    }

    #[test]
    fn tcb_record_validation_rejects_missing_parent() {
        let record = tcb_record(TCB_FW_ID, None);

        assert_eq!(
            validate_tcb_handle_record(&record, TCB_FW_ID).unwrap_err(),
            MeasurementApiError::InvalidDpeHandleStoreState
        );
    }

    #[test]
    fn software_pcr_record_validation_rejects_wrong_fw_id() {
        let record = MeasurementRecord {
            fw_id: NON_TCB_FW_ID + 1,
            ..Default::default()
        };

        assert_eq!(
            validate_software_pcr_record(&record, NON_TCB_FW_ID).unwrap_err(),
            MeasurementApiError::InvalidSoftwarePcrStoreState
        );
    }

    #[test]
    fn attestation_target_validation_rejects_manifest_target_mismatch() {
        let target = tcb_record(CHILD_TCB_FW_ID, Some(TCB_FW_ID));

        assert_eq!(
            validate_attestation_target_record(&target, TCB_FW_ID).unwrap_err(),
            MeasurementApiError::InvalidDpeHandleStoreState
        );
    }

    #[test]
    fn tcb_measurement_value_maps_tagged_tci_to_unified_fields() {
        let record = tcb_record(TCB_FW_ID, Some(MCU_RT_FW_ID));
        let tagged_tci = DpeTaggedTci {
            tci_cumulative: [0x11; DPE_TCI_MEASUREMENT_SIZE],
            tci_current: [0x22; DPE_TCI_MEASUREMENT_SIZE],
        };

        assert_eq!(
            tcb_measurement_from_record(&record, tagged_tci),
            MeasurementValue {
                target_env_id: TCB_FW_ID,
                current_digest: tagged_tci.tci_current,
                journey_digest: tagged_tci.tci_cumulative,
                svn: 0,
            }
        );
    }

    #[test]
    fn non_tcb_measurement_value_maps_pcr_record_to_unified_fields() {
        let record = MeasurementRecord {
            fw_id: NON_TCB_FW_ID,
            current_digest: [0x33; crate::IMAGE_MEASUREMENT_DIGEST_SIZE],
            journey_digest: [0x44; crate::IMAGE_MEASUREMENT_DIGEST_SIZE],
            svn: 7,
            version: 9,
            reserved: [0xa5; 4],
        };

        assert_eq!(
            non_tcb_measurement_from_record(&record),
            MeasurementValue {
                target_env_id: NON_TCB_FW_ID,
                current_digest: record.current_digest,
                journey_digest: record.journey_digest,
                svn: 7,
            }
        );
    }

    #[test]
    fn ak_target_lineage_omits_target_ancestors_and_includes_siblings() {
        let root = root_record();
        let parent = tcb_record(TCB_FW_ID, Some(MCU_RT_FW_ID));
        let target = tcb_record(CHILD_TCB_FW_ID, Some(TCB_FW_ID));
        let records = [root, parent, target];

        assert!(!should_include_tcb_candidate(
            target,
            CHILD_TCB_FW_ID,
            CHILD_TCB_FW_ID,
            3,
            |fw_id, out| { read_record_from(&records, fw_id, out) }
        )
        .unwrap());
        assert!(!should_include_tcb_candidate(
            target,
            CHILD_TCB_FW_ID,
            TCB_FW_ID,
            3,
            |fw_id, out| { read_record_from(&records, fw_id, out) }
        )
        .unwrap());
        assert!(should_include_tcb_candidate(
            target,
            CHILD_TCB_FW_ID,
            SIBLING_TCB_FW_ID,
            3,
            |fw_id, out| { read_record_from(&records, fw_id, out) }
        )
        .unwrap());
    }

    #[test]
    fn default_mcu_rt_ak_target_omits_root_and_includes_descendants() {
        let root = root_record();

        assert!(
            !should_include_tcb_candidate(root, MCU_RT_FW_ID, MCU_RT_FW_ID, 1, |_, _| {
                Err(MeasurementApiError::InvalidDpeHandleStoreState)
            })
            .unwrap()
        );
        assert!(
            should_include_tcb_candidate(root, MCU_RT_FW_ID, TCB_FW_ID, 1, |_, _| {
                Err(MeasurementApiError::InvalidDpeHandleStoreState)
            })
            .unwrap()
        );
    }

    #[test]
    fn ak_target_lineage_manifest_target_mismatch_fails_closed() {
        let target = tcb_record(CHILD_TCB_FW_ID, Some(TCB_FW_ID));

        assert_eq!(
            should_include_tcb_candidate(target, TCB_FW_ID, TCB_FW_ID, 2, |_, _| {
                Err(MeasurementApiError::InvalidDpeHandleStoreState)
            })
            .unwrap_err(),
            MeasurementApiError::InvalidDpeHandleStoreState
        );
    }

    #[test]
    fn ak_target_lineage_missing_parent_fails() {
        let target = tcb_record(CHILD_TCB_FW_ID, Some(TCB_FW_ID));

        assert_eq!(
            should_include_tcb_candidate(target, CHILD_TCB_FW_ID, SIBLING_TCB_FW_ID, 2, |_, _| {
                Err(MeasurementApiError::InvalidDpeHandleStoreState)
            })
            .unwrap_err(),
            MeasurementApiError::InvalidDpeHandleStoreState
        );
    }

    #[test]
    fn ak_target_lineage_cycle_fails() {
        let first = tcb_record(TCB_FW_ID, Some(CHILD_TCB_FW_ID));
        let second = tcb_record(CHILD_TCB_FW_ID, Some(TCB_FW_ID));
        let records = [first, second];

        assert_eq!(
            should_include_tcb_candidate(first, TCB_FW_ID, SIBLING_TCB_FW_ID, 2, |fw_id, out| {
                read_record_from(&records, fw_id, out)
            })
            .unwrap_err(),
            MeasurementApiError::InvalidDpeHandleStoreState
        );
    }

    #[test]
    fn should_include_tcb_measurement_fails_closed_when_uninitialized_or_error() {
        let manifest = valid_manifest_with_entries(&[(
            TCB_FW_ID,
            ATTESTATION_FLAG_SOC_TCB_DPE | ATTESTATION_FLAG_AK_TARGET,
        )]);
        let mut api = MeasurementApi::<DefaultSyscalls>::new(&manifest, &[TCB_FW_ID]).unwrap();

        assert_eq!(
            should_include_tcb_measurement(&api, TCB_FW_ID).unwrap_err(),
            MeasurementApiError::AttestationDisabled
        );

        api.state = AttestationState::Error;
        assert_eq!(
            should_include_tcb_measurement(&api, TCB_FW_ID).unwrap_err(),
            MeasurementApiError::AttestationDisabled
        );
    }
}
