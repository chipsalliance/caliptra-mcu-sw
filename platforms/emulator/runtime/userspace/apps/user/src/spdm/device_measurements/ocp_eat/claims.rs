// Licensed under the Apache-2.0 license

use crate::soc_env::*;
use arrayvec::ArrayString;
use arrayvec::ArrayVec;
use core::fmt::Write;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicBool, Ordering};
use libapi_caliptra::crypto::hash::SHA384_HASH_SIZE;
use libapi_caliptra::evidence::device_state::DeviceState;
use libapi_caliptra::evidence::ocp_eat_claims::generate_eat_claims;
use libapi_caliptra::evidence::pcr_quote::PcrQuote;
use ocp_eat::ocp_profile::{
    IntegrityRegisterEntry, IntegrityRegisterIdChoice, TaggedConciseEvidence,
};
use ocp_eat::{
    ClassMap, ConciseEvidence, ConciseEvidenceMap, DigestEntry, EnvironmentMap, EvTriplesMap,
    EvidenceTripleRecord, MeasurementMap, MeasurementValue,
};
use spdm_lib::measurements::{MeasurementsError, MeasurementsResult};
use zerocopy::IntoBytes;

const NUM_FW_TARGET_ENV: usize = NUM_DEFAULT_FW_COMPONENTS + NUM_SOC_FW_COMPONENTS;
const NUM_HW_TARGET_ENV: usize = 0; // For now, no HW IDs
const NUM_SW_TARGET_ENV: usize = 0; // For now, no SW IDs
const NUM_FW_HW_TARGET_ENV: usize = NUM_FW_TARGET_ENV + NUM_HW_TARGET_ENV;
const NUM_HW_SW_TARGET_ENV: usize = NUM_HW_TARGET_ENV + NUM_SW_TARGET_ENV;
const TOTAL_TARGET_ENV: usize = NUM_FW_TARGET_ENV + NUM_HW_TARGET_ENV + NUM_SW_TARGET_ENV;
const SHA384_HASH_WORDS: usize = SHA384_HASH_SIZE / 4; // Number of u32 words in a SHA384 hash

const FMC_FW_JOURNEY_PCR_INDEX: usize = 1;
const RT_FW_JOURNEY_PCR_INDEX: usize = 3;

const MAX_SEMVER_LEN: usize = 11;
const MAX_RAW_VALUE_LEN: usize = 32;

const FMC_MEASUREMENT_INDEX: usize = 0;
const RT_MEASUREMENT_INDEX: usize = 1;
const AUTHMAN_MEASUREMENT_INDEX: usize = 2;
const NUM_DEFAULT_FW_COMPONENTS: usize = 3;

const EAT_DEFAULT_ISSUER: &str = "CN=Caliptra EAT DPE Attestation Key";

const DEFAULT_MEAS_VALUE: MeasurementValue = MeasurementValue {
    version: None,
    svn: None,
    digests: None,
    integrity_registers: None,
    raw_value: None,
    raw_value_mask: None,
};

const DEFAULT_ENV_MAP: EnvironmentMap = EnvironmentMap {
    class: ClassMap {
        class_id: "",
        vendor: None,
        model: None,
    },
};

const DEFAULT_MEASUREMENT_MAP: MeasurementMap<'static> = MeasurementMap {
    key: 0,
    mval: DEFAULT_MEAS_VALUE,
};

static ENV_INIT_DONE: AtomicBool = AtomicBool::new(false);

static mut ENV_MAPS: MaybeUninit<[EnvironmentMap<'static>; TOTAL_TARGET_ENV]> =
    MaybeUninit::uninit();

pub fn init_target_env_claims() {
    if ENV_INIT_DONE.load(Ordering::Acquire) {
        return;
    }
    // Only one task should ever call this!
    let maps = build_environment_maps();
    unsafe {
        ENV_MAPS.write(maps);
    }
    ENV_INIT_DONE.store(true, Ordering::Release);
}

fn build_environment_maps() -> [EnvironmentMap<'static>; TOTAL_TARGET_ENV] {
    let mut arr = [DEFAULT_ENV_MAP; TOTAL_TARGET_ENV];

    for (i, id) in DEFAULT_FW_IDS.iter().enumerate() {
        arr[i].class.class_id = id;
    }

    for (i, id) in SOC_FW_ID_STRS.iter().enumerate() {
        let idx = NUM_DEFAULT_FW_COMPONENTS + i;
        arr[idx].class.class_id = id;
        arr[idx].class.vendor = Some(SOC_VENDOR);
        arr[idx].class.model = Some(SOC_MODEL);
    }

    // TODO: HW & SW populations here

    arr
}

fn get_env_maps() -> &'static [EnvironmentMap<'static>; TOTAL_TARGET_ENV] {
    // Wait until initialization is complete
    while !ENV_INIT_DONE.load(Ordering::Acquire) {
        core::hint::spin_loop();
    }
    // SAFETY: Only written once, then only read
    unsafe { ENV_MAPS.assume_init_ref() }
}

struct VersionField {
    buf: ArrayString<MAX_SEMVER_LEN>,
}

/// Generates all EAT claims and encodes them as a CBOR array into the provided buffer.
///
/// # Arguments
/// * `claims_buf` - Mutable buffer to write the CBOR-encoded EAT claims into.
/// * `nonce` - Nonce value to include in the EAT.
///
/// # Returns
/// Returns number of bytes written on success, or an error if claim generation or encoding fails.
pub async fn generate_claims(claims_buf: &mut [u8], nonce: &[u8]) -> MeasurementsResult<usize> {
    // version, svn, digests, integrity registers applicable to FW target envs
    // digests, raw values applicable to HW target envs
    let mut versions = [0u32; NUM_FW_TARGET_ENV];
    let mut svns = [0u32; NUM_FW_TARGET_ENV];
    let mut digests = [[0u32; SHA384_HASH_WORDS]; NUM_FW_HW_TARGET_ENV];
    let mut journey_digests = [[0u8; SHA384_HASH_SIZE]; NUM_FW_TARGET_ENV];

    // Raw values only for HW and SW target envs
    let mut raw_values: [Option<ArrayVec<u8, MAX_RAW_VALUE_LEN>>; NUM_HW_SW_TARGET_ENV] =
        [None; NUM_HW_SW_TARGET_ENV];
    // raw value masks only for SW target envs
    let mut raw_value_masks: [Option<ArrayVec<u8, MAX_RAW_VALUE_LEN>>; NUM_SW_TARGET_ENV] =
        [None; NUM_SW_TARGET_ENV];

    let mut digest_entries_arr: [[DigestEntry; 1]; NUM_FW_TARGET_ENV] = [[DigestEntry {
        alg_id: 7,
        value: &[0u8; SHA384_HASH_SIZE],
    }; 1];
        NUM_FW_TARGET_ENV];

    let mut journey_digest_entries_arr: [[DigestEntry; 1]; NUM_FW_TARGET_ENV] = [[DigestEntry {
        alg_id: 7,
        value: &[0u8; SHA384_HASH_SIZE],
    }; 1];
        NUM_FW_TARGET_ENV];

    let mut integrity_registers_arr: [[IntegrityRegisterEntry; 1]; NUM_FW_TARGET_ENV] =
        [[IntegrityRegisterEntry {
            id: IntegrityRegisterIdChoice::Uint(0),
            digests: &[],
        }; 1]; NUM_FW_TARGET_ENV];

    let mut version_fields: [VersionField; NUM_FW_TARGET_ENV] =
        core::array::from_fn(|_| VersionField {
            buf: ArrayString::new(),
        });

    // 1) Fill all the necessary leaf level measurement value info
    fill_fw_config_info(
        &mut versions,
        &mut svns,
        &mut digests[..NUM_FW_TARGET_ENV],
        &mut journey_digests,
    )
    .await?;
    fill_hw_config_info(
        &mut digests[NUM_FW_TARGET_ENV..],
        &mut raw_values[..NUM_HW_TARGET_ENV],
    )
    .await?;
    fill_sw_config_info(&mut raw_values[NUM_HW_TARGET_ENV..], &mut raw_value_masks).await?;

    // Convert u32 versions to ArrayStrings
    for i in 0..NUM_FW_TARGET_ENV {
        version_fields[i].buf = version_to_str(versions[i]);
    }

    // Fill the digest entries and integrity registers
    for i in 0..NUM_FW_TARGET_ENV {
        journey_digest_entries_arr[i][0] = DigestEntry {
            alg_id: 7,
            value: &journey_digests[i],
        };
    }
    for i in 0..NUM_FW_TARGET_ENV {
        digest_entries_arr[i][0] = DigestEntry {
            alg_id: 7,
            value: digests[i].as_bytes(),
        };
        integrity_registers_arr[i][0] = IntegrityRegisterEntry {
            id: IntegrityRegisterIdChoice::Uint(0),
            digests: &journey_digest_entries_arr[i],
        };
    }

    // 2) Now build measurement_maps array (one per target env)
    let mut measurement_maps: [MeasurementMap; TOTAL_TARGET_ENV] =
        [DEFAULT_MEASUREMENT_MAP; TOTAL_TARGET_ENV];

    for i in 0..NUM_FW_TARGET_ENV {
        measurement_maps[i] = MeasurementMap {
            key: i as u64,
            mval: MeasurementValue {
                version: Some(&version_fields[i].buf),
                svn: Some(svns[i] as u64),
                digests: Some(&digest_entries_arr[i]),
                integrity_registers: Some(&integrity_registers_arr[i]),
                raw_value: None,
                raw_value_mask: None,
            },
        };
    }

    // TODO: Populate HW and SW measurement maps if needed

    // 3. Build evidence triple records array (one per target env)
    let mut evidence_triple_records: [EvidenceTripleRecord; TOTAL_TARGET_ENV] =
        [EvidenceTripleRecord {
            environment: DEFAULT_ENV_MAP,
            measurements: &[],
        }; TOTAL_TARGET_ENV];
    let environment_maps = get_env_maps();
    for (i, record) in evidence_triple_records.iter_mut().enumerate() {
        record.environment = environment_maps[i];
        record.measurements = &measurement_maps[i..=i]; // single measurement per env
    }

    // 4. Build EvidenceTriplesMap
    let ev_triples_map = EvTriplesMap {
        evidence_triples: Some(&evidence_triple_records),
        identity_triples: None,
        dependency_triples: None,
        membership_triples: None,
        coswid_triples: None,
        attest_key_triples: None,
    };

    // 5. Build ConciseEvidenceMap
    let concise_evidence_map = ConciseEvidenceMap {
        ev_triples: ev_triples_map,
        evidence_id: None,
        profile: None,
    };

    // 6. Create TaggedConciseEvidenceMap
    let concise_evidence = ConciseEvidence::Tagged(TaggedConciseEvidence {
        concise_evidence: concise_evidence_map,
    });

    // 7. Generate EAT claims
    generate_eat_claims(EAT_DEFAULT_ISSUER, nonce, concise_evidence, claims_buf)
        .await
        .map_err(MeasurementsError::CaliptraApi)
}

fn version_to_str(ver: u32) -> ArrayString<MAX_SEMVER_LEN> {
    let major = (ver >> 16) & 0xFF;
    let minor = (ver >> 8) & 0xFF;
    let patch = ver & 0xFF;
    let mut s = ArrayString::<MAX_SEMVER_LEN>::new();
    let _ = write!(&mut s, "{}.{}.{}", major, minor, patch);
    s
}

async fn fill_fw_config_info(
    versions: &mut [u32; NUM_FW_TARGET_ENV],
    svns: &mut [u32; NUM_FW_TARGET_ENV],
    digests: &mut [[u32; SHA384_HASH_WORDS]],
    journey_digests: &mut [[u8; SHA384_HASH_SIZE]; NUM_FW_TARGET_ENV],
) -> MeasurementsResult<()> {
    if digests.len() != NUM_FW_TARGET_ENV {
        return Err(MeasurementsError::InvalidInput);
    }
    // Populate versions, svns, digests, journey_digests from device state or other sources
    // for default FW components first
    let fw_info = DeviceState::fw_info()
        .await
        .map_err(MeasurementsError::CaliptraApi)?;
    let (_, _, fmc_version, rt_version) = DeviceState::fw_version()
        .await
        .map_err(MeasurementsError::CaliptraApi)?;

    // VERSIONS: Get from fw_version
    versions[FMC_MEASUREMENT_INDEX] = fmc_version;
    versions[RT_MEASUREMENT_INDEX] = rt_version;
    versions[AUTHMAN_MEASUREMENT_INDEX] = 0; // TODO: AuthMan version to be captured

    // SVNs: Get from fw_info
    svns[FMC_MEASUREMENT_INDEX] = fw_info.fw_svn;
    svns[RT_MEASUREMENT_INDEX] = fw_info.fw_svn;
    svns[AUTHMAN_MEASUREMENT_INDEX] = fw_info.fw_svn;

    // DIGESTS: Get digests from fw_info
    digests[FMC_MEASUREMENT_INDEX] = fw_info.fmc_sha384_digest;
    digests[RT_MEASUREMENT_INDEX] = fw_info.runtime_sha384_digest;
    digests[AUTHMAN_MEASUREMENT_INDEX] = fw_info.authman_sha384_digest;

    // JOURNEY DIGESTS: Get journey digests from PCRs
    let pcrs = PcrQuote::get_pcrs()
        .await
        .map_err(MeasurementsError::CaliptraApi)?;

    journey_digests[FMC_MEASUREMENT_INDEX] = pcrs[FMC_FW_JOURNEY_PCR_INDEX];
    journey_digests[RT_MEASUREMENT_INDEX] = pcrs[RT_FW_JOURNEY_PCR_INDEX];
    journey_digests[AUTHMAN_MEASUREMENT_INDEX] = pcrs[RT_FW_JOURNEY_PCR_INDEX];

    // Populate for SOC FW components next
    #[allow(clippy::reversed_empty_ranges)]
    for i in 0..NUM_SOC_FW_COMPONENTS {
        let _image_info = DeviceState::image_info(SOC_FW_IDS[i])
            .await
            .map_err(MeasurementsError::CaliptraApi)?;
        // For now, set dummy values
        versions[NUM_DEFAULT_FW_COMPONENTS + i] = 0;
        svns[NUM_DEFAULT_FW_COMPONENTS + i] = 0;
        digests[NUM_DEFAULT_FW_COMPONENTS + i] = [0u32; SHA384_HASH_WORDS];
        journey_digests[NUM_DEFAULT_FW_COMPONENTS + i] = [0u8; SHA384_HASH_SIZE];
    }
    Ok(())
}

async fn fill_hw_config_info(
    digests: &mut [[u32; SHA384_HASH_WORDS]],
    raw_values: &mut [Option<ArrayVec<u8, MAX_RAW_VALUE_LEN>>],
) -> MeasurementsResult<()> {
    if digests.len() != NUM_HW_TARGET_ENV || raw_values.len() != NUM_HW_TARGET_ENV {
        return Err(MeasurementsError::InvalidInput);
    }
    // TODO: Populate digests and raw_values from HW fuses or other sources
    // For now, set dummy values
    #[allow(clippy::reversed_empty_ranges)]
    for i in 0..NUM_HW_TARGET_ENV {
        digests[i] = [0u32; SHA384_HASH_WORDS];
        raw_values[i] = None; // or Some(ArrayVec::from_slice(&[...]).unwrap());
    }
    Ok(())
}

async fn fill_sw_config_info(
    raw_values: &mut [Option<ArrayVec<u8, MAX_RAW_VALUE_LEN>>],
    raw_value_masks: &mut [Option<ArrayVec<u8, MAX_RAW_VALUE_LEN>>; NUM_SW_TARGET_ENV],
) -> MeasurementsResult<()> {
    if raw_values.len() != NUM_SW_TARGET_ENV {
        return Err(MeasurementsError::InvalidInput);
    }
    // TODO: Populate raw_values and raw_value_masks from SW config or other sources
    // For now, set dummy values
    #[allow(clippy::reversed_empty_ranges)]
    for i in 0..NUM_SW_TARGET_ENV {
        raw_values[i] = None; // or Some(ArrayVec::from_slice(&[...]).unwrap());
        raw_value_masks[i] = None; // or Some(ArrayVec::from_slice(&[...]).unwrap());
    }
    Ok(())
}
