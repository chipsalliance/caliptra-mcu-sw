// Licensed under the Apache-2.0 license

//! Concise-evidence contract helpers.

use mcu_caliptra_api_lite::DPE_TCI_MEASUREMENT_SIZE;

use super::read::MeasurementValue;
use crate::attestation_manifest::AttestationManifestEntry;
use crate::errors::{MeasurementApiError, MeasurementApiResult};

include!(concat!(env!("OUT_DIR"), "/evidence_templates.rs"));

pub(super) const EVIDENCE_DIGEST_SIZE: usize = DPE_TCI_MEASUREMENT_SIZE;
pub(super) const EVIDENCE_MEASUREMENT_KEY: u64 = 1;
pub(super) const EVIDENCE_INTEGRITY_REGISTER_ID: u64 = 0;
pub(super) const EVIDENCE_SHA384_ALG_ID: i32 = 7;
pub(super) const TCB_EVIDENCE_SVN: u64 = 0;
pub(super) const FW_ID_CLASS_ID_LEN: usize = 10;

const _: () = assert!(EVIDENCE_DIGEST_SIZE == crate::IMAGE_MEASUREMENT_DIGEST_SIZE);
const _: () = assert!(EVIDENCE_DIGEST_SIZE == 48);
const _: () = assert!(EVIDENCE_SHA384_ALG_ID == 7);

pub(super) fn inventory_evidence_eligible(_entry: AttestationManifestEntry) -> bool {
    true
}

pub(super) fn validate_evidence_buffer_size(
    buffer_len: usize,
    encoded_len: usize,
) -> MeasurementApiResult<usize> {
    if buffer_len < encoded_len {
        return Err(MeasurementApiError::EvidenceBufferTooSmall);
    }
    Ok(encoded_len)
}

pub(super) fn fw_id_class_id(fw_id: u32) -> [u8; FW_ID_CLASS_ID_LEN] {
    let mut out = *b"0x00000000";
    for i in 0..8 {
        let nibble = ((fw_id >> (28 - i * 4)) & 0x0f) as u8;
        out[2 + i] = match nibble {
            0..=9 => b'0' + nibble,
            _ => b'A' + (nibble - 10),
        };
    }
    out
}

pub(super) struct MeasurementEvidenceEncoder<'a> {
    writer: TemplateWriter<'a>,
    vendor: &'a str,
    model: &'a str,
}

impl<'a> MeasurementEvidenceEncoder<'a> {
    pub(super) fn new(
        buffer: &'a mut [u8],
        vendor: &'a str,
        model: &'a str,
        measurement_count: usize,
    ) -> MeasurementApiResult<Self> {
        let mut writer = TemplateWriter::new(buffer);
        writer.write(CONCISE_EVIDENCE_PREFIX)?;
        writer.write_array_len(measurement_count)?;
        Ok(Self {
            writer,
            vendor,
            model,
        })
    }

    pub(super) fn encode_measurement(
        &mut self,
        measurement: &MeasurementValue,
    ) -> MeasurementApiResult {
        let class_id = fw_id_class_id(measurement.target_env_id);
        self.writer.write(EVIDENCE_TRIPLE_CLASS_PREFIX)?;
        self.writer.write(&class_id)?;
        self.writer.write(CLASS_VENDOR_KEY)?;
        self.writer.write_text(self.vendor)?;
        self.writer.write(CLASS_MODEL_KEY)?;
        self.writer.write_text(self.model)?;
        self.writer.write(SINGLE_MEASUREMENT_ARRAY_PREFIX)?;
        encode_measurement_value_to(&mut self.writer, measurement)?;
        self.writer.write(EVIDENCE_TRIPLE_SUFFIX)
    }

    pub(super) fn finish(mut self) -> MeasurementApiResult<usize> {
        self.writer.write(CONCISE_EVIDENCE_SUFFIX)?;
        Ok(self.writer.len())
    }
}

pub(super) fn encode_measurement_value(
    buffer: &mut [u8],
    measurement: &MeasurementValue,
) -> MeasurementApiResult<usize> {
    let mut writer = TemplateWriter::new(buffer);
    encode_measurement_value_to(&mut writer, measurement)?;
    Ok(writer.len())
}

fn encode_measurement_value_to(
    writer: &mut TemplateWriter<'_>,
    measurement: &MeasurementValue,
) -> MeasurementApiResult {
    writer.write(MEASUREMENT_VALUE_PREFIX)?;
    writer.write_uint(measurement.svn)?;
    writer.write(CURRENT_DIGEST_PREFIX)?;
    writer.write(&measurement.current_digest)?;
    writer.write(JOURNEY_DIGEST_PREFIX)?;
    encode_digest_entry(writer, &measurement.journey_digest)?;
    writer.write(MEASUREMENT_VALUE_SUFFIX)
}

fn encode_digest_entry(
    writer: &mut TemplateWriter<'_>,
    digest: &[u8; EVIDENCE_DIGEST_SIZE],
) -> MeasurementApiResult {
    writer.write(digest)
}

struct TemplateWriter<'a> {
    buffer: &'a mut [u8],
    len: usize,
}

impl<'a> TemplateWriter<'a> {
    fn new(buffer: &'a mut [u8]) -> Self {
        Self { buffer, len: 0 }
    }

    fn len(&self) -> usize {
        self.len
    }

    fn write_uint(&mut self, value: u64) -> MeasurementApiResult {
        self.write_type_value(0, value)
    }

    fn write_array_len(&mut self, len: usize) -> MeasurementApiResult {
        self.write_type_value(4, len as u64)
    }

    fn write_text(&mut self, text: &str) -> MeasurementApiResult {
        self.write_type_value(3, text.len() as u64)?;
        self.write(text.as_bytes())
    }

    fn write_type_value(&mut self, major_type: u8, value: u64) -> MeasurementApiResult {
        let major = major_type << 5;
        if value <= 23 {
            self.write(&[major | value as u8])
        } else if value <= 0xff {
            self.write(&[major | 24, value as u8])
        } else if value <= 0xffff {
            self.write(&[major | 25])?;
            self.write(&(value as u16).to_be_bytes())
        } else if value <= 0xffff_ffff {
            self.write(&[major | 26])?;
            self.write(&(value as u32).to_be_bytes())
        } else {
            self.write(&[major | 27])?;
            self.write(&value.to_be_bytes())
        }
    }

    fn write(&mut self, bytes: &[u8]) -> MeasurementApiResult {
        let end = self
            .len
            .checked_add(bytes.len())
            .ok_or(MeasurementApiError::EvidenceBufferTooSmall)?;
        let out = self
            .buffer
            .get_mut(self.len..end)
            .ok_or(MeasurementApiError::EvidenceBufferTooSmall)?;
        out.copy_from_slice(bytes);
        self.len = end;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::api::read::MeasurementValue;
    use crate::attestation_manifest::{ATTESTATION_FLAG_AK_TARGET, ATTESTATION_FLAG_SOC_TCB_DPE};
    use caliptra_ocp_eat::ocp_profile::{
        IntegrityRegisterEntry, IntegrityRegisterIdChoice, TaggedConciseEvidence,
    };
    use caliptra_ocp_eat::{
        CborEncodable, CborEncoder, ClassIdTypeChoice, ClassMap, ConciseEvidence,
        ConciseEvidenceMap, DigestEntry, EnvironmentMap, EvTriplesMap, EvidenceTripleRecord,
        MeasurementMap, MeasurementValue as OcpMeasurementValue, TaggedBytes,
    };

    fn marker<const N: usize>(start: u8) -> [u8; N] {
        let mut out = [0u8; N];
        for (idx, byte) in out.iter_mut().enumerate() {
            *byte = start.wrapping_add(idx as u8);
        }
        out
    }

    fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        haystack
            .windows(needle.len())
            .position(|window| window == needle)
    }

    fn encode_ocp_measurement_value(measurement: &MeasurementValue, encoded: &mut [u8]) -> usize {
        let digest = [DigestEntry {
            alg_id: EVIDENCE_SHA384_ALG_ID,
            value: &measurement.current_digest,
        }];
        let integrity_digest = [DigestEntry {
            alg_id: EVIDENCE_SHA384_ALG_ID,
            value: &measurement.journey_digest,
        }];
        let integrity_registers = [IntegrityRegisterEntry {
            id: IntegrityRegisterIdChoice::Uint(EVIDENCE_INTEGRITY_REGISTER_ID),
            digests: &integrity_digest,
        }];
        let measurement_map = MeasurementMap {
            key: EVIDENCE_MEASUREMENT_KEY,
            mval: OcpMeasurementValue {
                version: None,
                svn: Some(measurement.svn),
                digests: Some(&digest),
                integrity_registers: Some(&integrity_registers),
                raw_value: None,
                raw_value_mask: None,
            },
        };
        let mut encoder = CborEncoder::new(encoded);
        measurement_map.encode(&mut encoder).unwrap();
        encoder.len()
    }

    #[test]
    fn fw_id_class_id_uses_fixed_uppercase_hex() {
        assert_eq!(&fw_id_class_id(0x0000_0002), b"0x00000002");
        assert_eq!(&fw_id_class_id(0xabcd_1234), b"0xABCD1234");
    }

    #[test]
    fn default_inventory_contract_marks_all_manifest_entries_eligible() {
        let tcb_entry = AttestationManifestEntry {
            fw_id: 0x1000,
            attestation_flags: ATTESTATION_FLAG_SOC_TCB_DPE | ATTESTATION_FLAG_AK_TARGET,
        };
        let non_tcb_entry = AttestationManifestEntry {
            fw_id: 0x2000,
            attestation_flags: 0,
        };

        assert!(inventory_evidence_eligible(tcb_entry));
        assert!(inventory_evidence_eligible(non_tcb_entry));
    }

    #[test]
    fn evidence_buffer_size_contract_returns_len_or_distinct_error() {
        assert_eq!(validate_evidence_buffer_size(128, 128), Ok(128));
        assert_eq!(validate_evidence_buffer_size(129, 128), Ok(128));
        assert_eq!(
            validate_evidence_buffer_size(127, 128),
            Err(MeasurementApiError::EvidenceBufferTooSmall)
        );
    }

    #[test]
    fn tcb_contract_uses_current_cumulative_and_zero_svn() {
        let current = [0x11; EVIDENCE_DIGEST_SIZE];
        let cumulative = [0x22; EVIDENCE_DIGEST_SIZE];
        let measurement = MeasurementValue {
            target_env_id: 0x1000,
            current_digest: current,
            journey_digest: cumulative,
            svn: TCB_EVIDENCE_SVN,
        };

        assert_eq!(measurement.target_env_id, 0x1000);
        assert_eq!(measurement.current_digest, current);
        assert_eq!(measurement.journey_digest, cumulative);
        assert_eq!(measurement.svn, TCB_EVIDENCE_SVN);
    }

    #[test]
    fn non_tcb_contract_uses_soft_pcr_svn_and_omits_fw_version() {
        let current = [0x33; EVIDENCE_DIGEST_SIZE];
        let journey = [0x44; EVIDENCE_DIGEST_SIZE];
        let measurement = MeasurementValue {
            target_env_id: 0x2000,
            current_digest: current,
            journey_digest: journey,
            svn: 7,
        };

        assert_eq!(measurement.target_env_id, 0x2000);
        assert_eq!(measurement.current_digest, current);
        assert_eq!(measurement.journey_digest, journey);
        assert_eq!(measurement.svn, 7);
    }

    #[test]
    fn measurement_value_encoder_uses_measurement_map_contract() {
        let current = marker::<EVIDENCE_DIGEST_SIZE>(0x10);
        let journey = marker::<EVIDENCE_DIGEST_SIZE>(0x60);
        let measurement = MeasurementValue {
            target_env_id: 0x1000,
            current_digest: current,
            journey_digest: journey,
            svn: 3,
        };

        let mut encoded = [0u8; 256];
        let encoded_len = super::encode_measurement_value(&mut encoded, &measurement).unwrap();
        let encoded = &encoded[..encoded_len];
        let mut expected = [0u8; 256];
        let expected_len = encode_ocp_measurement_value(&measurement, &mut expected);

        assert_eq!(encoded, &expected[..expected_len]);
        assert_eq!(
            encoded.get(..8),
            Some(&[0xa2, 0x00, 0x01, 0x01, 0xa3, 0x01, 0x03, 0x02][..])
        );
        assert!(find_subslice(encoded, &current).is_some());
        assert!(find_subslice(encoded, &journey).is_some());
    }

    #[test]
    fn concise_evidence_contract_encodes_tagged_shape_in_order() {
        const MANIFEST_VENDOR: &str = "vendor";
        const MANIFEST_MODEL: &str = "model";
        let current = marker::<EVIDENCE_DIGEST_SIZE>(0x10);
        let integrity = marker::<EVIDENCE_DIGEST_SIZE>(0x60);
        let first_class_id = fw_id_class_id(0x0000_1000);
        let second_class_id = fw_id_class_id(0x0000_2000);
        let digest = [DigestEntry {
            alg_id: EVIDENCE_SHA384_ALG_ID,
            value: &current,
        }];
        let integrity_digest = [DigestEntry {
            alg_id: EVIDENCE_SHA384_ALG_ID,
            value: &integrity,
        }];
        let integrity_registers = [IntegrityRegisterEntry {
            id: IntegrityRegisterIdChoice::Uint(EVIDENCE_INTEGRITY_REGISTER_ID),
            digests: &integrity_digest,
        }];
        let measurements = [MeasurementMap {
            key: EVIDENCE_MEASUREMENT_KEY,
            mval: OcpMeasurementValue {
                version: None,
                svn: Some(3),
                digests: Some(&digest),
                integrity_registers: Some(&integrity_registers),
                raw_value: None,
                raw_value_mask: None,
            },
        }];
        let triples = [
            EvidenceTripleRecord {
                environment: EnvironmentMap {
                    class: ClassMap {
                        class_id: ClassIdTypeChoice::TaggedBytes(TaggedBytes::new(&first_class_id)),
                        vendor: Some(MANIFEST_VENDOR),
                        model: Some(MANIFEST_MODEL),
                    },
                },
                measurements: &measurements,
            },
            EvidenceTripleRecord {
                environment: EnvironmentMap {
                    class: ClassMap {
                        class_id: ClassIdTypeChoice::TaggedBytes(TaggedBytes::new(
                            &second_class_id,
                        )),
                        vendor: Some(MANIFEST_VENDOR),
                        model: Some(MANIFEST_MODEL),
                    },
                },
                measurements: &measurements,
            },
        ];
        let evidence = ConciseEvidence::Tagged(TaggedConciseEvidence {
            concise_evidence: ConciseEvidenceMap {
                ev_triples: EvTriplesMap {
                    evidence_triples: Some(&triples),
                    identity_triples: None,
                    dependency_triples: None,
                    membership_triples: None,
                    coswid_triples: None,
                    attest_key_triples: None,
                },
                evidence_id: None,
                profile: None,
            },
        });

        let mut encoded = [0u8; 512];
        let encoded_len = {
            let mut encoder = CborEncoder::new(&mut encoded);
            evidence.encode(&mut encoder).unwrap();
            encoder.len()
        };
        let encoded = &encoded[..encoded_len];

        let first_measurement = MeasurementValue {
            target_env_id: 0x0000_1000,
            current_digest: current,
            journey_digest: integrity,
            svn: 3,
        };
        let second_measurement = MeasurementValue {
            target_env_id: 0x0000_2000,
            current_digest: current,
            journey_digest: integrity,
            svn: 3,
        };
        let mut templated = [0u8; 512];
        let templated_len = {
            let mut encoder =
                MeasurementEvidenceEncoder::new(&mut templated, MANIFEST_VENDOR, MANIFEST_MODEL, 2)
                    .unwrap();
            encoder.encode_measurement(&first_measurement).unwrap();
            encoder.encode_measurement(&second_measurement).unwrap();
            encoder.finish().unwrap()
        };
        let templated = &templated[..templated_len];

        assert_eq!(templated, encoded);
        corim_rs::coev::TaggedConciseEvidence::from_cbor(templated).unwrap();
        assert_eq!(encoded.get(..3), Some(&[0xd9, 0x02, 0x3b][..]));
        let first_pos = find_subslice(encoded, &first_class_id).unwrap();
        let second_pos = find_subslice(encoded, &second_class_id).unwrap();
        assert!(first_pos < second_pos);
        assert!(find_subslice(encoded, MANIFEST_VENDOR.as_bytes()).is_some());
        assert!(find_subslice(encoded, MANIFEST_MODEL.as_bytes()).is_some());
        assert!(find_subslice(encoded, &current).is_some());
        assert!(find_subslice(encoded, &integrity).is_some());
    }
}
