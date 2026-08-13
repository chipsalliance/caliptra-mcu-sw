// Licensed under the Apache-2.0 license

//! OCP EAT claims payload generation for Measurement API concise evidence.
//!
//! The generated template comes from `caliptra-ocp-eat` and covers the outer
//! EAT claims. Runtime fills nonce, debug status, and Measurement API concise
//! evidence.

use caliptra_mcu_libsyscall_caliptra::mci::{mci_reg, Mci};
use caliptra_mcu_libsyscall_caliptra::DefaultSyscalls;
use mcu_error::McuResult;

use super::common::{cbor_bstr_len, write_type_header};

include!(concat!(env!("OUT_DIR"), "/eat_claims_template.rs"));

pub const NONCE_LEN: usize = 32;
pub const EAT_PAYLOAD_MAX_SIZE: usize = EAT_CLAIMS_PREFIX.len()
    + NONCE_LEN
    + EAT_CLAIMS_DBGSTAT_PREFIX.len()
    + 1
    + EAT_CLAIMS_EVIDENCE_PREFIX.len()
    + cbor_bstr_len(CONCISE_EVIDENCE_MAX_SIZE)
    + EAT_CLAIMS_SUFFIX.len();

const DEBUG_LOCKED_MASK: u32 = 1 << 2;
const EAT_DBGSTAT_ENABLED: u8 = 0;
const EAT_DBGSTAT_DISABLED: u8 = 1;
const CONCISE_EVIDENCE_BSTR_HEADER_LEN: usize = 3;

#[derive(Copy, Clone)]
pub(crate) struct ClaimsPayloadLayout {
    evidence_bstr_header_offset: usize,
    evidence_offset: usize,
}

pub fn encode_claims_payload(
    claims_buf: &mut [u8],
    nonce: &[u8],
    concise_evidence: &[u8],
) -> McuResult<usize> {
    encode_claims_payload_with_debug_status(
        claims_buf,
        nonce,
        read_debug_status()?,
        concise_evidence,
    )
}

pub(crate) fn start_claims_payload(
    claims_buf: &mut [u8],
    nonce: &[u8],
) -> McuResult<ClaimsPayloadLayout> {
    start_claims_payload_with_debug_status(claims_buf, nonce, read_debug_status()?)
}

fn start_claims_payload_with_debug_status(
    claims_buf: &mut [u8],
    nonce: &[u8],
    debug_status: u8,
) -> McuResult<ClaimsPayloadLayout> {
    if nonce.len() != NONCE_LEN {
        return Err(mcu_error::codes::INTERNAL_BUG);
    }

    let mut writer = ClaimsWriter::new(claims_buf);
    writer.write(EAT_CLAIMS_PREFIX)?;
    writer.write(nonce)?;
    writer.write(EAT_CLAIMS_DBGSTAT_PREFIX)?;
    writer.write_uint(debug_status)?;
    writer.write(EAT_CLAIMS_EVIDENCE_PREFIX)?;
    let evidence_bstr_header_offset = writer.len();
    writer.write(&[0u8; CONCISE_EVIDENCE_BSTR_HEADER_LEN])?;
    let evidence_offset = writer.len();
    Ok(ClaimsPayloadLayout {
        evidence_bstr_header_offset,
        evidence_offset,
    })
}

pub(crate) fn concise_evidence_buffer_mut(
    claims_buf: &mut [u8],
    layout: ClaimsPayloadLayout,
) -> McuResult<&mut [u8]> {
    let max_end = EAT_PAYLOAD_MAX_SIZE
        .checked_sub(EAT_CLAIMS_SUFFIX.len())
        .ok_or(mcu_error::codes::INTERNAL_BUG)?;
    if layout.evidence_offset > max_end {
        return Err(mcu_error::codes::INTERNAL_BUG);
    }
    claims_buf
        .get_mut(layout.evidence_offset..max_end)
        .ok_or(mcu_error::codes::INTERNAL_BUG)
}

pub(crate) fn finish_claims_payload(
    claims_buf: &mut [u8],
    layout: ClaimsPayloadLayout,
    concise_evidence_len: usize,
) -> McuResult<usize> {
    // Upper bound on the payload assuming the maximum reserved 3-byte concise
    // evidence header. Validating against this before compaction guarantees the
    // `copy_within` below stays in bounds (the canonical header is <= reserved).
    let reserved_end = layout
        .evidence_offset
        .checked_add(concise_evidence_len)
        .and_then(|end| end.checked_add(EAT_CLAIMS_SUFFIX.len()))
        .ok_or(mcu_error::codes::INTERNAL_BUG)?;
    if reserved_end > EAT_PAYLOAD_MAX_SIZE || reserved_end > claims_buf.len() {
        return Err(mcu_error::codes::INTERNAL_BUG);
    }

    // Write the minimal (canonical) CBOR bstr header. `start_claims_payload`
    // reserves `CONCISE_EVIDENCE_BSTR_HEADER_LEN` bytes; when the actual length
    // needs a shorter header, compact the evidence left so the payload is
    // deterministically encoded (required by CHALLENGE measurement summaries).
    let header_len = write_type_header(
        claims_buf
            .get_mut(
                layout.evidence_bstr_header_offset
                    ..layout.evidence_bstr_header_offset + CONCISE_EVIDENCE_BSTR_HEADER_LEN,
            )
            .ok_or(mcu_error::codes::INTERNAL_BUG)?,
        2,
        concise_evidence_len as u64,
    )?;
    if header_len > CONCISE_EVIDENCE_BSTR_HEADER_LEN {
        return Err(mcu_error::codes::INTERNAL_BUG);
    }

    let evidence_start = layout
        .evidence_bstr_header_offset
        .checked_add(header_len)
        .ok_or(mcu_error::codes::INTERNAL_BUG)?;
    if header_len < CONCISE_EVIDENCE_BSTR_HEADER_LEN {
        claims_buf.copy_within(
            layout.evidence_offset..layout.evidence_offset + concise_evidence_len,
            evidence_start,
        );
    }

    let evidence_end = evidence_start
        .checked_add(concise_evidence_len)
        .ok_or(mcu_error::codes::INTERNAL_BUG)?;
    let suffix_end = evidence_end
        .checked_add(EAT_CLAIMS_SUFFIX.len())
        .ok_or(mcu_error::codes::INTERNAL_BUG)?;

    claims_buf
        .get_mut(evidence_end..suffix_end)
        .ok_or(mcu_error::codes::INTERNAL_BUG)?
        .copy_from_slice(EAT_CLAIMS_SUFFIX);
    Ok(suffix_end)
}

fn encode_claims_payload_with_debug_status(
    claims_buf: &mut [u8],
    nonce: &[u8],
    debug_status: u8,
    concise_evidence: &[u8],
) -> McuResult<usize> {
    if nonce.len() != NONCE_LEN {
        return Err(mcu_error::codes::INTERNAL_BUG);
    }

    let mut writer = ClaimsWriter::new(claims_buf);
    writer.write(EAT_CLAIMS_PREFIX)?;
    writer.write(nonce)?;
    writer.write(EAT_CLAIMS_DBGSTAT_PREFIX)?;
    writer.write_uint(debug_status)?;
    writer.write(EAT_CLAIMS_EVIDENCE_PREFIX)?;
    writer.write_bstr(concise_evidence)?;
    writer.write(EAT_CLAIMS_SUFFIX)?;
    Ok(writer.len())
}

fn debug_status_from_security_state(security_state: u32) -> u8 {
    if security_state & DEBUG_LOCKED_MASK == 0 {
        EAT_DBGSTAT_ENABLED
    } else {
        EAT_DBGSTAT_DISABLED
    }
}

fn read_debug_status() -> McuResult<u8> {
    let mci = Mci::<DefaultSyscalls>::new();
    let security_state = mci.read(mci_reg::SECURITY_STATE, 0)?;
    Ok(debug_status_from_security_state(security_state))
}

struct ClaimsWriter<'a> {
    buffer: &'a mut [u8],
    len: usize,
}

impl<'a> ClaimsWriter<'a> {
    fn new(buffer: &'a mut [u8]) -> Self {
        Self { buffer, len: 0 }
    }

    fn len(&self) -> usize {
        self.len
    }

    fn write_bstr(&mut self, bytes: &[u8]) -> McuResult<()> {
        self.write_type_value(2, bytes.len() as u64)?;
        self.write(bytes)
    }

    fn write_uint(&mut self, value: u8) -> McuResult<()> {
        self.write_type_value(0, u64::from(value))
    }

    fn write_type_value(&mut self, major_type: u8, value: u64) -> McuResult<()> {
        let mut header = [0u8; 9];
        let header_len = write_type_header(&mut header, major_type, value)?;
        self.write(&header[..header_len])
    }

    fn write(&mut self, bytes: &[u8]) -> McuResult<()> {
        let end = self
            .len
            .checked_add(bytes.len())
            .ok_or(mcu_error::codes::INTERNAL_BUG)?;
        let out = self
            .buffer
            .get_mut(self.len..end)
            .ok_or(mcu_error::codes::INTERNAL_BUG)?;
        out.copy_from_slice(bytes);
        self.len = end;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use coset::cbor::value::Value;
    use coset::CborSerializable;

    const CLAIM_KEY_NONCE: i128 = 10;
    const CLAIM_KEY_DEBUG_STATUS: i128 = 263;
    const CLAIM_KEY_MEASUREMENTS: i128 = 273;
    const CLAIM_KEY_ISSUER: i128 = 1;
    const CLAIM_KEY_CTI: i128 = 7;

    fn map_value(value: &Value, key: i128) -> Option<&Value> {
        let Value::Map(entries) = value else {
            return None;
        };
        entries.iter().find_map(|(entry_key, entry_value)| {
            if value_as_i128(entry_key) == Some(key) {
                Some(entry_value)
            } else {
                None
            }
        })
    }

    fn value_as_i128(value: &Value) -> Option<i128> {
        match value {
            Value::Integer(integer) => Some((*integer).into()),
            _ => None,
        }
    }

    #[test]
    fn debug_status_maps_mci_debug_lock_bit_to_eat_values() {
        assert_eq!(debug_status_from_security_state(0), EAT_DBGSTAT_ENABLED);
        assert_eq!(
            debug_status_from_security_state(DEBUG_LOCKED_MASK),
            EAT_DBGSTAT_DISABLED
        );
    }

    #[test]
    fn claims_payload_embeds_nonce_debug_status_and_concise_evidence() {
        let nonce = [0x11; NONCE_LEN];
        let concise_evidence = [0x5a; 32];
        let mut encoded = [0u8; 256];

        let encoded_len = encode_claims_payload_with_debug_status(
            &mut encoded,
            &nonce,
            EAT_DBGSTAT_ENABLED,
            &concise_evidence,
        )
        .unwrap();
        let claims = Value::from_slice(&encoded[..encoded_len]).unwrap();

        assert_eq!(
            map_value(&claims, CLAIM_KEY_NONCE),
            Some(&Value::Bytes(nonce.to_vec()))
        );
        assert_eq!(
            map_value(&claims, CLAIM_KEY_DEBUG_STATUS).and_then(value_as_i128),
            Some(i128::from(EAT_DBGSTAT_ENABLED))
        );
        assert!(map_value(&claims, CLAIM_KEY_ISSUER).is_none());
        assert!(map_value(&claims, CLAIM_KEY_CTI).is_none());

        let Some(Value::Array(entries)) = map_value(&claims, CLAIM_KEY_MEASUREMENTS) else {
            panic!("measurements must be an array");
        };
        assert_eq!(entries.len(), 1);
        let Value::Array(measurement_entry) = &entries[0] else {
            panic!("measurement entry must be an array");
        };
        assert_eq!(measurement_entry.len(), 2);
        assert!(matches!(measurement_entry[0], Value::Integer(_)));
        assert_eq!(
            measurement_entry[1],
            Value::Bytes(concise_evidence.to_vec())
        );
    }

    #[test]
    fn in_place_payload_matches_reference_encoder() {
        // Concise evidence lengths that exercise 1-, 2- and 3-byte bstr headers.
        // The <256 cases (which need compaction) are what the emulator hits and
        // previously errored; assert the in-place path is byte-identical to the
        // known-good non-in-place encoder, i.e. canonically encoded.
        let nonce = [0x11; NONCE_LEN];
        for concise_len in [10usize, 32, 200, 300] {
            let concise_evidence: std::vec::Vec<u8> =
                (0..concise_len).map(|i| (i % 251) as u8).collect();

            let mut in_place = std::vec![0u8; EAT_PAYLOAD_MAX_SIZE];
            let layout =
                start_claims_payload_with_debug_status(&mut in_place, &nonce, EAT_DBGSTAT_ENABLED)
                    .unwrap();
            concise_evidence_buffer_mut(&mut in_place, layout).unwrap()[..concise_len]
                .copy_from_slice(&concise_evidence);
            let payload_len = finish_claims_payload(&mut in_place, layout, concise_len).unwrap();

            let mut reference = std::vec![0u8; EAT_PAYLOAD_MAX_SIZE];
            let reference_len = encode_claims_payload_with_debug_status(
                &mut reference,
                &nonce,
                EAT_DBGSTAT_ENABLED,
                &concise_evidence,
            )
            .unwrap();

            assert_eq!(payload_len, reference_len, "len mismatch for {concise_len}");
            assert_eq!(
                &in_place[..payload_len],
                &reference[..reference_len],
                "bytes mismatch for {concise_len}"
            );

            let claims = Value::from_slice(&in_place[..payload_len]).unwrap();
            let Some(Value::Array(entries)) = map_value(&claims, CLAIM_KEY_MEASUREMENTS) else {
                panic!("measurements must be an array");
            };
            assert_eq!(entries.len(), 1);
        }
    }
}
