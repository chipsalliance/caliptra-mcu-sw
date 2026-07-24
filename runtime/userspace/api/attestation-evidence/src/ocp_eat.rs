// Licensed under the Apache-2.0 license

//! OCP EAT claims payload generation for Measurement API concise evidence.
//!
//! The generated template comes from `caliptra-ocp-eat` and covers the outer
//! EAT claims. Runtime fills nonce, debug status, and Measurement API concise
//! evidence.

use caliptra_mcu_libsyscall_caliptra::mci::{mci_reg, Mci};
use caliptra_mcu_libsyscall_caliptra::DefaultSyscalls;
use mcu_caliptra_api_lite::eat::cbor_bstr_len;
use mcu_error::McuResult;

include!(concat!(env!("OUT_DIR"), "/eat_claims_template.rs"));

pub const NONCE_LEN: usize = 32;
pub const EAT_PAYLOAD_MAX_SIZE: usize = EAT_CLAIMS_PREFIX.len()
    + NONCE_LEN
    + EAT_CLAIMS_DBGSTAT_PREFIX.len()
    + 1
    + EAT_CLAIMS_EVIDENCE_PREFIX.len()
    + cbor_bstr_len(CONCISE_EVIDENCE_WORKSPACE_SIZE)
    + EAT_CLAIMS_SUFFIX.len();

const DEBUG_LOCKED_MASK: u32 = 1 << 2;
const EAT_DBGSTAT_ENABLED: u8 = 0;
const EAT_DBGSTAT_DISABLED: u8 = 1;

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
        let major = major_type << 5;
        if value <= 23 {
            self.write(&[major | value as u8])
        } else if value <= 0xff {
            self.write(&[major | 24, value as u8])?;
            self.write(&[value as u8])
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

    fn map_value<'a>(value: &'a Value, key: i128) -> Option<&'a Value> {
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
        let concise_evidence = [0xd9, 0x02, 0x3b, 0xa1, 0x00, 0xa0];
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
}
