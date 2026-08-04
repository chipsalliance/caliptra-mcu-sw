// Licensed under the Apache-2.0 license

mod integrator_manifest;

mod boot;

pub(crate) use boot::boot_init;

#[allow(dead_code)]
pub(crate) fn attestation_manifest_bytes() -> &'static [u8] {
    integrator_manifest::ATTESTATION_MANIFEST_BYTES
}

#[cfg(test)]
mod tests {
    use super::*;
    use caliptra_mcu_measurement_api::attestation_manifest::{
        parse_and_validate, ATTESTATION_FLAG_AK_TARGET, ATTESTATION_FLAG_SOC_TCB_DPE,
        ATTESTATION_MANIFEST_ENTRY_SIZE, ATTESTATION_MANIFEST_FIXED_HEADER_SIZE,
        ATTESTATION_MANIFEST_MARKER, ATTESTATION_MANIFEST_PLATFORM_INFO_MAX_LEN,
        ATTESTATION_MANIFEST_VERSION,
    };
    use std::vec::Vec;

    const DEFAULT_DUMMY_SOC_FW_ID: u32 = 3;

    #[test]
    fn generated_attestation_manifest_is_valid() {
        parse_and_validate(attestation_manifest_bytes()).unwrap();
    }

    #[test]
    fn dummy_soc_component_manifest_is_valid() {
        let bytes = dummy_soc_component_manifest();
        let manifest = parse_and_validate(&bytes).unwrap();

        assert_eq!(manifest.header().entry_count, 1);
        assert_eq!(manifest.header().tcb_entry_count, 1);

        let mut entries = manifest.entries();
        let entry = entries.next().unwrap();
        assert_eq!(entry.fw_id, DEFAULT_DUMMY_SOC_FW_ID);
        assert!(entry.is_tcb());
        assert!(entry.is_ak_target());
        assert!(entries.next().is_none());
        assert_eq!(manifest.attestation_target_fw_id(), DEFAULT_DUMMY_SOC_FW_ID);
    }

    fn dummy_soc_component_manifest() -> Vec<u8> {
        let vendor = b"test-vendor";
        let model = b"test-model";
        let size = ATTESTATION_MANIFEST_FIXED_HEADER_SIZE + ATTESTATION_MANIFEST_ENTRY_SIZE;
        let flags = ATTESTATION_FLAG_SOC_TCB_DPE | ATTESTATION_FLAG_AK_TARGET;

        let mut bytes = Vec::with_capacity(size);
        push_u32(&mut bytes, ATTESTATION_MANIFEST_MARKER);
        push_u32(&mut bytes, size as u32);
        push_u32(&mut bytes, ATTESTATION_MANIFEST_VERSION);
        push_u32(&mut bytes, ATTESTATION_MANIFEST_FIXED_HEADER_SIZE as u32);
        push_u32(&mut bytes, 1);
        push_u32(&mut bytes, 1);
        push_u16(&mut bytes, vendor.len() as u16);
        push_u16(&mut bytes, model.len() as u16);
        push_fixed_platform_info(&mut bytes, vendor);
        push_fixed_platform_info(&mut bytes, model);
        push_u32(&mut bytes, DEFAULT_DUMMY_SOC_FW_ID);
        push_u32(&mut bytes, flags);
        bytes
    }

    fn push_u32(out: &mut Vec<u8>, value: u32) {
        out.extend_from_slice(&value.to_le_bytes());
    }

    fn push_u16(out: &mut Vec<u8>, value: u16) {
        out.extend_from_slice(&value.to_le_bytes());
    }

    fn push_fixed_platform_info(out: &mut Vec<u8>, value: &[u8]) {
        assert!(value.len() <= ATTESTATION_MANIFEST_PLATFORM_INFO_MAX_LEN);
        out.extend_from_slice(value);
        out.extend(
            std::iter::repeat(0).take(ATTESTATION_MANIFEST_PLATFORM_INFO_MAX_LEN - value.len()),
        );
    }
}
