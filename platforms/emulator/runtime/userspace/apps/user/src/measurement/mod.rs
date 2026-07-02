// Licensed under the Apache-2.0 license

mod integrator_manifest;

#[allow(dead_code)]
pub(crate) fn attestation_manifest_bytes() -> &'static [u8] {
    integrator_manifest::ATTESTATION_MANIFEST_BYTES
}

#[cfg(test)]
mod tests {
    use super::*;
    use caliptra_mcu_measurement_api::attestation_manifest::parse_and_validate;

    #[test]
    fn generated_attestation_manifest_is_valid() {
        parse_and_validate(attestation_manifest_bytes()).unwrap();
    }
}
