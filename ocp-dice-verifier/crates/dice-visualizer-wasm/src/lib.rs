// Licensed under the Apache-2.0 license

//! WebAssembly DICE and SPDM certificate chain visualizer.
//!
//! Exposes WebAssembly bindings to decode SPDM certificate chains,
//! extract TCG DICE extensions, and generate interactive chain visualizations.

pub mod model;
pub mod visualizer;

use wasm_bindgen::prelude::*;

const SAMPLE_CI_CHAIN: &[u8] = include_bytes!("../../../test-data/certificate_chain_slot_00.der");

/// Parses an SPDM certificate chain blob (either raw concatenated DER or SPDM header format)
/// and returns a serialized JSON string representing the full visualizer model.
#[wasm_bindgen]
pub fn parse_spdm_cert_chain(data: &[u8]) -> String {
    let output = visualizer::parse_chain_to_view(data);
    serde_json::to_string(&output).unwrap_or_else(|e| {
        format!(r#"{{"success":false,"total_certs":0,"error":"JSON serialization failed: {e}"}}"#)
    })
}

/// Returns the embedded golden Caliptra MCU Slot 0 certificate chain artifact from CI.
#[wasm_bindgen]
pub fn get_sample_ci_chain() -> Vec<u8> {
    SAMPLE_CI_CHAIN.to_vec()
}
