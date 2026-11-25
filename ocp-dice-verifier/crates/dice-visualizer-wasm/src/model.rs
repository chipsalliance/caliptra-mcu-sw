// Licensed under the Apache-2.0 license

use serde::{Deserialize, Serialize};

/// Root output returned to JavaScript / WebAssembly caller.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VisualizerOutput {
    pub success: bool,
    pub total_certs: usize,
    pub has_spdm_header: bool,
    pub root_hash_hex: Option<String>,
    pub certs: Vec<ParsedCertificateView>,
    pub mermaid_diagram: String,
    pub error: Option<String>,
}

/// Rich display model for an individual certificate in the chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedCertificateView {
    pub index: usize,
    pub tab_title: String,
    pub subject: String,
    pub issuer: String,
    pub serial_hex: String,
    pub not_before: String,
    pub not_after: String,
    pub sig_alg: String,
    pub public_key: PublicKeyInfoView,
    pub dice: DiceView,
    pub spdm: SpdmView,
    pub standard_extensions: Vec<ExtensionView>,
    pub raw_pem: String,
    pub raw_hex_len: usize,
}

/// Public key information for the certificate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyInfoView {
    pub algorithm: String,
    pub key_size_bits: Option<usize>,
}

/// Decoded TCG DICE extensions.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DiceView {
    pub has_dice: bool,
    pub ueid_hex: Option<String>,
    pub tcb_info: Option<TcbInfoView>,
    pub multi_tcb_info: Vec<TcbInfoView>,
    pub key_purposes: Vec<String>,
}

/// TCG DICE OperationalFlags (tag [7]).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OperationalFlagsView {
    pub raw_hex: String,
    pub not_configured: bool,
    pub not_secure: bool,
    pub recovery: bool,
    pub debug: bool,
    pub summary: String,
}

/// TCG DICE TcbInfo view.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TcbInfoView {
    pub vendor: Option<String>,
    pub model: Option<String>,
    pub version: Option<String>,
    pub svn: Option<u64>,
    pub layer: Option<u64>,
    pub index: Option<u64>,
    pub tcb_type: Option<String>,
    pub flags: Option<OperationalFlagsView>,
    pub flags_mask_hex: Option<String>,
    pub vendor_info_hex: Option<String>,
    pub fwids: Vec<FwidView>,
    pub integrity_registers: Vec<IntegrityRegisterView>,
}

/// Integrity register entry representing PCRs or platform measurements.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrityRegisterView {
    pub name: Option<String>,
    pub num: Option<u64>,
    pub digests: Vec<FwidView>,
}

/// Firmware identifier (hash of component).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FwidView {
    pub hash_alg: String,
    pub digest_hex: String,
}

/// Decoded DMTF SPDM extensions.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SpdmView {
    pub has_hardware_identity: bool,
    pub hardware_identity_hex: Option<String>,
    pub is_mutable: bool,
    pub has_device_info: bool,
    pub device_info: Option<String>,
    pub eku_responder_auth: bool,
    pub eku_requester_auth: bool,
}

/// General X.509 extension.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtensionView {
    pub oid: String,
    pub name: String,
    pub critical: bool,
    pub value_summary: String,
}
