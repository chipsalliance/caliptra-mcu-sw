// Licensed under the Apache-2.0 license

// Temp value, to be replaced with actual max size
pub const OCP_MIN_EAT_NONCE_SIZE: usize = 8;
pub const OCP_MAX_EAT_NONCE_SIZE: usize = 64;
// pub const MAX_STR_LEN: usize = 100; // max length for key ID

// BER encoded format of OCP Security OID: "1.3.6.1.4.1.42623.1"
pub const OCP_SECURITY_OID: [u8; 9] = [0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xCC, 0x7F, 0x01];

pub const DEFAULT_RIM_LOCATOR: &str = "https://www.opencompute.org/projects/security";

pub const OCP_EAT_CLAIMS_KEY_ID: &str = "OCP EAT Claims";
pub const OCP_ENVELOPE_CSR_KEY_ID: &str = "OCP Envelope CSR";

pub const DEFAULT_DEBUG_STATE: u8 = 1; // 0: disabled, 1: enabled
