// Licensed under the Apache-2.0 license

#![allow(dead_code)]

include!(concat!(env!("OUT_DIR"), "/soc_env_config.rs"));

// Re-export raw constants for direct use if desired.
pub use FW_IDS as SOC_FW_IDS;
pub use MODEL as SOC_MODEL;
pub use VENDOR as SOC_VENDOR;
// Some generated versions may not define NUM_FW_IDS; derive length defensively.
pub const NUM_SOC_FW_IDS: usize = FW_IDS.len();

pub const NUM_DEFAULT_FW_COMPONENTS: usize = 3;
const CALIPTRA_FW_FMC_OID: &str = "FMC_INFO";
const CALIPTRA_FW_RT_OID: &str = "RT_INFO";
const CALIPTRA_FW_AUTH_MAN_ID: &str = "SOC_MANIFEST";
