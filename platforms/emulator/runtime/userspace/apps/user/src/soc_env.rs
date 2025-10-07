// Licensed under the Apache-2.0 license

#![allow(dead_code)]

include!(concat!(env!("OUT_DIR"), "/soc_env_config.rs"));

// Re-export raw constants for direct use.
#[allow(unused_imports)]
pub use FW_IDS as SOC_FW_IDS;
#[allow(unused_imports)]
pub use FW_ID_STRS as SOC_FW_ID_STRS;
#[allow(unused_imports)]
pub use MODEL as SOC_MODEL;
#[allow(unused_imports)]
pub use VENDOR as SOC_VENDOR;
// Some generated versions may not define NUM_FW_IDS; derive length defensively.
pub const NUM_SOC_FW_COMPONENTS: usize = FW_IDS.len();

pub const NUM_DEFAULT_FW_COMPONENTS: usize = 3;
const CALIPTRA_FW_FMC_OID: &str = "FMC_INFO"; //TODO: This should be a registered OID
const CALIPTRA_FW_RT_OID: &str = "RT_INFO"; // TODO: This should be a registered OID
const CALIPTRA_FW_AUTH_MAN_ID: &str = "SOC_MANIFEST";
pub const DEFAULT_FW_IDS: [&str; NUM_DEFAULT_FW_COMPONENTS] = [
    CALIPTRA_FW_FMC_OID,
    CALIPTRA_FW_RT_OID,
    CALIPTRA_FW_AUTH_MAN_ID,
];
