// Licensed under the Apache-2.0 license

mod test_ecc_errors;
mod test_hitless_update;
mod test_lc_ctrl;
mod test_otp_blank_check;
mod test_sw_digest_lock;
mod test_warm_reset;

// testing this requires enabling the BootFSM breakpoint which is only implemented
// on FPGA for now.
#[cfg(feature = "fpga_realtime")]
mod test_bootfsm_timeout;
