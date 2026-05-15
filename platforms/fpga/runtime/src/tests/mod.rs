// Licensed under the Apache-2.0 license

#[cfg(any(feature = "test-i3c-simple", feature = "test-i3c-constant-writes",))]
pub(crate) mod i3c_target_test;
#[cfg(feature = "test-mctp-capsule-loopback")]
pub(crate) mod mctp_test;
