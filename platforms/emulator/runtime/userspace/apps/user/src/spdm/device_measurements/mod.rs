// Licensed under the Apache-2.0 license

#[cfg(any(
    feature = "test-mctp-spdm-responder-conformance",
    feature = "test-mctp-spdm-attestation"
))]
pub mod ocp_eat;
pub mod pcr_quote;
