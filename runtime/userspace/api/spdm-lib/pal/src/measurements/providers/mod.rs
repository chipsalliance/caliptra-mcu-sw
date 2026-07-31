// Licensed under the Apache-2.0 license

//! Built-in SPDM measurement provider implementations.
//!
//! These adapters keep SPDM-specific metadata and nonce handling in `spdm-pal`
//! while delegating evidence-format construction to lower-level APIs.

pub mod ocp_eat;
#[cfg(feature = "pcr-quote")]
pub mod pcr_quote;

pub use ocp_eat::OcpEatMeasurementProvider;
#[cfg(feature = "pcr-quote")]
pub use pcr_quote::PcrQuoteMeasurementProvider;
