// Licensed under the Apache-2.0 license

//! Built-in SPDM measurement provider implementations.
//!
//! These adapters keep SPDM-specific metadata and nonce handling in `spdm-pal`
//! while delegating evidence-format construction to lower-level APIs.

pub mod ocp_eat;
pub mod pcr_quote;

pub use ocp_eat::OcpEatMeasurementProvider;
pub use pcr_quote::PcrQuoteMeasurementProvider;
