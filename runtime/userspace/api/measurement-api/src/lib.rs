// Licensed under the Apache-2.0 license

#![no_std]

pub mod api;
pub mod attestation_manifest;
pub mod errors;

/// Reset classification passed to `measurement_boot_init`.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum BootKind {
    /// Cold boot: persistent measurement state is stale and must be
    /// reinitialized.
    ColdBoot,
    /// MCU hitless update: preserved measurement state must be validated
    /// against the authenticated attestation policy.
    HitlessUpdate,
}

/// Attestation availability state owned by the Measurement API.
///
/// Later Measurement API entry points (W6-W9) gate evidence generation and
/// component measurement-state mutation on this state.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum AttestationState {
    /// Boot initialization has not completed yet.
    Uninitialized,
    /// Measurement state is valid; attestation flows may run.
    Active,
    /// Measurement state is invalid; normal attestation flows are blocked
    /// until cold boot reinitializes measurement state.
    Error,
}
