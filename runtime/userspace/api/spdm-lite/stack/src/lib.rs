// Licensed under the Apache-2.0 license

//! `mcu-spdm-lite-stack` — SPDM responder state machine and dispatcher.
//!
//! This crate implements the responder side of the
//! [DMTF DSP0274 SPDM](https://www.dmtf.org/dsp/DSP0274) protocol on
//! top of the SPDM-Lite Platform Abstraction Layer
//! ([`mcu_spdm_lite_traits`]). It owns:
//!
//! * A [`SpdmStack`] — the main `run()` loop that receives an SPDM
//!   request, dispatches it to a handler, and sends back either the
//!   handler's response or a DSP0274 §10.10 `ERROR` PDU.
//! * A [`ConnectionState`] — the per-connection negotiation state
//!   (current phase, negotiated version, peer capabilities, …) plus
//!   the responder's fixed local-policy advertisement.
//! * Per-command handler modules ([`version`], [`capabilities`],
//!   [`algorithms`]).
//!
//! Handlers are pure async functions over `&mut ConnectionState` and
//! `&Pal`; they return [`SpdmResult<PalBytes<'_, Pal>>`](SpdmResult)
//! where `Ok` is the fully-encoded response buffer (transport header
//! + SPDM header + body) and `Err` is a DSP0274 wire-byte that the
//!   dispatcher turns into an `ERROR` PDU.
//!
//! Below the handler/dispatcher boundary this crate uses the
//! workspace-wide [`McuErrorCode`](mcu_error::McuErrorCode) /
//! [`McuResult`](mcu_error::McuResult) types; `?` lifts those into
//! [`SpdmError`] automatically (see [`error`]).

#![no_std]

mod algorithms;
mod build;
mod capabilities;
mod certificate;
mod challenge;
mod chunk;
mod digests;
mod error;
mod measurements;
#[cfg(feature = "set-certificate")]
mod set_certificate;
mod stack;
mod transcript;
mod vendor_defined;
mod version;

pub use error::*;
pub use mcu_spdm_lite_codec::StandardsBodyId;
pub use stack::*;
pub use transcript::*;
pub use vendor_defined::{SpdmVdmBackend, SyncVdmHandlers, VdmHandler, VdmRequest};
