// Licensed under the Apache-2.0 license

//! # `dice-rs`
//!
//! A pure Rust implementation of the [TCG DICE Attestation Architecture](https://trustedcomputinggroup.org/wp-content/uploads/DICE-Attestation-Architecture-v1.2_pub.pdf)
//! certificate extensions, compatible with TCG DICE standards and Veraison DICE models.
//!
//! ## Overview
//!
//! `dice-rs` provides strongly-typed data structures and ASN.1 DER decoding
//! for TCG DICE extensions commonly found in device certificate chains (e.g., Caliptra,
//! OpenDice, and OCP DPE iRoT profiles):
//!
//! - [`TcbInfo`]: TCG DICE TCB information extension (`tcg-dice-TcbInfo`, OID `2.23.133.5.4.1`)
//! - [`MultiTcbInfo`]: Multiple TCB measurements (`tcg-dice-MultiTcbInfo`, OID `2.23.133.5.4.5`)
//! - [`Ueid`]: Universal Entity Identifier (`tcg-dice-Ueid`, OID `2.23.133.5.4.4`)
//! - Key Purpose / EKU identifiers for identity, attestation, and assertion keys.
//!
//! ## Example
//!
//! ```rust,ignore
//! use dice_rs::tcb_info::TcbInfo;
//!
//! let der_bytes: &[u8] = /* extension octet string payload */;
//! let tcb_info = TcbInfo::from_der(der_bytes)?;
//!
//! if let Some(version) = tcb_info.version {
//!     println!("Version: {}", version);
//! }
//! ```

#![cfg_attr(not(feature = "std"), no_std)]

pub mod error;
pub mod kp;
pub mod multi_tcb_info;
pub mod oids;
pub mod tcb_info;
pub mod ueid;

#[cfg(feature = "std")]
pub mod cert;

pub use error::{DiceError, Result};
pub use multi_tcb_info::MultiTcbInfo;
pub use tcb_info::{Fwid, IntegrityRegister, TcbInfo};
pub use ueid::Ueid;
