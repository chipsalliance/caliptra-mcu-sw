// Licensed under the Apache-2.0 license

//! A module containing the protocol definition of the OCP interface.  It will also provide
//! trait definitions which integrators can implement to utilize the protocol regardless of
//! underlying transfer medium.

#![cfg_attr(not(test), no_std)]

pub mod error;
pub mod protocol;
