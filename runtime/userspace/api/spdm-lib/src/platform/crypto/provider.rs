// Licensed under the Apache-2.0 license

extern crate alloc;

use crate::platform::crypto::hash::SpdmHash;
use alloc::boxed::Box;

/// Factory interface for creating SPDM hashers.
/// Platform crates will implement this out-of-tree and provide a concrete hasher.
pub trait SpdmCryptoProvider {
    fn create_hasher(&mut self) -> Box<dyn SpdmHash>;
}
