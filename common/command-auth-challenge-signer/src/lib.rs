// Licensed under the Apache-2.0 license

//! Command authorization trait and default HMAC-SHA384 implementation.
//!
//! The [`CommandAuthChallengeSigner`] trait abstracts MAC computation for authorized
//! Caliptra commands.  The caller obtains a 32-byte challenge from the device,
//! then asks the authorizer to produce a 48-byte MAC over
//! `cmd_id(BE,4) || payload || challenge(32)`.
//!
//! [`HmacCommandAuthorizer`] is the default implementation that computes
//! HMAC-SHA384 using a caller-supplied key.

use anyhow::Result;
use hmac::{Hmac, Mac};
use sha2::Sha384;

/// Trait for authorizing Caliptra commands that require challenge-response MAC.
///
/// Implementors receive:
/// - `cmd_id`: The command identifier (u32, serialized big-endian).
/// - `payload`: Arbitrary command-specific payload bytes (e.g. partition as LE u32).
/// - `challenge`: The 32-byte challenge obtained from the device.
///
/// Returns a 48-byte MAC (HMAC-SHA384 sized).
pub trait CommandAuthChallengeSigner {
    fn authorize(&self, cmd_id: u32, payload: &[u8], challenge: &[u8; 32]) -> Result<[u8; 48]>;
}

/// A [`CommandAuthChallengeSigner`] that computes HMAC-SHA384.
///
/// The HMAC is computed over `cmd_id(BE,4) || payload || challenge(32)`.
pub struct HmacCommandAuthorizer {
    key: Vec<u8>,
}

impl HmacCommandAuthorizer {
    pub fn new(key: Vec<u8>) -> Self {
        Self { key }
    }
}

impl CommandAuthChallengeSigner for HmacCommandAuthorizer {
    fn authorize(&self, cmd_id: u32, payload: &[u8], challenge: &[u8; 32]) -> Result<[u8; 48]> {
        let mut mac = Hmac::<Sha384>::new_from_slice(&self.key)
            .map_err(|e| anyhow::anyhow!("HMAC key error: {}", e))?;
        mac.update(&cmd_id.to_be_bytes());
        mac.update(payload);
        mac.update(challenge);
        let result = mac.finalize().into_bytes();
        let mut out = [0u8; 48];
        out.copy_from_slice(&result);
        Ok(out)
    }
}
