// Licensed under the Apache-2.0 license

//! Shared types for Caliptra Cryptographic Manager (CM) mailbox commands.

/// Size in bytes of a CMK handle.
pub const CMK_SIZE: usize = 128;

/// Encrypted Caliptra Cryptographic Manager key blob.
///
/// Actual key material never leaves Caliptra unwrapped. `Cmk` is the
/// 128-byte encrypted key material returned by CM mailbox commands and
/// supplied back to subsequent CM commands.
#[repr(transparent)]
#[derive(Clone, Copy)]
pub struct Cmk(pub [u8; CMK_SIZE]);

impl Default for Cmk {
    fn default() -> Self {
        Self([0u8; CMK_SIZE])
    }
}

/// Key-usage tag that controls which CM commands accept a given CMK.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CmKeyUsage {
    Reserved = 0,
    Hmac = 1,
    Aes = 2,
    Ecdsa = 3,
    Mldsa = 4,
}
