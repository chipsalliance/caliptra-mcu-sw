// Licensed under the Apache-2.0 license

//! Cryptographic Import command types
//!
//! This module defines the request/response structures for the CM Import command
//! which imports a raw key and returns an encrypted CMK (Cryptographic Mailbox Key).

use crate::crypto_hmac::{CmKeyUsage, Cmk, CMK_SIZE};
use crate::{CaliptraCommandId, CommandRequest, CommandResponse, CommonResponse};
use zerocopy::{FromBytes, Immutable, IntoBytes};

pub const MAX_IMPORT_KEY_SIZE: usize = 64;

#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct ImportRequest {
    pub key_usage: u32,
    pub input_size: u32,
    pub input: [u8; MAX_IMPORT_KEY_SIZE],
}

impl Default for ImportRequest {
    fn default() -> Self {
        Self {
            key_usage: CmKeyUsage::Reserved as u32,
            input_size: 0,
            input: [0u8; MAX_IMPORT_KEY_SIZE],
        }
    }
}

impl ImportRequest {
    pub fn new(key_usage: CmKeyUsage, key: &[u8]) -> Self {
        let mut input = [0u8; MAX_IMPORT_KEY_SIZE];
        let len = core::cmp::min(key.len(), MAX_IMPORT_KEY_SIZE);
        input[..len].copy_from_slice(&key[..len]);
        Self {
            key_usage: key_usage as u32,
            input_size: len as u32,
            input,
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct ImportResponse {
    pub common: CommonResponse,
    pub cmk: Cmk,
}

impl Default for ImportResponse {
    fn default() -> Self {
        Self {
            common: CommonResponse { fips_status: 0 },
            cmk: Cmk::new([0u8; CMK_SIZE]),
        }
    }
}

impl CommandRequest for ImportRequest {
    type Response = ImportResponse;
    const COMMAND_ID: CaliptraCommandId = CaliptraCommandId::Import;
}

impl CommandResponse for ImportResponse {}
