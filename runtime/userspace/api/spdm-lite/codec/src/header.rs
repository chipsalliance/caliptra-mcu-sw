// Licensed under the Apache-2.0 license

//! SPDM common message header (DSP0274 §10.6) — wire-format
//! [`SpdmMsgHdrPdu`] (2 bytes) plus the [`ReqRespCode`] map.
//!
//! Per DSP0274 §10.6 every SPDM PDU begins with the same two bytes
//! `(SPDMVersion, RequestResponseCode)`. The next two bytes (`Param1`,
//! `Param2`) are command-specific and belong to each command's body
//! type, not to the common header — see how individual response body
//! structs (`VersionRspBody`, `CapabilitiesRspBody`, …) carry their
//! own `param1` / `param2` fields with command-specific meanings.

use crate::SpdmVersion;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

/// Size of [`SpdmMsgHdrPdu`] in bytes.
pub const SPDM_MSG_HDR_SIZE: usize = 2;

/// SPDM RequestResponseCode (DSP0274 §10.6, §10.7, §10.8).
#[derive(
    FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Copy, Clone, Debug, PartialEq, Eq, Hash,
)]
#[repr(transparent)]
pub struct ReqRespCode(pub u8);

impl ReqRespCode {
    // ----- Request codes (DSP0274 Table 4) -----
    pub const GET_DIGESTS: Self = Self(0x81);
    pub const GET_CERTIFICATE: Self = Self(0x82);
    pub const CHALLENGE: Self = Self(0x83);
    pub const GET_VERSION: Self = Self(0x84);
    pub const CHUNK_SEND: Self = Self(0x85);
    pub const CHUNK_GET: Self = Self(0x86);
    pub const GET_MEASUREMENTS: Self = Self(0xE0);
    pub const GET_CAPABILITIES: Self = Self(0xE1);
    pub const NEGOTIATE_ALGORITHMS: Self = Self(0xE3);
    pub const KEY_EXCHANGE: Self = Self(0xE4);
    pub const FINISH: Self = Self(0xE5);
    pub const PSK_EXCHANGE: Self = Self(0xE6);
    pub const PSK_FINISH: Self = Self(0xE7);
    pub const HEARTBEAT: Self = Self(0xE8);
    pub const KEY_UPDATE: Self = Self(0xE9);
    pub const GET_ENCAPSULATED_REQUEST: Self = Self(0xEA);
    pub const DELIVER_ENCAPSULATED_RESPONSE: Self = Self(0xEB);
    pub const END_SESSION: Self = Self(0xEC);
    pub const GET_CSR: Self = Self(0xED);
    pub const SET_CERTIFICATE: Self = Self(0xEE);
    pub const VENDOR_DEFINED_REQUEST: Self = Self(0xFE);

    // ----- Response codes (DSP0274 Table 4) -----
    pub const DIGESTS: Self = Self(0x01);
    pub const CERTIFICATE: Self = Self(0x02);
    pub const CHALLENGE_AUTH: Self = Self(0x03);
    pub const VERSION: Self = Self(0x04);
    pub const CHUNK_SEND_ACK: Self = Self(0x05);
    pub const CHUNK_RESPONSE: Self = Self(0x06);
    pub const MEASUREMENTS: Self = Self(0x60);
    pub const CAPABILITIES: Self = Self(0x61);
    pub const ALGORITHMS: Self = Self(0x63);
    pub const KEY_EXCHANGE_RSP: Self = Self(0x64);
    pub const FINISH_RSP: Self = Self(0x65);
    pub const PSK_EXCHANGE_RSP: Self = Self(0x66);
    pub const PSK_FINISH_RSP: Self = Self(0x67);
    pub const HEARTBEAT_ACK: Self = Self(0x68);
    pub const KEY_UPDATE_ACK: Self = Self(0x69);
    pub const ENCAPSULATED_REQUEST: Self = Self(0x6A);
    pub const ENCAPSULATED_RESPONSE_ACK: Self = Self(0x6B);
    pub const END_SESSION_ACK: Self = Self(0x6C);
    pub const CSR: Self = Self(0x6D);
    pub const SET_CERTIFICATE_RSP: Self = Self(0x6E);
    pub const VENDOR_DEFINED_RESPONSE: Self = Self(0x7E);
    pub const ERROR: Self = Self(0x7F);
}

/// 2-byte SPDM common header (DSP0274 §10.6 SPDMHeader).
///
/// `version` is a raw `u8` because not every byte is a valid
/// [`SpdmVersion`]; the dispatcher validates once via
/// [`SpdmVersion::from_u8`] before dispatching to a handler.
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Copy, Clone, Debug)]
#[repr(C)]
pub struct SpdmMsgHdrPdu {
    pub version: u8,
    pub code: ReqRespCode,
}

impl SpdmMsgHdrPdu {
    pub const SIZE: usize = SPDM_MSG_HDR_SIZE;

    /// Build a header from typed parts.
    pub const fn new(version: SpdmVersion, code: ReqRespCode) -> Self {
        Self {
            version: version.to_u8(),
            code,
        }
    }
}

const _: () = assert!(core::mem::size_of::<SpdmMsgHdrPdu>() == SpdmMsgHdrPdu::SIZE);
const _: () = assert!(core::mem::align_of::<SpdmMsgHdrPdu>() == 1);

// ---- Protocol-wide constants ------------------------------------------------

pub use mcu_spdm_lite_traits::SPDM_NONCE_LEN;

/// SHA-384 digest size (48 bytes).
pub const SHA384_HASH_SIZE: usize = 48;

/// RequesterContext length (SPDM V1.3+, 8 bytes).
pub const REQUESTER_CONTEXT_LEN: usize = 8;

/// ECC P-384 signature size (r || s, 96 bytes).
pub const ECC_P384_SIGNATURE_SIZE: usize = 96;

/// SPDM signing context prefix length (4 × 16 bytes).
pub const SPDM_PREFIX_LEN: usize = 64;

/// SPDM signing context operation string length.
pub const SPDM_CONTEXT_LEN: usize = 36;

/// Total signing context length.
pub const SPDM_SIGNING_CONTEXT_LEN: usize = SPDM_PREFIX_LEN + SPDM_CONTEXT_LEN;
