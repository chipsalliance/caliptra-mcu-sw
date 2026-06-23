// Licensed under the Apache-2.0 license

//! SPDM CAPABILITIES wire types (DSP0274 §10.5).
//!
//! Two layers:
//!
//! 1. [`CapFlags`] — `Unaligned` newtype over `le::U32` with
//!    bitflags-style API. Embeds directly in [`CapabilitiesBody`] —
//!    no parse-time conversion, no `u32 -> CapFlags` glue.
//! 2. [`CapabilitiesBody`] — single 18-byte wire body for v1.2+
//!    GET_CAPABILITIES request and CAPABILITIES response (same wire
//!    shape in both directions).

use zerocopy::{little_endian::U32, FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::flag_macros::def_flag_set_le;
use crate::{ReqRespCode, ResponseBody, WireError, WireWriter};

def_flag_set_le! {
    /// SPDM capability bitfield (DSP0274 §10.5.1 Table 11). Constants
    /// cover single-bit flags directly. The 2-bit `MEAS` and `PSK`
    /// fields are exposed as per-value constants (`MEAS_NO_SIG`,
    /// `MEAS_SIG`, `PSK`, `PSK_WITH_CTX`).
    pub struct CapFlags(U32: u32) {
        CACHE = 1 << 0,
        CERT = 1 << 1,
        CHAL = 1 << 2,
        /// `MEAS` field bit 3 set (value `1` = NO_SIG).
        MEAS_NO_SIG = 1 << 3,
        /// `MEAS` field bit 4 set (value `2` = SIG).
        MEAS_SIG = 2 << 3,
        MEAS_FRESH = 1 << 5,
        ENCRYPT = 1 << 6,
        MAC = 1 << 7,
        MUT_AUTH = 1 << 8,
        KEY_EX = 1 << 9,
        /// `PSK` field bit 10 set (value `1` = PSK).
        PSK = 1 << 10,
        /// `PSK` field bit 11 set (value `2` = PSK_WITH_CTX).
        PSK_WITH_CTX = 2 << 10,
        ENCAP = 1 << 12,
        HBEAT = 1 << 13,
        KEY_UPD = 1 << 14,
        HANDSHAKE_IN_THE_CLEAR = 1 << 15,
        PUB_KEY_ID = 1 << 16,
        CHUNK = 1 << 17,
        ALIAS_CERT = 1 << 18,
        SET_CERT = 1 << 19,
        /// `MULTI_KEY_CAP` field bits 27:26 set to `10b` (`MultiKeyConnRsp`).
        MULTI_KEY_CONN_RSP = 2 << 26,
        GET_KEY_PAIR_INFO = 1 << 28,
    }
}

impl CapFlags {
    /// 2-bit `MEAS` field value (bits 3..=4).
    #[inline]
    pub fn meas_field(self) -> u8 {
        ((self.into_bits() >> 3) & 0b11) as u8
    }
    /// 2-bit `PSK` field value (bits 10..=11).
    #[inline]
    pub fn psk_field(self) -> u8 {
        ((self.into_bits() >> 10) & 0b11) as u8
    }

    /// 2-bit `MULTI_KEY_CAP` field value (bits 26..=27).
    #[inline]
    pub fn multi_key_field(self) -> u8 {
        ((self.into_bits() >> 26) & 0b11) as u8
    }
}

/// 18-byte CAPABILITIES body (DSP0274 §10.5.1, v1.2+). Identical
/// layout for `GET_CAPABILITIES` request and `CAPABILITIES`
/// response.
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Copy, Clone, Default)]
#[repr(C)]
pub struct CapabilitiesBody {
    pub param1: u8,
    pub param2: u8,
    pub reserved: u8,
    pub ct_exponent: u8,
    pub reserved2: [u8; 2],
    pub flags: CapFlags,
    pub data_transfer_size: U32,
    pub max_spdm_msg_size: U32,
}

impl CapabilitiesBody {
    pub const SIZE: usize = 18;

    /// DSP0274 §10.3: minimum DataTransferSize for V1.2+ is 42 bytes
    /// ("MinDataTransferSize" in the spec).
    pub const MIN_DATA_TRANSFER_SIZE: u32 = 42;

    /// Practical upper bound on CTExponent (CT = 2^32 µs ≈ 1.2 h).
    pub const MAX_CT_EXPONENT: u8 = 32;
}

const _: () = assert!(core::mem::size_of::<CapabilitiesBody>() == CapabilitiesBody::SIZE);

/// Builder for a CAPABILITIES response.
pub struct CapabilitiesRsp {
    pub ct_exponent: u8,
    pub flags: CapFlags,
    pub data_transfer_size: u32,
    pub max_spdm_msg_size: u32,
}

impl ResponseBody for CapabilitiesRsp {
    const RESPONSE_CODE: ReqRespCode = ReqRespCode::CAPABILITIES;

    fn body_size(&self) -> usize {
        CapabilitiesBody::SIZE
    }

    fn encode_body(&self, w: &mut WireWriter<'_>) -> Result<(), WireError> {
        w.write(&CapabilitiesBody {
            param1: 0,
            param2: 0,
            reserved: 0,
            ct_exponent: self.ct_exponent,
            reserved2: [0; 2],
            flags: self.flags,
            data_transfer_size: U32::new(self.data_transfer_size),
            max_spdm_msg_size: U32::new(self.max_spdm_msg_size),
        })
    }
}
