// Licensed under the Apache-2.0 license

//! SPDM CAPABILITIES wire types.
//!
//! Two layers:
//!
//! 1. [`CapFlags`] — `Unaligned` newtype over `le::U32` with
//!    bitflags-style API. Embeds directly in [`CapabilitiesBody`] —
//!    no parse-time conversion, no `u32 -> CapFlags` glue.
//! 2. [`CapabilitiesBody`] — single 18-byte wire body for v1.2+
//!    GET_CAPABILITIES request and CAPABILITIES response (same wire
//!    shape in both directions).

use zerocopy::{
    little_endian::{U16, U32},
    FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned,
};

use crate::flag_macros::def_flag_set_le;
use crate::{ReqRespCode, ResponseBody, SpdmVersion, WireError, WireWriter};

def_flag_set_le! {
    /// SPDM capability bitfield. Constants
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
        CSR = 1 << 20,
        CERT_INSTALL_RESET = 1 << 21,
        EP_INFO_NO_SIG = 1 << 22,
        EP_INFO_SIG = 2 << 22,
        MEL = 1 << 24,
        EVENT = 1 << 25,
        /// `MULTI_KEY_CAP` field bits 27:26 set to `01b` (`MultiKeyOnly`).
        MULTI_KEY_ONLY = 1 << 26,
        /// `MULTI_KEY_CAP` field bits 27:26 set to `10b` (`MultiKeyConnRsp`).
        MULTI_KEY_CONN_RSP = 2 << 26,
        GET_KEY_PAIR_INFO = 1 << 28,
        SET_KEY_PAIR_INFO = 1 << 29,
        SET_KEY_PAIR_RESET = 1 << 30,
        LARGE_RESP = 1 << 31,
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

def_flag_set_le! {
    /// SPDM V1.4 extended responder capability flags. The requester
    /// field is reserved; responders ignore its value.
    pub struct ExtCapFlags(U16: u16) {
        SLOT_MGMT = 1 << 0,
    }
}

/// 18-byte CAPABILITIES body for v1.2+. Identical
/// layout for `GET_CAPABILITIES` request and `CAPABILITIES`
/// response.
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Copy, Clone, Default)]
#[repr(C)]
pub struct CapabilitiesBody {
    pub param1: u8,
    pub param2: u8,
    pub reserved: u8,
    pub ct_exponent: u8,
    /// Extended response capability flags in V1.4. The request field is reserved;
    /// the field is reserved in both directions in older versions.
    pub ext_flags: ExtCapFlags,
    pub flags: CapFlags,
    pub data_transfer_size: U32,
    pub max_spdm_msg_size: U32,
}

impl CapabilitiesBody {
    pub const SIZE: usize = 18;

    /// Minimum DataTransferSize for V1.2+ is 42 bytes.
    pub const MIN_DATA_TRANSFER_SIZE: u32 = 42;

    /// Practical upper bound on CTExponent (CT = 2^32 µs ≈ 1.2 h).
    pub const MAX_CT_EXPONENT: u8 = 32;

    /// V1.0/1.1 CAPABILITIES body size (DSP0274 1.1.1 §10.3, tables 175/176):
    /// `Param1(1) | Param2(1) | Reserved(1) | CTExponent(1) | Reserved(2) |
    /// Flags(4)` = 10 bytes. This is the 18-byte V1.2+ body **without** the
    /// trailing `DataTransferSize(4)` and `MaxSPDMmsgSize(4)` fields, which were
    /// added in V1.2. The V1.1 request carries the same 10-byte layout as the
    /// response (both directions share the shape, as in V1.2+).
    pub const SIZE_V11: usize = 10;
}

const _: () = assert!(core::mem::size_of::<CapabilitiesBody>() == CapabilitiesBody::SIZE);

/// Builder for a CAPABILITIES response.
pub struct CapabilitiesRsp {
    /// Negotiated SPDM version. Selects the wire shape: V1.1 emits the 10-byte
    /// legacy body (no DataTransferSize/MaxSPDMmsgSize); V1.2+ emits 18 bytes.
    pub version: SpdmVersion,
    pub ct_exponent: u8,
    pub ext_flags: ExtCapFlags,
    pub flags: CapFlags,
    pub data_transfer_size: u32,
    pub max_spdm_msg_size: u32,
}

impl ResponseBody for CapabilitiesRsp {
    const RESPONSE_CODE: ReqRespCode = ReqRespCode::CAPABILITIES;

    fn body_size(&self) -> usize {
        // V1.1 omits DataTransferSize + MaxSPDMmsgSize.
        if self.version < SpdmVersion::V12 {
            CapabilitiesBody::SIZE_V11
        } else {
            CapabilitiesBody::SIZE
        }
    }

    fn encode_body(&self, w: &mut WireWriter<'_>) -> Result<(), WireError> {
        // V1.0/1.1 use the 10-byte body that stops after Flags: it has no
        // ExtCapFlags (those two bytes are Reserved) and no
        // DataTransferSize/MaxSPDMmsgSize. V1.2+ uses the full 18-byte body,
        // which carries ExtCapFlags (V1.4) at bytes 4..6 and the transfer sizes.
        if self.version < SpdmVersion::V12 {
            w.write(&CapabilitiesBodyV11 {
                param1: 0,
                param2: 0,
                reserved: 0,
                ct_exponent: self.ct_exponent,
                reserved2: [0; 2],
                flags: self.flags,
            })
        } else {
            w.write(&CapabilitiesBody {
                param1: 0,
                param2: 0,
                reserved: 0,
                ct_exponent: self.ct_exponent,
                ext_flags: self.ext_flags,
                flags: self.flags,
                data_transfer_size: U32::new(self.data_transfer_size),
                max_spdm_msg_size: U32::new(self.max_spdm_msg_size),
            })
        }
    }
}

/// 10-byte V1.0/1.1 CAPABILITIES body (DSP0274 1.1.1 §10.3). Byte-identical to
/// the leading 10 bytes of [`CapabilitiesBody`]; used for both the V1.1
/// GET_CAPABILITIES request decode and the CAPABILITIES response encode.
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Copy, Clone, Default)]
#[repr(C)]
pub struct CapabilitiesBodyV11 {
    pub param1: u8,
    pub param2: u8,
    pub reserved: u8,
    pub ct_exponent: u8,
    pub reserved2: [u8; 2],
    pub flags: CapFlags,
}

impl CapabilitiesBodyV11 {
    pub const SIZE: usize = CapabilitiesBody::SIZE_V11;
}

const _: () = assert!(core::mem::size_of::<CapabilitiesBodyV11>() == CapabilitiesBodyV11::SIZE);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder::ResponseBody;
    use crate::wire::WireWriter;

    fn rsp(version: SpdmVersion) -> CapabilitiesRsp {
        CapabilitiesRsp {
            version,
            ct_exponent: 20,
            ext_flags: ExtCapFlags::EMPTY,
            flags: CapFlags::CERT | CapFlags::CHAL,
            data_transfer_size: 4096,
            max_spdm_msg_size: 4096,
        }
    }

    #[test]
    fn v11_capabilities_body_is_10_bytes_without_transfer_sizes() {
        // V1.1 CAPABILITIES has no DataTransferSize/MaxSPDMmsgSize.
        let body = rsp(SpdmVersion::V11);
        assert_eq!(body.body_size(), CapabilitiesBody::SIZE_V11);
        assert_eq!(body.body_size(), 10);

        let mut buf = [0u8; 32];
        let mut w = WireWriter::new(&mut buf);
        body.encode_body(&mut w).unwrap();
        // Flags occupy bytes 6..10; nothing follows them for V1.1.
        assert_eq!(&buf[6..10], &0x0000_0006u32.to_le_bytes()); // CERT|CHAL = bits 1,2
    }

    #[test]
    fn v12_capabilities_body_is_18_bytes_with_transfer_sizes() {
        let body = rsp(SpdmVersion::V12);
        assert_eq!(body.body_size(), CapabilitiesBody::SIZE);
        assert_eq!(body.body_size(), 18);

        let mut buf = [0u8; 32];
        let mut w = WireWriter::new(&mut buf);
        body.encode_body(&mut w).unwrap();
        // DataTransferSize at bytes 10..14, MaxSPDMmsgSize at 14..18.
        assert_eq!(&buf[10..14], &4096u32.to_le_bytes());
        assert_eq!(&buf[14..18], &4096u32.to_le_bytes());
    }
}
