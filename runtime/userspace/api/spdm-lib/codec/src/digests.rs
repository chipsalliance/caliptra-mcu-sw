// Licensed under the Apache-2.0 license

//! DIGESTS response (DSP0274 §10.5 Table 25).
//!
//! ```text
//!  byte 0           byte 1           byte 2..end
//! ┌────────────────┬─────────────────┬───────────────────┐
//! │ SupportedSlots │ ProvisionedSlots│ digest[0..k]      │
//! │  (Param1)      │  (Param2)       │   variable        │
//! └────────────────┴─────────────────┴───────────────────┘
//! ```
//!
//! `digest[i]` is the negotiated-algorithm hash of the SPDM
//! cert-chain wire format (length(2) | reserved(2) | root_hash(48)
//! | DER chain) for slot `i`. One digest per bit set in
//! `ProvisionedSlots`.

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::{ReqRespCode, ResponseBody, WireError, WireWriter};

/// 2-byte DIGESTS response body header.
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Copy, Clone, Debug, Default)]
#[repr(C)]
pub struct DigestsRspBody {
    /// `Param1` — `SupportedSlotMask` (V1.3+) / Reserved (V1.2-).
    pub supported_slots: u8,
    /// `Param2` — `ProvisionedSlotMask` (V1.3+) / `SlotMask` (V1.2-).
    pub provisioned_slots: u8,
}

impl DigestsRspBody {
    pub const SIZE: usize = 2;
}

const _: () = assert!(core::mem::size_of::<DigestsRspBody>() == DigestsRspBody::SIZE);

/// Builder for a DIGESTS response.
///
/// The handler streams cert-chain bytes through `SpdmPalHash` and
/// fills `digests` itself before calling `build_response`. This
/// builder just writes the 2-byte header + N digest bytes.
pub struct DigestsRsp<'a> {
    pub supported_slots: u8,
    pub provisioned_slots: u8,
    /// Concatenated digests (one per bit set in `provisioned_slots`).
    /// Total length = `popcount(provisioned_slots) * digest_size`.
    pub digests: &'a [u8],
}

impl ResponseBody for DigestsRsp<'_> {
    fn response_code(&self) -> ReqRespCode {
        ReqRespCode::DIGESTS
    }

    fn body_size(&self) -> usize {
        DigestsRspBody::SIZE + self.digests.len()
    }

    fn encode_body(&self, w: &mut WireWriter<'_>) -> Result<(), WireError> {
        w.write(&DigestsRspBody {
            supported_slots: self.supported_slots,
            provisioned_slots: self.provisioned_slots,
        })?;
        w.write_bytes(self.digests)
    }
}
